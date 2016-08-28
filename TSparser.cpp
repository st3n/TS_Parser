/***********************************************************
 * The goal is parse MPEG2 transport stream to elementary  *
 * streams  which represent audio, video and subtitle data *
 * and save  them to separate files.                       *
 * Compile with flag -std=c++11 -pthread                   *
 * author: Igor Gala                                       *
 *                                                         *
 * *********************************************************/

//#include <netinet/in.h> //htonl, ntohl
//#include <type_traits>
#include <cassert>
#include <iostream>
#include <bitset>
#include <fstream>
#include <stdexcept>
#include <cstring>
#include <string>
#include <cstdio>
#include <sstream>
#include <vector>
#include <set>
#include <map>
#include <thread>

#define ntohll(x) (((uint64_t)(ntohl((int)((x << 32) >> 32))) << 32) | (unsigned int)ntohl(((int)(x >> 32))))
#define htonll(x) ntohll(x)

//------------------- stuctures-------------------------------------------

struct TSPacketHeader {
    unsigned  continuityCounter : 4;       // 4  Continuity counter
    unsigned  adaptationFieldControl : 2;  // 2  Adaptation field control
    unsigned  scramblingControl : 2;       // 2  Transport scrambling control
    unsigned  PID : 13;                    // 13 Packet ID
    unsigned  priority : 1;                // 1  Transport Priority
    unsigned  PUSI : 1;                    // 1  Payload Unit Start Indicator
    unsigned  TEI : 1;                     // 1  Transport Error Indicator
    unsigned  syncByte : 8;                // 8  Synced byte in each packet
};

// PSI (Program Specific Information) structures
struct TSPSIHeader {
    uint8_t pointerField;  // 8 skip bytes to payload
    uint8_t tableId;       // 8 table ID
    uint8_t syntaxIndicator;    // 1 section syntax indicator
    uint8_t privateBit;   // 1 private indicator, PAT and PMT should have == 0
    // 2 reserved
    uint16_t sectionLen;          // 12 section length
    uint32_t syntaxSectionPos;       // need to count the end of PAT section
    // if (syntax_flag == 0), next private data len-4 bytes
    // if (syntax_flag == 1), then use next fields:
    uint16_t extId;        // 16 PAT use this for TS identifier
    // 2 reserved
    uint8_t version;       // 5 version number
    uint8_t nextFlag;      // 1 current next indicator
    uint8_t sectionNum;    // 8 section number
    uint8_t lastSecNum;       // 8 last section number
    // .. private data sectionLen-9 bytes
};

// PAT (program association table)
struct TSPATRecord {
    uint16_t num;           // 16 program num
    // 3 reserved, '111'
    uint16_t pid;           // 13 packets with this PID are assumed to be PMT tables
};

struct TSPAT {
    TSPSIHeader th;
    uint32_t recordCount;
    TSPATRecord records[150]; // max number of programms
};

// PMT (program map table)
struct TSDescriptor {
    uint8_t finishread;     // finish read this descriptor data
    uint8_t tag;            // 8 descriptor tag
    uint8_t len;            // 8 descriptor data length in bytes
    //  uint8_t *data;          // raw data
};

struct TSPMTRecord {
    unsigned finishread;     // finish read descriptor data of certain ES
    int esType;            // 08
    // 03 reserved '111'
    int esPid;             // 13
    // 04 reserved
    int descLen;           // 12 First two bits must be zero. Entire value may be zero
    int ESreadDescription;      // read bytes for elementary stream specific data
};

struct TSPMT {
    TSPSIHeader th;
    // 03 reserved
    int pcr_pid;           // 13 PID of general timecode stream
    // 4 reserved
    int progDescLen;           // 12 Sum size of following program descriptors
    int brokenPackets;      // PMT packets with no default data
    int readDescription;             // read bytes for this section
    std::vector<TSPMTRecord> records;
    std::vector<TSDescriptor> progDesc;
};

struct PESHeader {
    unsigned extension_flag : 1;
    unsigned crc_flag : 1;
    unsigned additonal_copy_info_flag : 1;
    unsigned dsm_trick_mode_flag : 1;
    unsigned es_rate_flag : 1;
    unsigned escr_flag : 1;
    unsigned pts_dts_indicator : 2;
    unsigned orig_or_copy : 1;
    unsigned copyright : 1;
    unsigned alignment_indicator : 1;
    unsigned priority : 1;
    unsigned scr_control : 2;
    unsigned  marker_bits : 2;
};

struct PES {
    bool isHeadRead; // is header read
    uint32_t data_read; // how mutch data was read
    uint32_t header_read; // how mutch form header was read
    uint32_t dataLen; // length of the data in PES
    uint32_t start_code;
    uint8_t stream_id;
    uint16_t pack_len;
    PESHeader pesHeader;
    uint8_t pes_header_len;
};

struct AdaptationFieldHeader {
    unsigned adaptFieldExtFlag : 1;
    unsigned transportPrivDataFlag : 1;
    unsigned splicingPointFlag : 1;
    unsigned OPCRFlag : 1;
    unsigned PCRFlag : 1;
    unsigned ESPriorityFlag : 1;
    unsigned randomAccessFlag : 1;
    unsigned discontinuityFlag : 1;
};

struct AdaptationField {
    uint8_t len;
    AdaptationFieldHeader header;
    uint64_t PCR;
    uint64_t OPCR;
    uint8_t spliceCountDown;
    uint8_t transportPrivDataLen;
    //void* transportPrivData;
    //void* adaptationExtention;
};

//-------------- variables ---------------------------------------------

static TSPAT patTable;
static TSPMT* pmtTables;

std::map<uint8_t, uint8_t> sectionDesc;
std::set<uint32_t> videoPIDs;
std::set<uint32_t> audioPIDs;
std::set<uint32_t> subtitlePIDs;
std::set<uint32_t> teletextPIDs;

//---------------------- functions -----------------------------------------

bool isBigEndian() {
    union {
        uint32_t i;
        uint8_t p[4];
    } check = { 0x01020304 };

    return check.p[0] == 1;
}

inline uint8_t getbits8(char* buf, size_t& pos) {
    uint8_t tmp8;
    tmp8 = buf[pos];
    pos += 1;
    return tmp8;
}

inline uint16_t getbits16(char* buf, size_t& pos) {
    uint16_t tmp16;
    tmp16 = (buf[pos] << 8 & 0xff00)
          | (buf[pos+1]    & 0x00ff);
    pos += 2;
    return tmp16;
}

inline uint32_t getbits32(char* buf, size_t& pos) {
    uint32_t tmp32;
    tmp32 = (buf[pos]   << 24 & 0xff000000)
          | (buf[pos+1] << 16 & 0x00ff0000)
          | (buf[pos+2] << 8  & 0x0000ff00)
          | (buf[pos+3]       & 0x000000ff);

    pos += 4;
    return tmp32;
}

inline uint64_t getbits64(char* buf, size_t& pos) {
    uint64_t tmp64;
    tmp64 = ((uint64_t)getbits32(buf, pos) << 32 & 0xffffffff00000000)
          |           (getbits32(buf, pos)       & 0x00000000ffffffff);
    return tmp64;
}

void printTSPacketHeader(const TSPacketHeader& pHead) {
    std::cout << std::endl;
    std::cout << "Sync byte: 0x" << std::hex << (int) pHead.syncByte << std::endl;
    std::cout << "Transport Error Indicator: "<<std::dec << pHead.TEI << std::endl;
    std::cout << "Payload Unit Start Indicator: " << pHead.PUSI << std::endl;
    std::cout << "Transport Priority: " << pHead.priority << std::endl;
    std::cout << "PID: " << pHead.PID << std::endl;
    std::cout << "Scrambling control: " << pHead.scramblingControl << std::endl;
    std::cout << "Adaptation field control: " << pHead.adaptationFieldControl << std::endl;
    std::cout << "Continuity counter: " << pHead.continuityCounter << std::endl;
    std::cout << std::endl;
}

// Just another approuch to parse TS header if compiler will not be able
// map read 4 bytes to the structure with bit filds
class TSPacketHeader2 {
public:
    uint8_t  syncByte;
    uint8_t  TEI;
    uint8_t  PUSI;
    uint8_t  priority;
    int16_t PID;
    uint8_t  scramblingControl;
    uint8_t  adaptationFieldControl;
    uint8_t  continuityCounter;
    std::bitset<32> *rowData;

    TSPacketHeader2(uint32_t data, int n);
    ~TSPacketHeader2() { delete rowData; }
    std::string toString() const;
};

TSPacketHeader2::TSPacketHeader2(uint32_t data, int n) {
    assert(n == 4);
    unsigned char* buff = reinterpret_cast<unsigned char*>(&data);
    for (int i = 0; i < n; i++) {
        printf("\nByte %d: \t \t 0x%x", i, buff[i]);
    }

    this->rowData = new std::bitset<32>(data);
    this->syncByte = buff[n-1];
    this->TEI = (data & 0x800000) >> 23;
    this->PUSI = (data & 0x400000) >> 22;
    this->priority = (data & 0x200000) >> 21;
    this->PID = (data & 0x1fff00) >> 8;
    this->scramblingControl = (data & 0xc0) >> 6;
    this->adaptationFieldControl = (data & 0x30) >> 4;
    this->continuityCounter = (data & 0xf);

}

std::string TSPacketHeader2::toString() const {
    std::ostringstream oss;
    oss << "\nTSHeader2 approach\n";
    oss << "Row data: " <<  *this->rowData << "\n";
    oss << "Sync byte: 0x" << std::hex << (int)(this->syncByte) << "\n";
    oss << "Transport Error Indicator: " << std::dec << (unsigned)this->TEI << "\n";
    oss << "Payload Unit Start Indicator: " << (unsigned)this->PUSI << "\n";
    oss << "Transport Priority: " << (unsigned)this->priority << "\n";
    oss << "PID: " << (unsigned)(this->PID) << "\n";
    oss << "Scrambling control: " << (unsigned)this->scramblingControl << "\n";
    oss << "Adaptation field control: " << (unsigned)this->adaptationFieldControl << "\n";
    oss << "Continuity counter: " << (unsigned)(this->continuityCounter) << "\n";
    return oss.str();
}

const char* getStreamType(int stream_id, int pid) {
    switch (stream_id) {
        case 0x0000: return "Reserved";
        case 0x0001:
            videoPIDs.insert(pid);
            return "ISO/IEC 11172-2 (MPEG-1 Video PES)";
        case 0x0002:
            videoPIDs.insert(pid);
            return "ISO/IEC 13818-2 (MPEG-2 Video PES)";
        case 0x0003:
            audioPIDs.insert(pid);
            return "ISO/IEC 11172-3 (MPEG-1 Audio PES)";
        case 0x0004:
            audioPIDs.insert(pid);
            return "ISO/IEC 13818-3 (MPEG-2 Audio PES)";
        case 0x0005: return "ISO/IEC 13818-1 (MPEG-2 tabled data)";
        case 0x0006:
            subtitlePIDs.insert(pid);
            return "ISO/IEC 13818-1 PES (DVB subtitles/VBI and AC-3)";
        case 0x0007: return "ISO/IEC 13522 (MHEG)";
        case 0x0008: return "ITU-T H.222.0 and ISO/IEC 13818-1 DSM-CC";
        case 0x0009: return "ITU-T H.222.1 (auxiliary data)";
        case 0x000a: return "ISO/IEC 13818-6 DSM-CC (multiprotocol encapsulation)";
        case 0x000b: return "ISO/IEC 13818-6 DSM-CC (U-N messages)";
        case 0x000c: return "ISO/IEC 13818-6 DSM-CC (stream descriptors)";
        case 0x000d: return "ISO/IEC 13818-6 DSM-CC (tabled data)";
        case 0x000e: return "ISO/IEC 13818-1 (auxiliary data)";
        case 0x000f:
            audioPIDs.insert(pid);
            return "ISO/IEC 13818-7 (AAC Audio)";
        case 0x0010:
            videoPIDs.insert(pid);
            return "ISO/IEC 14496-2 (MPEG-4 H.263 based Video)";
        case 0x0011:
            audioPIDs.insert(pid);
            return "ISO/IEC 14496-3 (AAC LATM Audio)";
        case 0x0012: return "ISO/IEC 14496-1 (MPEG-4 FlexMux)";
        case 0x0013: return "ISO/IEC 14496-1 (MPEG-4 FlexMux)";
        case 0x0014: return "ISO/IEC 13818-6 DSM CC synchronized download protocol";
        case 0x0015: return "Packetized metadata";
        case 0x0016: return "Sectioned metadata";
        case 0x0017: return "ISO/IEC 13818-6 DSM CC Data Carousel metadata";
        case 0x0018: return "ISO/IEC 13818-6 DSM CC Object Carousel metadata";
        case 0x0019: return "ISO/IEC 13818-6 Synchronized Download Protocol metadata";
        case 0x001a: return "ISO/IEC 13818-11 IPMP";
        case 0x001b:
            videoPIDs.insert(pid);
            return "ITU-T H.264 (h264 lower bit rate Video)";
        case 0x0024:
            videoPIDs.insert(pid);
            return "ITU-T Rec. H.265 and ISO/IEC 23008-2 (Ultra HD video)";
        case 0x0042: return "Chinese Video Standard";
        case 0x0080:
            audioPIDs.insert(pid);
            return "ITU-T Rec. H.262 and ISO/IEC 13818-2 for DigiCipher II or PCM audio for Blu-ray";
        case 0x0081:
            audioPIDs.insert(pid);
            return "Dolby Digital up to six channel AUDIO for ATSC and Blu-ray";
        case 0x0082:
            subtitlePIDs.insert(pid);
            return "SCTE subtitle";
        case 0x0083:
            audioPIDs.insert(pid);
            return "Dolby TrueHD lossless AUDIO for Blu-ray";
        case 0x0084:
            audioPIDs.insert(pid);
            return "Dolby Digital Plus up to 16 channel audio for Blu-ray";
        case 0x0085:
            return "DTS 8 channel audio for Blu-ray";
            audioPIDs.insert(pid);
        case 0x0086:
            audioPIDs.insert(pid);
            return "DTS 8 channel lossless audio for Blu-ray";
        case 0x0087:
            audioPIDs.insert(pid);
            return "Dolby Digital Plus up to 16 channel audio for ATSC";
        case 0x0090:
            subtitlePIDs.insert(pid);
            return "Blu-ray Presentation Graphic Stream (subtitling)";
        case 0x0095: return "ATSC DSM CC Network Resources table";
        case 0x00c0:
            teletextPIDs.insert(pid);
            return "DigiCipher II text";
        case 0x00c1:
            audioPIDs.insert(pid);
            return "Dolby Digital up to six channel audio with AES-128-CBC data encryption";
        case 0x00c2: return "ATSC DSM CC synchronous data or Dolby Digital Plus up to 16 channel audio with"
                            "AES-128-CBC data encryption";
        case 0x00cf: return "ISO/IEC 13818-7 ADTS AAC with AES-128-CBC frame encryption";
        case 0x00d1:
            videoPIDs.insert(pid);
            return "(DIRAC Video ULTRA HD)";
        case 0x00db: return "ITU-T Rec. H.264 and ISO/IEC 14496-10 with AES-128-CBC slice encryption";
        case 0x00ea:
            videoPIDs.insert(pid);
            return "Microsoft Windows Media Video 9 (lower bit-rate video)";
        case 0x00be: return "padding stream";

        default:
            if (stream_id >= 0x001c && stream_id <= 0x0023) return "Reserved";
            if (stream_id >= 0x0025 && stream_id <= 0x0041) return "Reserved";
            if (stream_id >= 0x0043 && stream_id <= 0x007f) return "Reserved";
            if (stream_id >= 0x0088 && stream_id <= 0x008f) return "Privately defined";
            if (stream_id >= 0x0095 && stream_id <= 0x00df) return "Privately defined";
            if (stream_id >= 0x00c3 && stream_id <= 0x00ce) return "Privately defined";
            if (stream_id >= 0x00d2 && stream_id <= 0x00da) return "Privately defined";
            if (stream_id >= 0x00dc && stream_id <= 0x00e9) return "Privately defined";
            if (stream_id >= 0x00eb && stream_id <= 0x00ff) return "Privately defined";
    }
    return "UNKNOWN";
}

bool parsePSISectionHeader(uint64_t& section, TSPSIHeader& th) {
    bool isBroken = false;
    th.tableId = section >> 56;
    th.syntaxIndicator = (section >> 55) & 0x1;
    th.privateBit = (section >> 54) & 0x1;
    th.sectionLen = (section >> 40) & 0x3ff;

    if (th.syntaxIndicator) {
        th.extId = (section >> 24) & 0xffff; // TS identifier
        if (!(th.nextFlag = (section >> 16) & 0x1))
            printf("Current PAT or PMT section is not applicable\n");
        th.lastSecNum = section & 0xff;
    }
    else std::cerr << "Syntax section do not follow header of the section.\n";

    if (th.tableId != 0x0 && th.tableId != 0x2)
        isBroken = true;
    if (th.privateBit || th.sectionLen > 1021)
        isBroken = true;
    if (isBroken) {
        std::cerr << "Something wrong with pat or pmt packet!!!" << std::endl;
        std::cerr << "table id: 0x" << std::hex << (int)th.tableId << std::endl;
        std::cerr << "private bit: " << (int)th.privateBit << std::endl;
        std::cerr << "section length: " << std::dec << (int)th.sectionLen << std::endl;
    }
    return isBroken;
}

void parsePATSection(char* buf, size_t pos) {
    uint32_t sectionEnd, data;
    TSPATRecord *record;
    sectionEnd = patTable.th.syntaxSectionPos + patTable.th.sectionLen - 4 - 5; // -CRC32-syntax header
    while ((pos % 188 != 0) && (pos < sectionEnd)) {
        record = &patTable.records[patTable.recordCount++];
        data = getbits32(buf, pos);
        record->num = data >> 16;
        record->pid = data & 0x7ff;
        printf("Program number = %u PMT PID = 0x%04x \n", record->num, record->pid);
    }
}

void findPATInfo(char* buf, size_t size) {
    uint32_t packetsAmount = 0, packWithPID0 = 0;
    uint32_t tsHeader;
    size_t pos = 0;

    printf("\n---------------------------PAT INFO---------------------------\n\n");
    while (pos < size) {
        packetsAmount++;
        tsHeader = getbits32(buf, pos);

        TSPacketHeader* pTSHeader = reinterpret_cast<TSPacketHeader*>(&tsHeader);
        if (pTSHeader->syncByte != 0x47 || pTSHeader->TEI) {
            fprintf(stderr, "Something wrong with packet number %d!\n", packetsAmount);
            fprintf(stderr, "Sync byte: 0x%x, TEI: %d\n", pTSHeader->syncByte, pTSHeader->TEI);
            std::cout << "\nPositon in buffer before : " << pos << std::endl;
            pos += 184;
            continue;
        }

        if (pTSHeader->PID != 0x0) {
            pos += 184;
            continue;
        }
        ++packWithPID0;

        if (pTSHeader->adaptationFieldControl == 0x1) {
            bool isSectionBroken = false;
            if (pTSHeader->PUSI) {
                uint8_t pointerField = 0x0000;
                pointerField = getbits8(buf, pos);
                pos += pointerField;
                patTable.th.pointerField = pointerField;
                uint64_t section;
                section = getbits64(buf, pos);
                uint8_t sectionNumb = 0x0000;
                uint8_t versionNumb = 0x0000;
                versionNumb = (section & 0x3e0000) >> 17;
                sectionNumb = (section >> 8) & 0xff;
                if (    sectionDesc.count(sectionNumb)
                        && sectionDesc[sectionNumb] == versionNumb)
                {
                    pos += 188 - pos % 188;
                    continue;
                }
                patTable.th.sectionNum = sectionNumb;
                patTable.th.version = versionNumb;
                patTable.th.syntaxSectionPos = pos;
                sectionDesc[sectionNumb] = versionNumb;
                isSectionBroken = parsePSISectionHeader(section, patTable.th);
            }
            else std::cout << "PAT with PUSI 0 \n";
            if (!isSectionBroken)
                parsePATSection(buf, pos);
        }
        else std::cerr << "PAT section with adaptation fields!!\n";
        if (pos % 188 != 0)
            pos += 188 - pos % 188;
    }
    sectionDesc.clear();
    printf("\n----------------------------END PAT INFO---------------------------------\n");
    std::cout << "\nPositon in buffer after : " << pos << std::endl;
    std::cout << "Amount of records in the PAT table: " << patTable.recordCount << std::endl;
    std::cout << "Number of packets: " << packetsAmount << std::endl;
    std::cout << "Packets with PID 0: " << packWithPID0 << std::endl;
}

void parsePMTProgDescription(char* buf, size_t& pos, uint32_t index) {
    TSPMT* pmt =  &pmtTables[index];
    TSDescriptor progDesc = TSDescriptor();
    uint8_t len;

    printf("Program Description parsing \n");
    while (pmt->readDescription < pmt->progDescLen) {
        if (pmt->progDesc.empty() || pmt->progDesc.back().finishread) {
            progDesc.tag = getbits8(buf, pos);
            progDesc.len = getbits8(buf, pos);
            pmt->progDesc.push_back(progDesc);
            pmt->readDescription += 2;
        }
        if (pos % 188 == 0) return;
        len = pmt->progDesc.back().len;
        if (len < 188 - pos % 188) {
            pos += len;
            pmt->readDescription += len;
            pmt->progDesc.back().finishread = true;
        }
        else {
            int pass = 188 - pos % 188;
            pmt->readDescription += pass;
            pos += pass;
        }
    }
}

void parsePMTSpecificData(char* buf, size_t& pos, size_t size, TSPMT* pmt, int32_t& remain, unsigned PID) {
    TSPMTRecord record = TSPMTRecord();
    int pass;

    // go to the elementary stream specific data
    while (remain > 0 && pos < size) {
        if (pmt->records.empty() || pmt->records.back().finishread) {
            record.esType = getbits8(buf, pos);
            record.esPid = getbits16(buf, pos) & 0x1fff;
            record.descLen = getbits16(buf, pos) & 0x03ff;
            pmt->records.push_back(record);
            remain -= 5;
            printf("PMT PID 0x%04x\n", PID);
            printf("Elementary stream type=0x%02x pid=0x%04x\n", record.esType, record.esPid);
            printf("description length = %u\n", record.descLen);
            printf("Stream Id: %s\n\n", getStreamType(record.esType, record.esPid));
        }
        if (pmt->records.back().descLen == 0) {
            pmt->records.back().finishread = true;
            continue;
        }
        if (pos % 188 == 0) return;
        // skip elementary stream descriptors
        record = pmt->records.back();
        pass = 188 - pos % 188;
        if (record.descLen <= pass || record.descLen - record.ESreadDescription <= pass) {
            remain -= record.descLen;
            pos += record.descLen;
            pmt->records.back().finishread = true;
        }
        else {
            remain -= pass;
            pmt->records.back().ESreadDescription += pass;
            return;
        }
    }
}

void findPMTInfo(char* buf, size_t size) {
    TSPMT* curPMT;
    uint32_t tsHeader;
    uint32_t amount = 0, broken = 0;
    size_t pos = 0;
    int32_t specificDataRemain;
    uint32_t crcLen = 4, sectionInfoLen = 9;

    printf("\n-------------------------------PMT INFO-----------------------------------\n");
    while (pos < size) {
        tsHeader = getbits32(buf, pos);

        TSPacketHeader* pTSHeader = reinterpret_cast<TSPacketHeader*>(&tsHeader);
        if (pTSHeader->PID == 0x0010) {
            //Skip parsing NIT table
            pos += 184;
            continue;
        }

        for (uint32_t i = 0; i < patTable.recordCount; ++i) {
            if (pTSHeader->PID == patTable.records[i].pid) {
                amount++;
                if (pTSHeader->adaptationFieldControl > 1) {
                    pos += 184;
                    continue;
                    printf("PMT section with adaptaion fields\n");

                }
                curPMT = &pmtTables[i];
                bool isSectionBroken = false;
                if (pTSHeader->PUSI) {
                    uint8_t pointerField = 0x0000;
                    pointerField = getbits8(buf, pos);
                    pos += pointerField;
                    curPMT->th.pointerField = pointerField;
                    uint64_t section;
                    section = getbits64(buf, pos);
                    uint8_t sectionNumb = 0x0000;
                    uint8_t versionNumb = 0x0000;
                    versionNumb = (section & 0x3e0000) >> 17;
                    sectionNumb = (section >> 8) & 0xff;
                    if (  !sectionDesc.count(sectionNumb)
                        || sectionDesc[sectionNumb] != versionNumb)
                    {
                        sectionDesc[sectionNumb] = versionNumb;
                        curPMT->th.sectionNum = sectionNumb;
                        curPMT->th.version = versionNumb;
                        curPMT->th.syntaxSectionPos = pos;
                        isSectionBroken = parsePSISectionHeader(section, curPMT->th);
                        curPMT->pcr_pid = getbits16(buf, pos) & 0x1fff;
                        curPMT->progDescLen = getbits16(buf, pos) & 0x03ff;
                        curPMT->readDescription = 0;
                        specificDataRemain = curPMT->th.sectionLen - curPMT->progDescLen - crcLen - sectionInfoLen;
                    }
                    else break;
                }
                if (isSectionBroken) {
                    curPMT->brokenPackets++;
                    broken++;
                    printf("PID of broken packet: 0x%04x\n", pTSHeader->PID);
                    break;
                }

                if (curPMT->readDescription < curPMT->progDescLen)
                    parsePMTProgDescription(buf, pos, i);
                if (    (curPMT->readDescription >= curPMT->progDescLen)
                     && (specificDataRemain > 0))
                    parsePMTSpecificData(buf, pos, size, curPMT, specificDataRemain, pTSHeader->PID);
                break;
            }
        }

        if (pos % 188 != 0)
            pos += 188 - pos % 188;
    }

    printf("\nAmount of packets with PMT data: %u\n", amount);
    printf("Among them amount of broken packets: %u\n", broken);
    printf("\n----------------------------END PMT INFO--------------------------------\n\n");
}

//extract elementary stream from PES packets and save to files. one pid one file.
void saveES(char* buf, size_t size, std::set<uint32_t>& pids, std::string type) {
    uint32_t tsHeader, restInPES;
    uint32_t start_code;
    uint32_t adaptationFieldLen = 0;
    uint16_t pes_pack_header;
    size_t pos = 0;
    PES* pesPack = new PES[pids.size()]();

    while (pos < size) {
        tsHeader = getbits32(buf, pos);
        TSPacketHeader* pTSHeader = reinterpret_cast<TSPacketHeader*>(&tsHeader);
        for (auto i : pids) {
            if (i == pTSHeader->PID) {
                //check adaptation field
                if (pTSHeader->adaptationFieldControl == 0x2 || pTSHeader->adaptationFieldControl == 0x0) break;
                if (pTSHeader->adaptationFieldControl == 0x3) {
                    adaptationFieldLen = getbits8(buf, pos);
                    if (adaptationFieldLen > 188 - pos % 188) {
                       fprintf(stderr, "Ouch! Adaptation Field is bigger the rest of TS packet. PID: 0x%04x\n", pTSHeader->PID);
                       break;
                    }
                    pos += adaptationFieldLen;
                }
                if (!pesPack[i].isHeadRead) {
                    if (pesPack[i].header_read == 0 && pTSHeader->PUSI == 1) {
                        start_code = getbits32(buf, pos);
                        pesPack[i].start_code = start_code >> 8;
                        pesPack[i].stream_id = start_code & 0x000000ff;
                        if (pesPack[i].start_code != 0x000001) {
                            // some data, not a PES
                            fprintf(stderr, "Something wrong with header of PES packet! PID: 0x%04x\n", pTSHeader->PID);
                            fprintf(stderr, "Start code of PES:  0x%04x\n", pesPack[i].start_code);
                            fprintf(stderr, "Stream Id: 0x%04x\n", pesPack[i].stream_id);
                            break;;
                        }
                        pesPack[i].pack_len = getbits16(buf, pos);
                        pes_pack_header = getbits16(buf, pos);
                        PESHeader* pPESHeader = reinterpret_cast<PESHeader*>(&pes_pack_header);
                        if (pPESHeader->marker_bits != 0x2) {
                            fprintf(stderr, "Something wrong with optional PES header! PID: 0x%04x\n", pTSHeader->PID);
                            fprintf(stderr, "PES Header marker bits != 0x2");
                            break;
                        }
                        pesPack[i].pes_header_len = getbits8(buf, pos);
                        pesPack[i].dataLen = pesPack[i].pack_len - pesPack[i].pes_header_len - 3;
                    }
                    restInPES = 188 - pos % 188;
                    if (pesPack[i].pes_header_len < restInPES || pesPack[i].pes_header_len - pesPack[i].header_read < restInPES) {
                        pos += pesPack[i].pes_header_len - pesPack[i].header_read;
                        pesPack[i].isHeadRead = true;
                        pesPack[i].header_read += pesPack[i].pes_header_len - pesPack[i].header_read;
                    }
                    else {
                        pesPack[i].header_read += restInPES;
                        break;
                    }
                }
                else {
                    //read data
                    restInPES = 188 - pos % 188;
                    uint32_t write;
                    char* toWrite;
                    if (pesPack[i].dataLen - pesPack[i].data_read < restInPES) {
                        // all data was written
                        write = pesPack[i].dataLen - pesPack[i].data_read;
                        toWrite = new char[write];

                        pesPack[i].isHeadRead = false;
                        pesPack[i].header_read = 0;
                        pesPack[i].data_read = 0;
                    }
                    else {
                        pesPack[i].data_read += restInPES;
                        write = restInPES;
                        toWrite = new char[write];
                    }
                    for (uint32_t k = 0; k < write; ++k )
                       toWrite[k] = buf[pos+k];

                    std::ofstream out(type + std::to_string(pTSHeader->PID) + ".bin", std::ios::app | std::ios::binary);
                    if (!out.is_open())
                        std::cerr << "Can not open output file!" << std::endl;
                    out.write(toWrite, write);
                    out.close();
                    delete [] toWrite;
                }
            }
        }
        if (pos % 188 != 0)
            pos += 188 - pos % 188;
    }

    delete [] pesPack;
}

//-------------------------------------------------------------------------------------------//

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << "<filename>\n";
        return 1;
    }

    std::ifstream instream(argv[1], std::ios::binary | std::ios::ate);
    if (!instream.is_open())
        throw std::runtime_error("Can not open input file!");

    size_t size = instream.tellg();
    instream.seekg(std::ios::beg);
    char* data = new char[size];
    instream.read(data, size);
    printf("\nLength of the %s is %d bytes\n\n", argv[1], (int)size);
    instream.close();

    findPATInfo(data, size);
    pmtTables = new TSPMT[patTable.recordCount];
    findPMTInfo(data, size);

    std::cout << "Video set size : " << videoPIDs.size() << std::endl;
    std::cout << "Audio set size : " << audioPIDs.size() << std::endl;
    std::cout << "Subtitle set size : " << subtitlePIDs.size() << std::endl;

    std::string video = "video_es_";
    std::string audio = "audio_es_";
    std::string subtitle = "subtitle_es_";
    std::thread thrV(saveES, std::cref(data), size, std::ref(videoPIDs), video);
    std::thread thrA(saveES, std::cref(data), size, std::ref(audioPIDs), audio);
    std::thread thrS(saveES, std::cref(data), size, std::ref(subtitlePIDs), subtitle);

    thrV.join();
    thrA.join();
    thrS.join();

    delete [] data;
    delete [] pmtTables;
    return 0;
}

