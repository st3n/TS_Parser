/***********************************************************
 * The goal is parse MPEG2 transport stream to elementary  *
 * streams  which represent audio, video and subtitle data *
 * and save  them to separate files.                       *
 * Compile with flag -std=c++11                            *
 * author: Igor Gala                                       *
 *                                                         *
 * *********************************************************/

#include <netinet/in.h> //htonl, ntohl
#include <cassert>
//#include <type_traits>
#include <iostream>
#include <bitset>
#include <fstream>
#include <stdexcept>
#include <cstring>
#include <string>
#include <cstdio>
#include <sstream>
#include <vector>
#include <map>

#define ntohll(x) (((uint64_t)(ntohl((int)((x << 32) >> 32))) << 32) | (unsigned int)ntohl(((int)(x >> 32))))
#define htonll(x) ntohll(x)

static uint32_t readBytes = 0;
 // description of the PAT section (version, number) Used to prevent handlind the same table sections
std::map<uint8_t, uint8_t> sectionDesc;
std::vector<uint32_t> PMTList;
std::vector<uint32_t> videoPIDs;
std::vector<uint32_t> audioPIDs;
std::vector<uint32_t> subtitlePIDs;
std::vector<uint32_t> teletextPIDs;

struct TSPacketHeader {
   unsigned        continuityCounter : 4;       // 4  Continuity counter
   unsigned        adaptationFieldControl : 2;  // 2  Adaptation field control
   unsigned        scramblingControl : 2;       // 2  Transport scrambling control
   unsigned        PID : 13;                    // 13 Packet ID
   bool            priority : 1;                // 1  Transport Priority
   bool            PUSI : 1;                    // 1  Payload Unit Start Indicator
   bool            TEI : 1;                     // 1  Transport Error Indicator
   unsigned char   syncByte : 8;                // 8  Synced byte in each packet
};

// PSI (Program Specific Information) structures
struct TSPSIHeader {
   uint8_t pointerField;  // 8 skip bytes to payload
   uint8_t tableId;       // 8 table ID
   uint8_t syntaxFlag;    // 1 section syntax indicator
   uint8_t privateFlag;   // 1 private indicator
   // 2 reserved
   uint16_t sectionLen;          // 12 section length
   uint32_t lenPos;       // need to count the end of PAT section
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

static TSPAT patTable;

// PMT (program map table)
struct TSDescriptor {
   uint8_t tag;            // 8 descriptor tag
   uint8_t len;            // 8 descriptor data length in bytes
   uint8_t *data;          // raw data
};

struct TSPMTRecord {
   int esType;            // 08
   // 03 reserved '111'
   int esPid;             // 13
   // 04 reserved
   int descLen;           // 12 First two bits must be zero. Entire value may be zero
   int descCount;
   TSDescriptor desc[8];
};

struct TSPMT {
   TSPSIHeader *h;
   // 03 reserved
   int pcr_pid;           // 13 PID of general timecode stream, or 0x1FFF
   // 4 reserved
   int infoLen;           // 12 Sum size of following program descriptors.
   int recordCount;
   TSPMTRecord records[32];
};

bool isBigEndian() {
   union {
      uint32_t i;
      uint8_t p[4];
   } check = { 0x01020304 };

   return check.p[0] == 1;
}

void swapByteOrder(uint32_t& ui)
{
    ui = (ui >> 24) |
         ((ui << 8) & 0x00ff0000) |
         ((ui >> 8) & 0x0000ff00) |
         (ui << 24);
}

void printTSPachetHeader(const TSPacketHeader& pHead) {
   std::cout << std::endl;
   std::cout << "Sync byte: " << pHead.syncByte << std::endl;
   std::cout << "Transport Error Indicator: " << pHead.TEI << std::endl;
   std::cout << "Payload Unit Start Indicator: " << pHead.PUSI << std::endl;
   std::cout << "Transport Priority: " << pHead.priority << std::endl;
   std::cout << "PID: " << pHead.PID << std::endl;
   std::cout << "Scrambling control: " << pHead.scramblingControl << std::endl;
   std::cout << "Adaptation field control: " << pHead.adaptationFieldControl << std::endl;
   std::cout << "Continuity counter: " << pHead.continuityCounter << std::endl;
   std::cout << std::endl;
}

// Just another approuch to parse TS header if compiler will not be able
// map readed 4 bytes to the structure with bit filds
class TSPacketHeader2 {
public:
   uint8_t  syncByte;
   uint8_t  TEI;
   uint8_t  PUSI;
   uint8_t  priority;
   uint16_t PID;
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
   oss << "Sync byte: " << (char)(this->syncByte) << "\n";
   oss << "Transport Error Indicator: " << (unsigned)this->TEI << "\n";
   oss << "Payload Unit Start Indicator: " << (unsigned)this->PUSI << "\n";
   oss << "Transport Priority: " << (unsigned)this->priority << "\n";
   oss << "PID: " << (unsigned)(this->PID) << "\n";
   oss << "Scrambling control: " << (unsigned)this->scramblingControl << "\n";
   oss << "Adaptation field control: " << (unsigned)this->adaptationFieldControl << "\n";
   oss << "Continuity counter: " << (unsigned)(this->continuityCounter) << "\n";
   return oss.str();
}

void parsePATSectionHeader(std::ifstream& instream, uint64_t& section) {
   patTable.th.tableId = section >> 56;
   patTable.th.syntaxFlag = (section >> 55) & 0x1;
   patTable.th.privateFlag = (section >> 54) & 0x1;
   patTable.th.sectionLen = (section >> 40) & 0x3ff;
   patTable.th.lenPos = instream.tellg();

   if (patTable.th.syntaxFlag) {
      patTable.th.extId = (section >> 24) & 0xffff; // TS identifier
      patTable.th.nextFlag = (section >> 16) & 0x1;
      patTable.th.lastSecNum = section & 0xff;
   }
   else std::cerr << "Syntax section do not follow header of the section.\n";

   if (patTable.th.tableId != 0x0 || patTable.th.privateFlag || patTable.th.sectionLen > 1021) {
      std::cerr << "SomepatTable.thing wrong with pat packet!!!" << std::endl;
      std::cerr << "PAT table id: 0x" << std::hex << patTable.th.tableId << std::endl;
      std::cerr << "PAT section lengpatTable.th: " << patTable.th.sectionLen << std::endl;
      std::cerr << "PAT private bit: " << patTable.th.privateFlag << std::endl;
   }
}

void parsePATSection(std::ifstream& instream) {
   uint32_t sectionEnd, data;
   TSPATRecord *record;
   //patTable.recordCount = 0;
   sectionEnd = patTable.th.lenPos + patTable.th.sectionLen - 4; // - CRC32
   while (readBytes < 188 && instream.tellg() < sectionEnd) {
      record = &patTable.records[patTable.recordCount];
      patTable.recordCount++;
      instream.read(reinterpret_cast<char*> (&data), 4);
      readBytes += 4;
      data = ntohl(data);
      record->num = data >> 16;
      record->pid = data & 0x7ff;
      printf("Program number = %u PMT PID = 0x%04x \n", record->num, record->pid);
   }
}

void findPATInfo(std::ifstream& instream) {
   uint32_t packetsAmount = 0, packWithPID0 = 0;
   uint32_t buff;

   while (instream.read(reinterpret_cast<char*> (&buff), 4)) {
      readBytes += 4;
      ++packetsAmount;
      buff = ntohl(buff);
      TSPacketHeader* pTSHeader = reinterpret_cast<TSPacketHeader*>(&buff);

      if (pTSHeader->syncByte != 0x47 || pTSHeader->TEI) {
         fprintf(stderr, "Something wrong with packet number %d!\n", packetsAmount);
         fprintf(stderr, "Sync byte: 0x%x, TEI: %d\n", pTSHeader->syncByte, pTSHeader->TEI);
         instream.ignore(184);
         readBytes = 0;
         continue;
      }

      if (pTSHeader->PID != 0x0 || pTSHeader->adaptationFieldControl > 1) {
         instream.ignore(184);
         readBytes = 0;
         continue;
      }
      ++packWithPID0;

      if (pTSHeader->adaptationFieldControl == 0x1) {
         if (pTSHeader->PUSI) {
            uint8_t pointerField = 0x0000;
            instream.read(reinterpret_cast<char*> (&pointerField), 1);
            instream.ignore(pointerField);
            readBytes += pointerField + 1;
            patTable.th.pointerField = pointerField;
            uint64_t section;
            instream.read(reinterpret_cast<char*> (&section), 8);
            section = ntohll(section);
            uint8_t sectionNumb = 0x0000;
            uint8_t versionNumb = 0x0000;
            versionNumb = (section & 0x3e0000) >> 17;
            sectionNumb = (section >> 8) & 0xff;
            if (    sectionDesc.count(sectionNumb)
                 && sectionDesc[sectionNumb] == versionNumb)
            {
               readBytes += 8;
               instream.ignore(188-readBytes);
               continue;
            }
            readBytes += 8;
            patTable.th.sectionNum = sectionNumb;
            patTable.th.version = versionNumb;
            sectionDesc[sectionNumb] = versionNumb;
            parsePATSectionHeader(instream, section);
         }
         else std::cerr << "PAT with PUSI 0" << std::endl;
         parsePATSection(instream);
      }
      else std::cerr << "PAT section without payload\n";
      if (188-readBytes > 0)
         instream.ignore(188-readBytes);
      readBytes = 0;
   }
   std::cout << "\nPositon in file : " << instream.tellg() << std::endl;
   std::cout << "Amount of records in the PAT table: " << patTable.recordCount << std::endl;
   std::cout << "Number of packets: " << packetsAmount << std::endl;
   std::cout << "Packets with PID 0: " << packWithPID0 << std::endl;
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

   int len = instream.tellg();
   printf("\nLength of the %s is %d bytes\n\n", argv[1], len);
   instream.seekg(std::ios::beg);
   findPATInfo(instream);

   instream.close();
   return 0;
}

