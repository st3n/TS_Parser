#include <bitset>
#include <cstring>
#include <iostream>
#include <fstream>
#include <stdexcept>

#define SYNC_BYTE_MASK 0xff000000
#define TEI_MASK 0x800000
#define PAYLOAD_START_MASK 0x400000
#define PRIORITY_MASK 0x200000
#define PID_MASK 0x1fff00
#define SCRAMBLING_CONTROL_MASK 0xc0
#define ADAPTATION_FIELD_CONTROL_MASK 0x30
#define CONTINUITY_COUNTER_MASK 0xf
#define HEADER_BITS 32

bool isBigEndian() {

   union {
      uint32_t i;
      uint8_t p[4];
   } check = { 0x01020304 };

   return check.p[0] == 1;
}

bool isLittleEndian() {
   return !isLittleEndian();
}

void swap(char *s, int a, int b) {
    char tmp;

    tmp = s[a];
    s[a] = s[b];
    s[b] = tmp;
}

uint32_t reverseLE(const char *bits, size_t n) {
    uint32_t ret = 0;
    char *cp = (char *)malloc(n * sizeof(char));

    memcpy(cp, bits, n);
    if (!isBigEndian()) {
        for (int i = 0; i < n / 2; i++)
            swap(cp, i, n - 1 - i);
    }

    ret = *((uint32_t *)cp);
    free(cp);
    return ret;
}

class Header {

public:
   std::bitset<HEADER_BITS> *full;

   unsigned char mSyncByte;
   bool mTEI;
   bool mPayloadUSI;
   bool mPriority;
   uint16_t mPID;
   std::bitset<2> *mScramblingControl;
   std::bitset<2> *mAdaptationFieldControl;
   int mContinuityCounter;

   Header(const char *, size_t);
   ~Header();

   void str() const;
};

Header::Header(const char *header, size_t n) {
   uint32_t bytes = reverseLE(header, n);

   char t[4];
   memcpy(t, header, 4);
   std::cout << "Original: " << std::bitset<32>(*((uint32_t *)t)) << std::endl;
   this->full = new std::bitset<HEADER_BITS>(bytes);

   uint32_t tmp = bytes & SYNC_BYTE_MASK;
   this->mSyncByte = ((char *)&tmp)[n - 1];

   this->mTEI = bytes & TEI_MASK;
   this->mPayloadUSI = bytes & PAYLOAD_START_MASK;
   this->mPriority = bytes & PRIORITY_MASK;
   this->mPID = bytes & PID_MASK;
   this->mPID >>= 8;
   this->mScramblingControl = new std::bitset<2>(bytes & SCRAMBLING_CONTROL_MASK);
   this->mAdaptationFieldControl = new std::bitset<2>(bytes & ADAPTATION_FIELD_CONTROL_MASK);
   this->mContinuityCounter = bytes & CONTINUITY_COUNTER_MASK;
}

Header::~Header() {
   delete this->full;
   delete this->mScramblingControl;
   delete this->mAdaptationFieldControl;
}

void Header::str() const {
   std::cout << "Reversed: " << *this->full << std::endl;
   std::cout << std::endl;
   std::cout << "Sync byte: " << this->mSyncByte << std::endl;
   std::cout << "Transport Error Indicator: " << this->mTEI << std::endl;
   std::cout << "Payload Unit Start Indicator: " << this->mPayloadUSI << std::endl;
   std::cout << "Transport Priority: " << this->mPriority << std::endl;
   std::cout << "PID: " << this->mPID << std::endl;
   std::cout << "Scrambling control: " << *this->mScramblingControl << std::endl;
   std::cout << "Adaptation field control: " << *this->mAdaptationFieldControl << std::endl;
   std::cout << "Continuity counter: " << this->mContinuityCounter << std::endl;
}

int main(int argc, char *argv[])
{
   if (argc < 2) {
      std::cerr << "Usage: " << argv[0] << "<filename>\n";
      return 1;
   }

   char *buffer = new char[4];

   std::ifstream instream(argv[1], std::ios::binary | std::ios::in);
   if (!instream.is_open())
      throw std::runtime_error("Can not open input file!");

   if (!instream.read(buffer, 4))
       throw std::runtime_error("Failed to read from file");

   Header a(buffer, 4);
   a.str();

   std::cout << std::endl;

   instream.close();
   delete [] buffer;

   return 0;
}
