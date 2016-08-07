#include <iostream>
#include <fstream>
#include <stdexcept>
#include <cstring>

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

void reverseLE(char *bits, size_t n) {
    if (!isBigEndian()) {
        for (int i = 0; i < n / 2; i++)
            swap(bits, i, n - 1 - i);
    }
}

struct Header {
   unsigned        continuityCounter : 4;
   unsigned        adaptationFieldControl : 2;
   unsigned        scramblingControl : 2;
   unsigned        PID : 13;
   bool            priority : 1;
   bool            payloadUSI : 1;
   bool            TEI : 1;
   unsigned char   syncByte : 8;
};


void str(const Header& pHead) {
      std::cout << std::endl;
      std::cout << "Sync byte: " << pHead.syncByte << std::endl;
      std::cout << "Transport Error Indicator: " << pHead.TEI << std::endl;
      std::cout << "Payload Unit Start Indicator: " << pHead.payloadUSI << std::endl;
      std::cout << "Transport Priority: " << pHead.priority << std::endl;
      std::cout << "PID: " << pHead.PID << std::endl;
      std::cout << "Scrambling control: " << pHead.scramblingControl << std::endl;
      std::cout << "Adaptation field control: " << pHead.adaptationFieldControl << std::endl;
      std::cout << "Continuity counter: " << pHead.continuityCounter << std::endl;
      std::cout << std::endl;
}

int main(int argc, char *argv[])
{
   if (argc < 2) {
      std::cerr << "Usage: " << argv[0] << "<filename>\n";
      return 1;
   }

   std::ifstream instream(argv[1], std::ios::binary | std::ios::in);
   if (!instream.is_open())
      throw std::runtime_error("Can not open input file!");

   int cnt = 0;
   int pakWithPID0 = 0;
   char * buffer = new char[4];
   while (instream.read(buffer, 4)) {
      reverseLE(buffer, 4);
      Header *pHeader = (Header*) buffer;
      if (pHeader->PID == 0) {
         str(*pHeader);
         ++pakWithPID0;
      }
      ++cnt;
      instream.ignore(184);
   }
   std::cout << "Number of packets: " << cnt << std::endl;
   std::cout << "Packets with PID 0: " << pakWithPID0 << std::endl;
   return 0;
}

