#include <cassert>
#include <iostream>
#include <iomanip>
#include <bitset>
#include <fstream>
#include <stdexcept>
#include <cstring>
#include <string>
#include <cstdio>
#include <sstream>

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

struct Header {
   unsigned        continuityCounter : 4;
   unsigned        adaptationFieldControl : 2;
   unsigned        scramblingControl : 2;
   unsigned        PID : 13;
   bool            priority : 1;
   bool            PUSI : 1;
   bool            TEI : 1;
   unsigned char   syncByte : 8;
};
//int32_t __builtin_bswap32 (int32_t x)
void str(const Header& pHead) {
      std::cout << std::endl;
      std::cout << "\nHeader1 aprouch" << std::endl;
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

class Header2 {
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

   Header2(uint32_t data, int n);
   Header2(uint32_t data, int n, int k);
   ~Header2() { delete rowData; }
   std::string toString() const;
};

Header2::Header2(uint32_t data, int n) {
   assert(n == 4);
   unsigned char* buff = reinterpret_cast<unsigned char*>(&data);
   for (int i = 0; i < n; i++) {
      printf("\nByte %d: \t \t 0x%x", i, buff[i]);
   }

   this->rowData = new std::bitset<32>(data);
   this->syncByte = buff[0];
   this->TEI = (buff[1] & 0x01);
   this->PUSI = (buff[1] & 0x02) >> 1;
   this->priority = (buff[1] & 0x40) >> 2;
   this->PID = (data & 0xfff800) >> 11;
   this->scramblingControl = (buff[3] & 0x03);
   this->adaptationFieldControl = (buff[3] & 0xC) >> 2;
   this->continuityCounter = (buff[3] & 0xF0) >> 4;

 //  this->syncByte = buff[0];
 //  this->TEI = (buff[1] & 0x80) >> 7;
 //  this->PUSI = (buff[1] & 0x40) >> 6;
 //  this->priority = (buff[1] & 0x20) >> 5;
 //  this->PID = ((buff[1] & 31) << 8) | buff[2];
 //  this->scramblingControl = (buff[3] & 0xC0);
 //  this->adaptationFieldControl = (buff[3] & 0x30) >> 4;
 //  this->continuityCounter = (buff[3] & 0xF);
}

std::string Header2::toString() const {
   std::ostringstream oss;
   oss << "\nHeader2 approach\n";
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

Header2::Header2(uint32_t data, int n, int k) {
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

int main(int argc, char *argv[])
{
   if (argc < 2) {
      std::cerr << "Usage: " << argv[0] << "<filename>\n";
      return 1;
   }

   std::ifstream instream(argv[1], std::ios::binary);
   if (!instream.is_open())
      throw std::runtime_error("Can not open input file!");

   uint32_t cnt = 0, pakWithPID0 = 0;
   uint32_t buff;
   uint32_t chunk = sizeof(uint32_t);
   instream.read(reinterpret_cast<char *> (&buff), chunk);
   Header2 data(buff, chunk);
   std::cout << data.toString();
   if (!isBigEndian())
      swapByteOrder(buff);
   Header *pHeader = reinterpret_cast<Header*>(&buff);
   str(*pHeader);
   std::cout << "BIG ENDIAN conversion" << "\n";
   Header2 data2(buff, chunk, chunk);
   std::cout << data2.toString();
   //while (instream.read(buffer, 4)) {
   //  // reverseLE(buffer, 4);
   //   Header *pHeader = (Header*) buffer;
   //   if (pHeader->PID == 0) {
   //      str(*pHeader);
   //      ++pakWithPID0;
   //   }
   //   ++cnt;
   //   instream.ignore(184);
   //}
   //std::cout << "Number of packets: " << cnt << std::endl;
   //std::cout << "Packets with PID 0: " << pakWithPID0 << std::endl;
   return 0;
}

