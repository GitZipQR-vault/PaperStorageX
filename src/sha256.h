#ifndef TINY_SHA256_H
#define TINY_SHA256_H
#include <cstdint>
#include <cstring>
#include <vector>
struct SHA256 {
  uint32_t h[8]; uint64_t len; unsigned char buf[64]; size_t pos;
  SHA256(){ init(); }
  void init(){ h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19; len=0; pos=0; }
  static uint32_t rotr(uint32_t x,int n){ return (x>>n)|(x<<(32-n)); }
  static void compress(uint32_t h[8], const unsigned char* p){
    static const uint32_t K[64]={
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xc19bf174,0xe49b69c1,0xefbe4786
    };
    uint32_t w[64];
    for(int i=0;i<16;i++){
      w[i]=(p[4*i]<<24)|(p[4*i+1]<<16)|(p[4*i+2]<<8)|p[4*i+3];
    }
    for(int i=16;i<64;i++){
      uint32_t s0 = SHA256::rotr(w[i-15],7) ^ SHA256::rotr(w[i-15],18) ^ (w[i-15]>>3);
      uint32_t s1 = SHA256::rotr(w[i-2],17) ^ SHA256::rotr(w[i-2],19) ^ (w[i-2]>>10);
      w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int i=0;i<64;i++){
      uint32_t S1 = SHA256::rotr(e,6)^SHA256::rotr(e,11)^SHA256::rotr(e,25);
      uint32_t ch = (e&f) ^ ((~e)&g);
      uint32_t temp1 = hh + S1 + ch + K[i] + w[i];
      uint32_t S0 = SHA256::rotr(a,2)^SHA256::rotr(a,13)^SHA256::rotr(a,22);
      uint32_t maj = (a&b) ^ (a&c) ^ (b&c);
      uint32_t temp2 = S0 + maj;
      hh=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
  }
  void update(const unsigned char* data, size_t lenBytes){
    len += lenBytes*8;
    while(lenBytes>0){
      size_t take = 64 - pos; if(take>lenBytes) take=lenBytes;
      memcpy(buf+pos, data, take); pos+=take; data+=take; lenBytes-=take;
      if(pos==64){ compress(h, buf); pos=0; }
    }
  }
  void finish(unsigned char out[32]){
    unsigned char pad[128]; size_t p=0;
    pad[p++]=0x80;
    size_t z = (pos<=56)?(56-pos):(120-pos);
    memset(pad+p,0,z); p+=z;
    for(int i=7;i>=0;i--) pad[p++]=(len>>(8*i))&0xFF;
    update(pad,p);
    for(int i=0;i<8;i++){ out[4*i]=h[i]>>24; out[4*i+1]=(h[i]>>16)&255; out[4*i+2]=(h[i]>>8)&255; out[4*i+3]=h[i]&255; }
  }
  static std::vector<unsigned char> hash(const std::vector<unsigned char>& v){
    SHA256 s; s.update(v.data(), v.size()); std::vector<unsigned char> out(32); s.finish(out.data()); return out;
  }
};
#endif
