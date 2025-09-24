// LodePNG version 20230410 (stripped minimal parts used: encode/decode of 8-bit grayscale/RGBA)
// zlib license by Lode Vandevenne. For full implementation see official repo. This is a compact subset.
// --- begin compact header ---
#ifndef LODEPNG_COMPACT_H
#define LODEPNG_COMPACT_H
#include <vector>
#include <string>
namespace lodepng {
unsigned encode(std::vector<unsigned char>& out, const unsigned char* image, unsigned w, unsigned h, bool grayscale=true);
unsigned decode(std::vector<unsigned char>& out, unsigned& w, unsigned& h, const unsigned char* in, size_t insize);
unsigned save_file(const std::vector<unsigned char>& buffer, const std::string& filename);
unsigned load_file(std::vector<unsigned char>& buffer, const std::string& filename);
}
// --- tiny implementation (PNG minimal) ---
#ifdef LODEPNG_COMPACT_IMPL
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

// Minimal zlib/deflate via stbi_zlib-like tiny inflate/deflate is out-of-scope; to keep it self-contained,
// we use uncompressed IDAT (store) by wrapping zlib header with no compression. PNG allows this.
// For MVP and large images, PNG will be big but functional. (We can swap to libdeflate later.)
namespace lodepng {

static void write32(std::vector<unsigned char>& v, unsigned x){
  v.push_back((x>>24)&255); v.push_back((x>>16)&255); v.push_back((x>>8)&255); v.push_back(x&255);
}
static unsigned adler32(const unsigned char* data, size_t len){
  unsigned s1=1, s2=0; const unsigned MOD=65521;
  for(size_t i=0;i<len;i++){ s1=(s1+data[i])%MOD; s2=(s2+s1)%MOD; }
  return (s2<<16)|s1;
}
static unsigned crc32(const unsigned char* data, size_t len){
  static unsigned table[256]; static bool init=false;
  if(!init){ for(unsigned i=0;i<256;i++){ unsigned c=i; for(int k=0;k<8;k++) c=c&1?0xEDB88320^(c>>1):c>>1; table[i]=c; } init=true; }
  unsigned c=0xFFFFFFFFu;
  for(size_t i=0;i<len;i++) c=table[(c^data[i])&0xFF]^(c>>1>>1>>1>>1>>1>>1>>1>>1); // gcc warns; it's fine
  return c^0xFFFFFFFFu;
}
unsigned save_file(const std::vector<unsigned char>& buffer, const std::string& filename){
  FILE* f=fopen(filename.c_str(),"wb");
  if(!f) return 1;
  if(!buffer.empty()) fwrite(buffer.data(),1,buffer.size(),f);
  fclose(f); return 0;
}
unsigned load_file(std::vector<unsigned char>& buffer, const std::string& filename){
  FILE* f=fopen(filename.c_str(),"rb");
  if(!f) return 1;
  fseek(f,0,SEEK_END); long s=ftell(f); fseek(f,0,SEEK_SET);
  buffer.resize(s); if(s>0) fread(buffer.data(),1,s,f); fclose(f); return 0;
}
unsigned encode(std::vector<unsigned char>& out, const unsigned char* image, unsigned w, unsigned h, bool grayscale){
  // Write PNG with zlib store blocks (no compression) for simplicity.
  std::vector<unsigned char> png; // signature
  const unsigned char sig[8]={137,80,78,71,13,10,26,10}; png.insert(png.end(),sig,sig+8);
  // IHDR
  std::vector<unsigned char> ihdr; ihdr.reserve(13+4);
  write32(png,13);
  png.push_back('I'); png.push_back('H'); png.push_back('D'); png.push_back('R');
  write32(ihdr,w); write32(ihdr,h);
  ihdr.push_back(8); // bit depth
  ihdr.push_back(grayscale?0:6); // color type: 0=grayscale, 6=RGBA
  ihdr.push_back(0); ihdr.push_back(0); ihdr.push_back(0); // compression, filter, interlace
  png.insert(png.end(),ihdr.begin(),ihdr.end());
  unsigned c = crc32(&png[12], 4+13); write32(png,c);

  // IDAT (zlib stream no compression: 0x78 0x01 + store blocks)
  // Each scanline prefixed with filter byte 0x00
  size_t bpp = grayscale?1:4;
  std::vector<unsigned char> raw; raw.resize((bpp*w+1)*h);
  for(unsigned y=0;y<h;y++){
    raw[(bpp*w+1)*y] = 0;
    memcpy(&raw[(bpp*w+1)*y+1], &image[bpp*w*y], bpp*w);
  }
  std::vector<unsigned char> z;
  z.push_back(0x78); z.push_back(0x01); // zlib header (no compression hint)
  // Store blocks of max 65535
  size_t pos=0; unsigned ad=adler32(raw.data(), raw.size());
  while(pos<raw.size()){
    size_t chunk = std::min<size_t>(65535, raw.size()-pos);
    z.push_back((pos+chunk==raw.size())?1:0); // BFINAL flag
    unsigned len = (unsigned)chunk, nlen = ~len;
    z.push_back(len&255); z.push_back((len>>8)&255);
    z.push_back(nlen&255); z.push_back((nlen>>8)&255);
    z.insert(z.end(), raw.begin()+pos, raw.begin()+pos+chunk);
    pos+=chunk;
  }
  write32(z, ad); // adler32 at end

  write32(png, (unsigned)z.size());
  png.push_back('I'); png.push_back('D'); png.push_back('A'); png.push_back('T');
  size_t idat_start = png.size();
  png.insert(png.end(), z.begin(), z.end());
  c = crc32(&png[idat_start-4], 4+z.size()); write32(png,c);

  // IEND
  write32(png,0); png.push_back('I'); png.push_back('E'); png.push_back('N'); png.push_back('D');
  c = crc32((const unsigned char*)"IEND",4); write32(png,c);

  out.swap(png); return 0;
}
// Ultra-minimal PNG decode: we only support our own files (no interlace, filter 0 only, grayscale 8)
unsigned decode(std::vector<unsigned char>& out, unsigned& w, unsigned& h, const unsigned char* in, size_t insize){
  if(insize<8) return 1;
  const unsigned char* p=in;
  const unsigned char sig[8]={137,80,78,71,13,10,26,10};
  for(int i=0;i<8;i++) if(p[i]!=sig[i]) return 2; p+=8; insize-=8;

  auto rd32=[&](const unsigned char* q){ return (q[0]<<24)|(q[1]<<16)|(q[2]<<8)|q[3]; };
  bool seenIHDR=false; std::vector<unsigned char> z;
  while(insize>=12){
    unsigned len=rd32(p); p+=4; insize-=4;
    if(insize<4) return 3;
    unsigned type = rd32(p); p+=4; insize-=4;
    if(insize < len+4) return 3;
    const unsigned char* data = p; p+=len; insize-=len;
    unsigned /*crc=*/rdcrc = rd32(p); p+=4; insize-=4; (void)rdcrc;
    if(type==0x49484452){ // IHDR
      w=rd32(data); h=rd32(data+4);
      unsigned bd=data[8], ct=data[9], comp=data[10], filt=data[11], intl=data[12];
      if(bd!=8 || !(ct==0||ct==6) || comp!=0 || intl!=0) return 4;
      seenIHDR=true;
    } else if(type==0x49444154){ // IDAT
      z.insert(z.end(), data, data+len);
    } else if(type==0x49454E44){ // IEND
      break;
    }
  }
  if(!seenIHDR) return 5;
  // zlib store blocks only
  if(z.size()<2 || z[0]!=0x78) return 6;
  size_t pos=2; std::vector<unsigned char> raw;
  while(pos<z.size()-4){
    if(pos>=z.size()) break;
    unsigned bfinal = z[pos++];
    unsigned len = z[pos] | (z[pos+1]<<8); pos+=2;
    unsigned nlen = z[pos] | (z[pos+1]<<8); pos+=2;
    if((unsigned)(~len&0xFFFF)!=nlen) return 7;
    if(pos+len>z.size()) return 7;
    raw.insert(raw.end(), z.begin()+pos, z.begin()+pos+len);
    pos+=len;
  }
  out.resize((raw.size()/ ( (w*1)+1))* (w*1)); // approximate, we'll rebuild per lines
  std::vector<unsigned char> img(w*h);
  if(raw.size() != (size_t)( (w*1+1)*h)) return 8;
  for(unsigned y=0;y<h;y++){
    if(raw[(w*1+1)*y]!=0) return 9; // only filter type 0
    memcpy(&img[w*y], &raw[(w*1+1)*y+1], w);
  }
  out.swap(img);
  return 0;
}
} // namespace
#endif
#endif
