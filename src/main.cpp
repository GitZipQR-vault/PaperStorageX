// LodePNG version 20230410 (stripped minimal parts used: encode/decode of 8-bit grayscale/RGBA)
// zlib license by Lode Vandevenne. For full implementation see official repo. This is a compact subset.
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
#ifdef LODEPNG_COMPACT_IMPL
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
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
  for(size_t i=0;i<len;i++) c=table[(c^data[i])&0xFF]^(c>>1>>1>>1>>1>>1>>1>>1>>1);
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
  std::vector<unsigned char> png;
  const unsigned char sig[8]={137,80,78,71,13,10,26,10}; png.insert(png.end(),sig,sig+8);
  std::vector<unsigned char> ihdr; ihdr.reserve(17);
  write32(png,13);
  png.push_back('I'); png.push_back('H'); png.push_back('D'); png.push_back('R');
  write32(ihdr,w); write32(ihdr,h);
  ihdr.push_back(8);
  ihdr.push_back(grayscale?0:6);
  ihdr.push_back(0); ihdr.push_back(0); ihdr.push_back(0);
  png.insert(png.end(),ihdr.begin(),ihdr.end());
  unsigned c = crc32(&png[12], 4+13); write32(png,c);
  size_t bpp = grayscale?1:4;
  std::vector<unsigned char> raw; raw.resize((bpp*w+1)*h);
  for(unsigned y=0;y<h;y++){
    raw[(bpp*w+1)*y] = 0;
    memcpy(&raw[(bpp*w+1)*y+1], &image[bpp*w*y], bpp*w);
  }
  std::vector<unsigned char> z; z.reserve(raw.size()+64);
  z.push_back(0x78); z.push_back(0x01);
  size_t pos=0; unsigned ad=adler32(raw.data(), raw.size());
  while(pos<raw.size()){
    size_t chunk = std::min<size_t>(65535, raw.size()-pos);
    z.push_back((pos+chunk==raw.size())?1:0);
    unsigned len = (unsigned)chunk, nlen = ~len;
    z.push_back(len&255); z.push_back((len>>8)&255);
    z.push_back(nlen&255); z.push_back((nlen>>8)&255);
    z.insert(z.end(), raw.begin()+pos, raw.begin()+pos+chunk);
    pos+=chunk;
  }
  write32(z, ad);
  write32(png, (unsigned)z.size());
  png.push_back('I'); png.push_back('D'); png.push_back('A'); png.push_back('T');
  size_t idat_start = png.size();
  png.insert(png.end(), z.begin(), z.end());
  c = crc32(&png[idat_start-4], 4+z.size()); write32(png,c);
  write32(png,0); png.push_back('I'); png.push_back('E'); png.push_back('N'); png.push_back('D');
  c = crc32((const unsigned char*)"IEND",4); write32(png,c);
  out.swap(png); return 0;
}
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
    unsigned _rdcrc = rd32(p); p+=4; insize-=4; (void)_rdcrc;
    if(type==0x49484452){
      w=rd32(data); h=rd32(data+4);
      unsigned bd=data[8], ct=data[9], comp=data[10], filt=data[11], intl=data[12];
      if(bd!=8 || !(ct==0||ct==6) || comp!=0 || intl!=0) return 4; seenIHDR=true;
    } else if(type==0x49444154){ z.insert(z.end(), data, data+len);
    } else if(type==0x49454E44){ break; }
  }
  if(!seenIHDR) return 5;
  if(z.size()<2 || z[0]!=0x78) return 6;
  size_t pos=2; std::vector<unsigned char> raw;
  while(pos<z.size()-4){
    unsigned bfinal = z[pos++]; (void)bfinal;
    unsigned len = z[pos] | (z[pos+1]<<8); pos+=2;
    unsigned nlen = z[pos] | (z[pos+1]<<8); pos+=2;
    if((unsigned)(~len&0xFFFF)!=nlen) return 7;
    if(pos+len>z.size()) return 7;
    raw.insert(raw.end(), z.begin()+pos, z.begin()+pos+len); pos+=len;
  }
  std::vector<unsigned char> img(w*h);
  if(raw.size() != (size_t)((w*1+1)*h)) return 8;
  for(unsigned y=0;y<h;y++){
    if(raw[(w*1+1)*y]!=0) return 9;
    memcpy(&img[w*y], &raw[(w*1+1)*y+1], w);
  }
  out.swap(img); return 0;
}
} // namespace
#endif
#endif

// PaperStorageX — single multi-page PDF, streaming encode/decode, progress, flexible geometry, --folder, auto-names
// NOTE "nanotech": metadata tag; 500 TB/sheet is physically not feasible with printing.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <fstream>
#include <iostream>
#include <iterator>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cerrno>
#include <cmath>
#include <cctype>
#include <openssl/evp.h>
#include <openssl/rand.h>

static inline void flush_stderr(){ std::cerr.flush(); }

/* ====== tiny SHA256 ====== */
struct SHA256{
  uint32_t h[8]; uint64_t len; unsigned char buf[64]; size_t pos;
  SHA256(){ init(); }
  void init(){ h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19; len=0; pos=0; }
  static uint32_t rotr(uint32_t x,int n){ return (x>>n)|(x<<(32-n)); }
  static void compress(uint32_t h[8], const unsigned char* p){
    static const uint32_t K[64]={
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xc19bf174,0xe49b69c1,0xefbe4786
    };
    uint32_t w[64];
    for(int i=0;i<16;i++){
      w[i]=(p[4*i]<<24)|(p[4*i+1]<<16)|(p[4*i+2]<<8)|p[4*i+3];
    }
    for(int i=16;i<64;i++){
      uint32_t s0=(w[i-15]>>7|w[i-15]<<25)^(w[i-15]>>18|w[i-15]<<14)^(w[i-15]>>3);
      uint32_t s1=(w[i-2]>>17|w[i-2]<<15)^(w[i-2]>>19|w[i-2]<<13)^(w[i-2]>>10);
      w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int i=0;i<64;i++){
      uint32_t S1=(e>>6|e<<26)^(e>>11|e<<21)^(e>>25|e<<7);
      uint32_t ch=(e&f)^((~e)&g);
      uint32_t t1=hh+S1+ch+K[i]+w[i];
      uint32_t S0=(a>>2|a<<30)^(a>>13|a<<19)^(a>>22|a<<10);
      uint32_t maj=(a&b)^(a&c)^(b&c);
      uint32_t t2=S0+maj;
      hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
  }
  void update(const unsigned char* data,size_t lenBytes){
    len+=lenBytes*8;
    while(lenBytes>0){
      size_t take=64-pos; if(take>lenBytes) take=lenBytes;
      memcpy(buf+pos,data,take); pos+=take; data+=take; lenBytes-=take;
      if(pos==64){ compress(h,buf); pos=0; }
    }
  }
  void finish(unsigned char out[32]){
    unsigned char pad[128]; size_t p=0; pad[p++]=0x80;
    size_t z=(pos<=56)?(56-pos):(120-pos); memset(pad+p,0,z); p+=z;
    for(int i=7;i>=0;i--) pad[p++]=(len>>(8*i))&0xFF;
    update(pad,p);
    for(int i=0;i<8;i++){ out[4*i]=h[i]>>24; out[4*i+1]=(h[i]>>16)&255; out[4*i+2]=(h[i]>>8)&255; out[4*i+3]=h[i]&255; }
  }
};

/* ====== UI ====== */
namespace ui {
  static const char* R="\x1b[31m"; static const char* G="\x1b[32m"; static const char* Y="\x1b[33m";
  static const char* B="\x1b[34m"; static const char* M="\x1b[35m"; static const char* C="\x1b[36m"; static const char* N="\x1b[0m";
  bool quiet=false;
  void banner(){ if(quiet) return; std::cerr<<B<<"PaperStorageX"<<N<<" — printable secure storage (PDF)\n"
                                 <<"support: "<<M<<"0xa8b3A40008EDF9AF21D981Dc3A52aa0ed1cA88fD"<<N<<" [USD,ETH]\n"; }
  void step(const std::string&s){ if(!quiet) std::cerr<<C<<"» "<<s<<N<<"\n"; flush_stderr(); }
  void ok(const std::string&s){ if(!quiet) std::cerr<<G<<"✓ "<<s<<N<<"\n"; flush_stderr(); }
  void warn(const std::string&s){ if(!quiet) std::cerr<<Y<<"! "<<s<<N<<"\n"; flush_stderr(); }
  void fail(const std::string&s){ std::cerr<<R<<"✗ "<<s<<N<<"\n"; flush_stderr(); }
  void progress(const char* phase, uint64_t done, uint64_t total){
    if(quiet) return;
    double pct = (total==0)?100.0: (100.0 * (double)done / (double)total);
    if(pct>100) pct=100;
    std::cerr<<"\r"<<phase<<": "<<pct<<"% ("<<done<<"/"<<total<<")   ";
    flush_stderr();
  }
  void progress_done(const char* phase){
    if(quiet) return;
    std::cerr<<"\r"<<phase<<": 100%                       \n";
    flush_stderr();
  }
}

/* ====== path utils ====== */
static bool is_dir(const std::string& p){ struct stat st{}; return (stat(p.c_str(),&st)==0)&&S_ISDIR(st.st_mode); }
static void ensure_dir(const std::string& dir){
  if(dir.empty()||dir==".") return;
  if(is_dir(dir)) return;
  std::string cur;
  for(size_t i=0;i<dir.size();++i){
    if(dir[i]=='/'){ if(!cur.empty() && !is_dir(cur)) ::mkdir(cur.c_str(),0775); }
    cur.push_back(dir[i]);
  }
  if(!is_dir(dir) && ::mkdir(dir.c_str(),0775)!=0 && errno!=EEXIST)
    throw std::runtime_error("Cannot create folder: "+dir);
}
static std::string path_basename(const std::string& p){
  auto s=p.find_last_of("/"); return (s==std::string::npos)? p : p.substr(s+1);
}
static std::string path_stem(const std::string& p){
  std::string b=path_basename(p); auto d=b.find_last_of('.');
  return (d==std::string::npos)? b : b.substr(0,d);
}
static std::string join2(const std::string& a,const std::string& b){
  if(a.empty()||a==".") return b;
  if(a.back()=='/') return a+b;
  return a+"/"+b;
}

/* ====== geometry (runtime) ====== */
static unsigned G_IMG_W=11760, G_IMG_H=8268; // A4@600dpi
static unsigned G_MARGIN_PX=(unsigned)std::lround(5.0/25.4*600.0);
static unsigned G_CELL=1;

static inline uint64_t usable_cells_w(){ return (G_IMG_W>2*G_MARGIN_PX)? (G_IMG_W-2*G_MARGIN_PX)/G_CELL : 0; }
static inline uint64_t usable_cells_h(){ return (G_IMG_H>2*G_MARGIN_PX)? (G_IMG_H-2*G_MARGIN_PX)/G_CELL : 0; }
static inline uint64_t usable_bits(){ return usable_cells_w()*usable_cells_h(); }
static inline uint64_t usable_bytes(){ return usable_bits()/8ull; }

/* ====== io utils ====== */
static void rnd(unsigned char* b,size_t n){ if(RAND_bytes(b,(int)n)!=1) throw std::runtime_error("RAND_bytes failed"); }
static std::vector<unsigned char> read_file_small(const std::string& path){
  std::ifstream f(path,std::ios::binary); if(!f) throw std::runtime_error("Cannot open: "+path);
  return std::vector<unsigned char>((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
}

/* ====== packers to temp files (stream-friendly) ====== */
struct TempPack { std::string path; uint64_t size; };
static TempPack pack_tar_to_tmp(const std::string& dir){
  char tmpl[]="/tmp/paperx_tar_XXXXXX.tar"; int fd=mkstemps(tmpl,4); if(fd==-1) throw std::runtime_error("mkstemps failed"); close(fd);
  std::string tarf=tmpl;
  std::string cmd="tar -C '"+dir+"' -cf '"+tarf+"' .";
  int rc=system(cmd.c_str()); if(rc!=0) throw std::runtime_error("tar failed");
  struct stat st{}; if(stat(tarf.c_str(),&st)!=0) throw std::runtime_error("tar output not found");
  return TempPack{tarf,(uint64_t)st.st_size};
}
static TempPack pack_zip_to_tmp(const std::string& dir){
  char tmpl[]="/tmp/paperx_zip_XXXXXX.zip"; int fd=mkstemps(tmpl,4); if(fd==-1) throw std::runtime_error("mkstemps failed"); close(fd);
  std::string zipf=tmpl;
  std::string cmd="cd '"+dir+"' && zip -r -q '"+zipf+"' .";
  int rc=system(cmd.c_str()); if(rc!=0) throw std::runtime_error("zip failed");
  struct stat st{}; if(stat(zipf.c_str(),&st)!=0) throw std::runtime_error("zip output not found");
  return TempPack{zipf,(uint64_t)st.st_size};
}

/* ====== header ====== */
#pragma pack(push,1)
struct Header512_v3{
  char magic[8]; uint32_t version; uint64_t payload_size_total; uint32_t page_no; uint32_t pages_total;
  uint8_t uuid[16]; uint32_t width,height,margin; uint8_t sha256_total[32];
  uint32_t kdf_id; uint32_t N,r,p; uint8_t salt[16]; uint8_t nonce[12]; uint8_t tag[16];
  uint8_t reserved[512 - 8-4-8-4-4-16-4-4-4-32 -4-4-4-4-16 -12-16];
};
#pragma pack(pop)

static void uuid16(uint8_t u[16]){ rnd(u,16); u[6]=(u[6]&0x0F)|0x40; u[8]=(u[8]&0x3F)|0x80; }

static std::string out_pdf_name(const std::string& base){
  std::string b=base; if(b.size()<4||b.substr(b.size()-4)!=".pdf") b+=".pdf";
  return b;
}

/* ====== ISO pages ====== */
static void set_page_by_iso(const std::string& name, double dpi){
  double wmm=210, hmm=297;
  if(name=="A0"){ wmm=841; hmm=1189; }
  else if(name=="A1"){ wmm=594; hmm=841; }
  else if(name=="A2"){ wmm=420; hmm=594; }
  else if(name=="A3"){ wmm=297; hmm=420; }
  else if(name=="A4"){ wmm=210; hmm=297; }
  else throw std::runtime_error("Unknown ISO A page: "+name);
  auto mm_to_px=[&](double mm){ return (unsigned)std::llround(mm/25.4 * dpi); };
  G_IMG_W = mm_to_px(wmm);
  G_IMG_H = mm_to_px(hmm);
}

/* ====== raster ====== */
static void draw_markers(std::vector<unsigned char>& img){
  std::fill(img.begin(),img.end(),255);
  auto fill=[&](unsigned x,unsigned y,unsigned w,unsigned h,unsigned char v){
    for(unsigned j=0;j<h;j++){ unsigned row=(y+j)*G_IMG_W; for(unsigned i=0;i<w;i++) img[row+x+i]=v; }
  };
  unsigned s = std::min<unsigned>(200u, (unsigned)std::lround(8.0/25.4 * (double)G_IMG_W * 25.4 / (double)G_IMG_W));
  fill(G_MARGIN_PX,G_MARGIN_PX,s,s,0);
  fill(G_IMG_W-G_MARGIN_PX-s,G_MARGIN_PX,s,s,0);
  fill(G_MARGIN_PX,G_IMG_H-G_MARGIN_PX-s,s,s,0);
}
static void bits_to_image(std::vector<unsigned char>& img,const std::vector<unsigned char>& block){
  const uint64_t cells_w = usable_cells_w();
  const uint64_t cells_h = usable_cells_h();
  const uint64_t total_bits=(uint64_t)block.size()*8ull;
  uint64_t idx=0;
  for(uint64_t cy=0; cy<cells_h; ++cy){
    unsigned y0 = G_MARGIN_PX + (unsigned)(cy*G_CELL);
    for(uint64_t cx=0; cx<cells_w; ++cx){
      if(idx>=total_bits) return;
      unsigned x0 = G_MARGIN_PX + (unsigned)(cx*G_CELL);
      unsigned b=(block[idx>>3]>>(7-(idx&7)))&1u; ++idx;
      unsigned char v = b?0:255;
      for(unsigned dy=0; dy<G_CELL && y0+dy<G_IMG_H-G_MARGIN_PX; ++dy){
        unsigned row=(y0+dy)*G_IMG_W;
        for(unsigned dx=0; dx<G_CELL && x0+dx<G_IMG_W-G_MARGIN_PX; ++dx) img[row + x0 + dx] = v;
      }
    }
  }
}

/* ====== crypto ====== */
struct KdfCtx{ uint32_t N,r,p; unsigned char salt[16], key[32]; };
static const uint64_t SCRYPT_MAXMEM=256ull*1024*1024;
static void kdf_from_header(const unsigned char* pw,size_t pwlen,KdfCtx& k,const Header512_v3& H){
  k.N=H.N; k.r=H.r; k.p=H.p; std::memcpy(k.salt,H.salt,16);
  if(EVP_PBE_scrypt((const char*)pw,pwlen,k.salt,16,k.N,k.r,k.p,SCRYPT_MAXMEM,k.key,32)!=1)
    throw std::runtime_error("scrypt failed");
}

/* ====== AES-GCM ====== */
static std::vector<unsigned char> aes_dec(const unsigned char* key,const unsigned char* nonce,const std::vector<unsigned char>& c,const unsigned char tag[16]){
  std::vector<unsigned char> out(c.size()); int len=0,outl=0;
  EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new(); if(!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),nullptr,nullptr,nullptr);
  EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,12,nullptr);
  EVP_DecryptInit_ex(ctx,nullptr,nullptr,key,nonce);
  if(!c.empty()){ if(EVP_DecryptUpdate(ctx,out.data(),&len,c.data(),(int)c.size())!=1){ EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("DecryptUpdate failed"); } outl=len; }
  EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,16,(void*)tag);
  if(EVP_DecryptFinal_ex(ctx,out.data()+outl,&len)!=1){ EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("GCM auth failed (wrong password or corrupted data)"); }
  outl+=len; EVP_CIPHER_CTX_free(ctx); out.resize(outl); return out;
}

/* ====== PDF writer (multi-page, streaming to FILE*) ====== */
struct PdfWriter {
  FILE* fp=nullptr;
  std::vector<size_t> xref;
  std::vector<unsigned> kids; // page object numbers
  unsigned next_obj=3; // 1: Catalog, 2: Pages, from 3 — page-related
  bool opened=false;
  unsigned w=0,h=0;

  static void put_str(FILE* f, const std::string& s){ fwrite(s.data(),1,s.size(),f); }
  static void put_bin(FILE* f, const unsigned char* p,size_t n){ if(n) fwrite(p,1,n,f); }
  size_t off() const { return (size_t)ftell(fp); }

  void open(const std::string& path, unsigned W, unsigned H){
    w=W; h=H;
    fp=fopen(path.c_str(),"wb"); if(!fp) throw std::runtime_error("Cannot write: "+path);
    // header
    put_str(fp, "%PDF-1.4\n%âãÏÓ\n");
    opened=true;
  }

  // add one page (img is raw 8-bit gray, size w*h; block is PAPERX payload)
  void add_page(const std::vector<unsigned char>& img, const std::vector<unsigned char>& block){
    if(!opened) throw std::runtime_error("PdfWriter not opened");
    unsigned page_obj = next_obj++;
    unsigned img_obj  = next_obj++;
    unsigned cont_obj = next_obj++;
    unsigned px_obj   = next_obj++;

    kids.push_back(page_obj);

    // Page
    xref.push_back(off()); {
      char buf[256];
      snprintf(buf,sizeof(buf),
        "%u 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /XObject << /Im0 %u 0 R >> >> /MediaBox [0 0 %u %u] /Contents %u 0 R >>\nendobj\n",
        page_obj, img_obj, w, h, cont_obj);
      put_str(fp, buf);
    }

    // Image XObject
    xref.push_back(off()); {
      char hdr[256];
      snprintf(hdr,sizeof(hdr),
        "%u 0 obj\n<< /Type /XObject /Subtype /Image /Width %u /Height %u /ColorSpace /DeviceGray /BitsPerComponent 8 /Length %zu >>\nstream\n",
        img_obj, w, h, (size_t)img.size());
      put_str(fp, hdr); put_bin(fp, img.data(), img.size()); put_str(fp, "\nendstream\nendobj\n");
    }

    // Contents
    xref.push_back(off()); {
      char cnt[256];
      snprintf(cnt,sizeof(cnt),"%u 0 obj\n<< /Length 35 >>\nstream\nq\n%u 0 0 %u 0 0 cm\n/Im0 Do\nQ\nendstream\nendobj\n", cont_obj, w, h);
      put_str(fp, cnt);
    }

    // PAPERX opaque stream
    xref.push_back(off()); {
      char hdr[256];
      snprintf(hdr,sizeof(hdr), "%u 0 obj\n<< /Type /PAPERX /Length %zu >>\nstream\n", px_obj, (size_t)block.size());
      put_str(fp, hdr); put_bin(fp, block.data(), block.size()); put_str(fp, "\nendstream\nendobj\n");
    }
  }

  void finish(){
    if(!opened) return;
    // Catalog (obj 1)
    xref.insert(xref.begin(), 0); // placeholder for free object 0
    size_t cat_off = off();
    put_str(fp, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    // Pages (obj 2)
    size_t pages_off = off();
    put_str(fp, "2 0 obj\n<< /Type /Pages /Count ");
    char num[32]; snprintf(num,sizeof(num),"%zu", kids.size()); put_str(fp,num);
    put_str(fp, " /Kids [");
    for(size_t i=0;i<kids.size();++i){
      char id[32]; snprintf(id,sizeof(id)," %u 0 R", kids[i]); put_str(fp,id);
    }
    put_str(fp, " ] >>\nendobj\n");

    // record offsets for 1 and 2
    xref[0]=0; // free obj
    xref.push_back(cat_off);
    xref.push_back(pages_off);

    // xref
    size_t xref_pos = off();
    char head[64]; snprintf(head,sizeof(head),"xref\n0 %zu\n", xref.size()+1);
    put_str(fp, head);
    put_str(fp, "0000000000 65535 f \n");
    // Offsets order: objects were written as: pages/img/cont/px (per page)*, then 1,2.
    // We collected xref for page-related in order already, then appended 1 and 2 above.
    for(size_t i=0;i<xref.size();++i){
      if(i==0) continue; // already wrote free
      char line[32]; snprintf(line,sizeof(line),"%010zu 00000 n \n", xref[i]);
      put_str(fp, line);
    }

    // trailer
    put_str(fp, "trailer\n<< /Size ");
    char sz[32]; snprintf(sz,sizeof(sz),"%zu",(size_t)(xref.size()+1)); put_str(fp, sz);
    put_str(fp, " /Root 1 0 R >>\nstartxref\n");
    char pos[32]; snprintf(pos,sizeof(pos),"%zu\n", xref_pos); put_str(fp,pos);
    put_str(fp, "%%EOF\n");
    fclose(fp); fp=nullptr; opened=false;
  }
};

/* ====== password sources ====== */
struct Pw{ std::vector<unsigned char> v; };
static std::string read_line_fd(int fd){ std::string s; char ch; while(true){ ssize_t r=read(fd,&ch,1); if(r<=0) break; if(ch=='\n'||ch=='\r') break; s.push_back(ch);} return s; }
static std::string prompt_pwd(const char* prompt){
  int tty=open("/dev/tty",O_RDWR);
  if(tty>=0){
    (void)!write(tty,prompt,strlen(prompt));
    termios oldt; if(tcgetattr(tty,&oldt)!=0){ std::string s=read_line_fd(tty); close(tty); if(s.empty()) throw std::runtime_error("Empty password"); return s; }
    termios nt=oldt; nt.c_lflag&=~ECHO; tcsetattr(tty,TCSANOW,&nt);
    std::string s=read_line_fd(tty); (void)!write(tty,"\n",1); tcsetattr(tty,TCSANOW,&oldt); close(tty);
    if(s.empty()) throw std::runtime_error("Empty password"); return s;
  }
  std::cerr<<prompt<<std::flush; std::string a; std::getline(std::cin,a); if(a.empty()) throw std::runtime_error("Empty password"); return a;
}
static Pw pw_from_file(const std::string& path){ Pw pw; pw.v=read_file_small(path); return pw; }
static Pw pw_from_string(const std::string& s){ Pw pw; pw.v.assign(s.begin(),s.end()); return pw; }
static Pw pw_from_tty(){ return pw_from_string(prompt_pwd("Password: ")); }

/* ====== PAPERX extractor (ALL streams from one PDF) ====== */
static std::vector<std::vector<unsigned char>> read_all_paperx_from_pdf(const std::string& path){
  auto buf = read_file_small(path);
  const std::string key = "/Type /PAPERX";
  const std::string LKEY = "/Length";
  const unsigned char s1[]="stream\n", s2[]="stream\r\n";

  std::vector<std::vector<unsigned char>> res;
  auto p = buf.begin();
  while(true){
    auto pos = std::search(p, buf.end(), key.begin(), key.end());
    if(pos==buf.end()) break;

    auto lpos = std::search(pos, buf.end(), LKEY.begin(), LKEY.end());
    if(lpos==buf.end()) break;
    lpos += LKEY.size();
    auto it = lpos; while(it!=buf.end() && (*it==' '||*it=='\t'||*it=='\r'||*it=='\n')) ++it;
    if(it==buf.end() || !std::isdigit((unsigned char)*it)) throw std::runtime_error("Unsupported /Length (not a direct number)");
    size_t length = 0;
    while(it!=buf.end() && std::isdigit((unsigned char)*it)){ length = length*10 + (size_t)(*it - '0'); ++it; }

    auto p2 = std::search(it, buf.end(), s1, s1+7);
    if(p2==buf.end()) p2 = std::search(it, buf.end(), s2, s2+8);
    if(p2==buf.end()) throw std::runtime_error("stream not found");
    size_t data_off = (size_t)(p2 - buf.begin()) + ((p2[6]=='\n') ? 7 : 8);
    if(data_off + length > buf.size()) throw std::runtime_error("Truncated PAPERX stream");
    res.emplace_back(buf.begin()+data_off, buf.begin()+data_off+length);
    p = buf.begin()+data_off+length;
  }
  if(res.empty()) throw std::runtime_error("PAPERX stream(s) not found in: "+path);
  return res;
}

/* ====== helpers ====== */
static void draw_image_and_write_page(PdfWriter& pdf,const std::vector<unsigned char>& block){
  const uint64_t max_pixels = 2000000000ULL;
  if((uint64_t)G_IMG_W*(uint64_t)G_IMG_H > max_pixels)
    throw std::runtime_error("Page exceeds safe raster memory; reduce DPI or page size");
  std::vector<unsigned char> img((size_t)G_IMG_W*(size_t)G_IMG_H,255);
  draw_markers(img); bits_to_image(img,block); pdf.add_page(img,block);
}

/* ====== CLI usage ====== */
static void usage(const char* argv0){
  std::cerr<<"Usage:\n"
           <<"  "<<argv0<<" encode [--password <ascii>] [--bin <pwfile>] [--type <zip|tar>] [--page <A0|A1|A2|A3|A4|WxHmm>] [--dpi <int>] [--margin-mm <mm>] [--cell <px>] [--nanotech] [--folder <DIR>] [--quiet] [--no-tty] <input_path> [out_base]\n"
           <<"  "<<argv0<<" decode [--password <ascii>] [--bin <pwfile>] [--folder <DIR>] [--quiet] [--no-tty] <in.pdf> [out_file]\n";
}

/* ====== page parser ====== */
static bool parse_custom_mm(const std::string& s, double& wmm, double& hmm){
  if(s.size()<4) return false;
  if(s.substr(s.size()-2)!="mm") return false;
  auto x = s.find('x'); if(x==std::string::npos) return false;
  std::string ws=s.substr(0,x), hs=s.substr(x+1, s.size()-2-(x+1));
  char* e1=nullptr; char* e2=nullptr;
  double w=std::strtod(ws.c_str(), &e1);
  double h=std::strtod(hs.c_str(), &e2);
  if(e1==ws.c_str() || e2==hs.c_str()) return false;
  wmm=w; hmm=h; return true;
}

/* ====== encode (streaming, single multi-page PDF) ====== */
static void encode_stream(const std::string& src_path, uint64_t total_size,
                          const std::string& out_base, const std::string& type, bool tag_nanotech,
                          const std::vector<unsigned char>& sha_total,
                          const unsigned char key[32], uint32_t N, uint32_t r, uint32_t p, const unsigned char salt[16]){
  uint64_t cap=usable_bytes(); if(cap<=512) throw std::runtime_error("Invalid page geometry or too large cell/margins");
  uint64_t per=cap-512; if(per==0) throw std::runtime_error("No payload capacity on page");
  uint32_t pages=(uint32_t)((total_size + per - 1)/per); if(pages==0) pages=1;
  uint8_t uuid[16]; uuid16(uuid);

  if(tag_nanotech) ui::warn("nanotech preset is a metadata tag; physical 500TB-per-sheet is not feasible.");

  std::ifstream in(src_path, std::ios::binary);
  if(!in) throw std::runtime_error("Cannot open source: "+src_path);

  PdfWriter pdf;
  std::string pdf_path = out_pdf_name(out_base);
  pdf.open(pdf_path, G_IMG_W, G_IMG_H);

  uint64_t done=0;
  std::vector<unsigned char> chunk; chunk.resize((size_t)per);

  for(uint32_t pg=1; pg<=pages; ++pg){
    uint64_t take = std::min<uint64_t>(per, total_size - done);
    in.read((char*)chunk.data(), (std::streamsize)take);
    if((uint64_t)in.gcount()!=take) throw std::runtime_error("Short read from source");
    std::vector<unsigned char> slice(chunk.begin(), chunk.begin()+(size_t)take);

    Header512_v3 H{}; std::memcpy(H.magic,"PAPERX\0",8); H.version=3;
    H.payload_size_total=total_size; H.page_no=pg; H.pages_total=pages;
    std::memcpy(H.uuid,uuid,16); H.width=G_IMG_W; H.height=G_IMG_H; H.margin=G_MARGIN_PX;
    std::memcpy(H.sha256_total,sha_total.data(),32);
    H.kdf_id=1; H.N=N; H.r=r; H.p=p; std::memcpy(H.salt,salt,16);
    rnd(H.nonce,12);
    if(tag_nanotech){ H.reserved[0]='N'; H.reserved[1]='A'; H.reserved[2]='N'; H.reserved[3]='O'; H.reserved[4]=1; H.reserved[5]=(uint8_t)G_CELL; }
    H.reserved[10]='T'; H.reserved[11]='Y'; H.reserved[12]='P'; H.reserved[13]='E';
    if(type=="zip"){ H.reserved[14]='Z'; H.reserved[15]='I'; H.reserved[16]='P'; }
    else           { H.reserved[14]='T'; H.reserved[15]='A'; H.reserved[16]='R'; }

    // AES-GCM encrypt page slice
    std::vector<unsigned char> cipher(slice.size()); int len=0,outl=0;
    EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx,EVP_aes_256_gcm(),nullptr,nullptr,nullptr);
    EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,12,nullptr);
    EVP_EncryptInit_ex(ctx,nullptr,nullptr,key,H.nonce);
    if(!slice.empty()){ EVP_EncryptUpdate(ctx,cipher.data(),&len,slice.data(),(int)slice.size()); outl=len; }
    EVP_EncryptFinal_ex(ctx,cipher.data()+outl,&len); outl+=len;
    EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,16,H.tag);
    EVP_CIPHER_CTX_free(ctx);
    cipher.resize(outl);

    std::vector<unsigned char> block(512 + cipher.size());
    std::memcpy(block.data(),&H,512);
    if(!cipher.empty()) std::memcpy(block.data()+512,cipher.data(),cipher.size());

    draw_image_and_write_page(pdf,block);

    done += take;
    ui::progress("Encode", done, total_size);
  }
  ui::progress_done("Encode");
  pdf.finish();
}

/* ====== decode (streaming; assemble to temp-file) ====== */
static void decode_stream(const std::vector<std::string>& inputs, const std::string& out_file, const Pw& pw){
  ui::banner();
  if(inputs.empty()) throw std::runtime_error("No input PDFs");

  // read first PAPERX from first input to get header
  auto blocks0 = read_all_paperx_from_pdf(inputs[0]);
  auto block0 = blocks0[0];
  if(block0.size()<512) throw std::runtime_error("Block too small in first PDF");
  Header512_v3 H0{}; std::memcpy(&H0,block0.data(),512);
  if(std::memcmp(H0.magic,"PAPERX\0",8)!=0 || H0.version!=3) throw std::runtime_error("Unsupported header");
  G_IMG_W = H0.width; G_IMG_H = H0.height; G_MARGIN_PX = H0.margin;

  uint64_t total=H0.payload_size_total, cap=usable_bytes(), per=cap-512;

  ui::step("deriving key (scrypt) and validating password");
  KdfCtx k0; kdf_from_header(pw.v.data(),pw.v.size(),k0,H0);
  { std::vector<unsigned char> c0(block0.begin()+512,block0.end()); (void)aes_dec(k0.key,H0.nonce,c0,H0.tag); ui::ok("password OK"); }

  // proper mkstemp template (no suffix)
  char tmpl[]="/tmp/paperx_restore_XXXXXX";
  int tfd=mkstemp(tmpl);
  if(tfd<0) throw std::runtime_error("mkstemp failed");
  FILE* tf=fdopen(tfd,"w+b"); if(!tf){ close(tfd); unlink(tmpl); throw std::runtime_error("fdopen failed"); }
  if(ftruncate(tfd, (off_t)total)!=0){ fclose(tf); unlink(tmpl); throw std::runtime_error("ftruncate failed"); }

  std::vector<bool> placed(H0.pages_total+1,false);
  uint64_t placed_bytes=0;

  auto process_block=[&](const std::vector<unsigned char>& block){
    if(block.size()<512) throw std::runtime_error("Block too small");
    Header512_v3 H{}; std::memcpy(&H,block.data(),512);
    if(std::memcmp(H.magic,"PAPERX\0",8)!=0 || H.version!=3) throw std::runtime_error("Bad header");
    if(std::memcmp(H.uuid,H0.uuid,16)!=0) throw std::runtime_error("Mixed volumes");
    if(H.payload_size_total!=total || H.pages_total!=H0.pages_total) throw std::runtime_error("Inconsistent pages");

    KdfCtx k; kdf_from_header(pw.v.data(),pw.v.size(),k,H);
    uint64_t off=(uint64_t)(H.page_no-1)*per; uint64_t need=(off<total)?std::min<uint64_t>(per,total-off):0;

    std::vector<unsigned char> cipher(block.begin()+512,block.end());
    auto plain=aes_dec(k.key,H.nonce,cipher,H.tag);
    if(plain.size()<need) throw std::runtime_error("Truncated page data");

    if(fseek(tf,(long)off,SEEK_SET)!=0){ fclose(tf); unlink(tmpl); throw std::runtime_error("seek failed"); }
    if(need>0 && fwrite(plain.data(),1,(size_t)need,tf)!=(size_t)need){ fclose(tf); unlink(tmpl); throw std::runtime_error("write failed"); }
    if(!placed[H.page_no]){ placed[H.page_no]=true; placed_bytes += need; }
    ui::progress("Decode", placed_bytes, total);
  };

  for(const auto& f: inputs){
    ui::step("reading "+f);
    auto blocks = read_all_paperx_from_pdf(f);
    for(const auto& b: blocks) process_block(b);
  }
  ui::progress_done("Decode");
  fflush(tf); fsync(fileno(tf));

  // Verify SHA-256 streaming
  ui::step("verifying SHA-256");
  SHA256 s; const size_t CH=16*1024*1024; std::vector<unsigned char> ch; ch.resize(CH);
  if(fseek(tf,0,SEEK_SET)!=0){ fclose(tf); unlink(tmpl); throw std::runtime_error("seek2 failed"); }
  uint64_t read_total=0;
  for(;;){
    size_t r=fread(ch.data(),1,CH,tf);
    if(r==0) break;
    s.update(ch.data(),r); read_total+=r;
    ui::progress("Hash", read_total, total);
  }
  ui::progress_done("Hash");
  unsigned char shab[32]; s.finish(shab);
  if(memcmp(shab,H0.sha256_total,32)!=0){ fclose(tf); unlink(tmpl); throw std::runtime_error("SHA-256(total) mismatch"); }

  fclose(tf);

  // Move temp to final
  if(rename(tmpl, out_file.c_str())!=0){
    std::ifstream src(tmpl,std::ios::binary); std::ofstream dst(out_file,std::ios::binary);
    if(!src || !dst){ unlink(tmpl); throw std::runtime_error("finalize move failed"); }
    dst<<src.rdbuf(); src.close(); dst.close(); unlink(tmpl);
  }
  ui::ok("decoded");
}

/* ====== master encode wrapper ====== */
static void encode_cmd(const std::string& input,const std::string& out_base,const Pw& pw,const std::string& type, bool tag_nanotech){
  ui::banner();
  // Determine source stream path and total size
  std::string src_path=input; uint64_t total_size=0; bool temp=false;
  struct stat st{};
  if(is_dir(input)){
    ui::step(std::string("packing directory as ")+ (type=="zip"?"ZIP":"TAR"));
    TempPack P = (type=="zip") ? pack_zip_to_tmp(input) : pack_tar_to_tmp(input);
    src_path = P.path; total_size=P.size; temp=true;
  }else{
    if(stat(input.c_str(), &st)!=0) throw std::runtime_error("Cannot stat input");
    total_size = (uint64_t)st.st_size;
  }
  if(!ui::quiet) std::cerr<<"   size: "<<total_size<<" bytes\n";

  // Streaming SHA-256 of the whole plaintext
  ui::step("hashing (stream)");
  SHA256 s; const size_t CH=16*1024*1024; std::vector<unsigned char> ch; ch.resize(CH);
  std::ifstream ins(src_path, std::ios::binary);
  if(!ins) throw std::runtime_error("Cannot open for hashing: "+src_path);
  uint64_t hashed=0;
  for(;;){
    ins.read((char*)ch.data(), (std::streamsize)CH);
    std::streamsize r = ins.gcount();
    if(r<=0) break;
    s.update(ch.data(), (size_t)r); hashed += (uint64_t)r;
    ui::progress("Hash", hashed, total_size);
  }
  ui::progress_done("Hash");
  unsigned char shab[32]; s.finish(shab);
  std::vector<unsigned char> sha_total(shab, shab+32);

  // Derive key
  ui::step("deriving key (scrypt)");
  uint32_t N,r,p; unsigned char salt[16], key[32];
  N=1u<<15; r=8; p=1; rnd(salt,16);
  if(EVP_PBE_scrypt((const char*)pw.v.data(),pw.v.size(),salt,16,N,r,p,SCRYPT_MAXMEM,key,32)!=1)
    throw std::runtime_error("scrypt failed");
  ui::ok("kdf ready");

  // Encode pages streaming
  encode_stream(src_path, total_size, out_base, type, tag_nanotech, sha_total, key, N, r, p, salt);

  // cleanup temp pack
  if(temp) unlink(src_path.c_str());
}

/* ====== CLI main ====== */
int main(int argc,char** argv){
  try{
    if(argc<3){ usage(argv[0]); return 1; }
    std::string mode=argv[1];
    int i=2; std::string pwfile, pwascii, outtype="tar", outdir=""; bool no_tty=false; bool nanotech=false;
    std::string page="A4"; int dpi=600; double margin_mm=5.0; int cell=1;

    while(i<argc){
      std::string a=argv[i];
      if(a=="--password"){ if(i+1>=argc){ usage(argv[0]); return 1; } pwascii=argv[++i]; ++i; continue; }
      if(a=="--bin"){ if(i+1>=argc){ usage(argv[0]); return 1; } pwfile=argv[++i]; ++i; continue; }
      if(a=="--type"){ if(i+1>=argc){ usage(argv[0]); return 1; } outtype=argv[++i]; ++i; continue; }
      if(a=="--page"){ if(i+1>=argc){ usage(argv[0]); return 1; } page=argv[++i]; ++i; continue; }
      if(a=="--dpi"){ if(i+1>=argc){ usage(argv[0]); return 1; } dpi=std::max(72, std::atoi(argv[++i])); ++i; continue; }
      if(a=="--margin-mm"){ if(i+1>=argc){ usage(argv[0]); return 1; } margin_mm=std::max(0.0, std::atof(argv[++i])); ++i; continue; }
      if(a=="--cell"){ if(i+1>=argc){ usage(argv[0]); return 1; } cell=std::max(1, std::atoi(argv[++i])); ++i; continue; }
      if(a=="--nanotech"){ nanotech=true; ++i; continue; }
      if(a=="--folder"){ if(i+1>=argc){ usage(argv[0]); return 1; } outdir=argv[++i]; ++i; continue; }
      if(a=="--quiet"){ ui::quiet=true; ++i; continue; }
      if(a=="--no-tty"){ no_tty=true; ++i; continue; }
      break;
    }

    // geometry
    if(page=="A0"||page=="A1"||page=="A2"||page=="A3"||page=="A4"){
      set_page_by_iso(page, (double)dpi);
    } else {
      double wmm=210, hmm=297;
      if(parse_custom_mm(page, wmm, hmm)){
        auto mm_to_px=[&](double mm){ return (unsigned)std::llround(mm/25.4 * (double)dpi); };
        G_IMG_W = mm_to_px(wmm); G_IMG_H = mm_to_px(hmm);
      } else {
        ui::warn("Unknown --page; defaulting to A4");
        set_page_by_iso("A4", (double)dpi);
      }
    }
    G_MARGIN_PX = (unsigned)std::llround(margin_mm/25.4 * (double)dpi);
    G_CELL = (unsigned)cell;

    // Optional "nanotech" scaling guard
    if(nanotech){
      if(dpi < 1200){
        double w_mm = (double)G_IMG_W / (double)dpi * 25.4;
        double h_mm = (double)G_IMG_H / (double)dpi * 25.4;
        dpi = 1200;
        auto mm_to_px=[&](double mm){ return (unsigned)std::llround(mm/25.4 * (double)dpi); };
        G_IMG_W = mm_to_px(w_mm); G_IMG_H = mm_to_px(h_mm);
        G_MARGIN_PX = (unsigned)std::llround(margin_mm/25.4 * (double)dpi);
      }
      const uint64_t max_pixels = 2000000000ULL;
      if((uint64_t)G_IMG_W*(uint64_t)G_IMG_H > max_pixels){
        double scale = std::sqrt((double)max_pixels / ((double)G_IMG_W*(double)G_IMG_H));
        G_IMG_W = (unsigned)std::floor(G_IMG_W*scale);
        G_IMG_H = (unsigned)std::floor(G_IMG_H*scale);
        ui::warn("nanotech: scaled down to fit memory");
      }
    }

    Pw pw;
    if(!pwfile.empty()) pw=pw_from_file(pwfile);
    else if(!pwascii.empty()) pw=pw_from_string(pwascii);
    else { if(no_tty) throw std::runtime_error("No password source (--no-tty without --bin/--password)"); pw=pw_from_tty(); }

    if(mode=="encode"){
      if(argc-i<1){ usage(argv[0]); return 1; }
      std::string in=argv[i];
      std::string out_base;
      if(argc-i>=2){
        out_base = argv[i+1];
      }else{
        std::string base = path_stem(path_basename(in));
        if(base.empty()) base="paperx";
        ensure_dir(outdir.empty()? "." : outdir);
        out_base = join2(outdir.empty()? "." : outdir, base);
      }
      if(outtype!="tar" && outtype!="zip") throw std::runtime_error("--type must be zip|tar");
      if(!outdir.empty()) ensure_dir(outdir);
      encode_cmd(in,out_base,pw,outtype,nanotech);

    }else if(mode=="decode"){
      if(argc-i<1){ usage(argv[0]); return 1; }
      std::vector<std::string> ins;
      std::string out_path;
      if(!outdir.empty()){
        for(int j=i;j<argc;++j) ins.push_back(argv[j]);
        if(ins.empty()) { usage(argv[0]); return 1; }
        ensure_dir(outdir);
        // peek TYPE for extension
        auto blocks = read_all_paperx_from_pdf(ins[0]);
        Header512_v3 H0{}; if(!blocks.empty() && blocks[0].size()>=512) std::memcpy(&H0,blocks[0].data(),512);
        std::string ext = "tar";
        if(H0.reserved[10]=='T' && H0.reserved[11]=='Y' && H0.reserved[12]=='P' && H0.reserved[13]=='E'){
          if(H0.reserved[14]=='Z' && H0.reserved[15]=='I' && H0.reserved[16]=='P') ext="zip";
        }
        std::string base = path_stem(path_basename(ins[0]));
        out_path = join2(outdir, base + "." + ext);
      }else{
        if(argc-i<2){ usage(argv[0]); return 1; }
        for(int j=i;j<argc-1;++j) ins.push_back(argv[j]);
        out_path = argv[argc-1];
      }
      decode_stream(ins,out_path,pw);
    }else{
      usage(argv[0]); return 1;
    }
  }catch(const std::exception& e){
    ui::fail(e.what()); return 2;
  }
  return 0;
}
