// PaperStorageX — flexible geometry + --folder + auto-names; stores TYPE in header.reserved.
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
#include <openssl/evp.h>
#include <openssl/rand.h>

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
    for(int i=0;i<16;i++) w[i]=(p[4*i]<<24)|(p[4*i+1]<<16)|(p[4*i+2]<<8)|p[4*i+3];
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
  static std::vector<unsigned char> hash(const std::vector<unsigned char>& v){ SHA256 s; s.update(v.data(),v.size()); std::vector<unsigned char> out(32); s.finish(out.data()); return out; }
};

/* UI */
namespace ui {
  static const char* R="\x1b[31m"; static const char* G="\x1b[32m"; static const char* Y="\x1b[33m";
  static const char* B="\x1b[34m"; static const char* M="\x1b[35m"; static const char* C="\x1b[36m"; static const char* N="\x1b[0m";
  bool quiet=false;
  void banner(){ if(quiet) return; std::cerr<<B<<"PaperStorageX"<<N<<" — printable secure storage (PDF)\n"
                                 <<"support: "<<M<<"0xa8b3A40008EDF9AF21D981Dc3A52aa0ed1cA88fD"<<N<<" [USD,ETH]\n"; }
  void step(const std::string&s){ if(!quiet) std::cerr<<C<<"» "<<s<<N<<"\n"; }
  void ok(const std::string&s){ if(!quiet) std::cerr<<G<<"✓ "<<s<<N<<"\n"; }
  void warn(const std::string&s){ if(!quiet) std::cerr<<Y<<"! "<<s<<N<<"\n"; }
  void fail(const std::string&s){ std::cerr<<R<<"✗ "<<s<<N<<"\n"; }
}

/* path helpers */
static bool is_dir(const std::string& p){ struct stat st{}; return (stat(p.c_str(),&st)==0)&&S_ISDIR(st.st_mode); }
static void ensure_dir(const std::string& dir){
  if(dir.empty() || dir=="." ) return;
  if(is_dir(dir)) return;
  if(::mkdir(dir.c_str(), 0775)!=0){
    // try -p style
    std::string cur;
    for(size_t i=0;i<dir.size();++i){
      if(dir[i]=='/'){ if(!cur.empty() && !is_dir(cur)) ::mkdir(cur.c_str(),0775); }
      cur.push_back(dir[i]);
    }
    if(!is_dir(dir) && ::mkdir(dir.c_str(),0775)!=0 && errno!=EEXIST)
      throw std::runtime_error("Cannot create folder: "+dir);
  }
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

/* geometry (runtime) */
static unsigned G_IMG_W=11760, G_IMG_H=8268;
static unsigned G_MARGIN_PX=(unsigned)std::lround(5.0/25.4*600.0);
static unsigned G_CELL=1;

static inline uint64_t usable_cells_w(){ return (G_IMG_W>2*G_MARGIN_PX)? (G_IMG_W-2*G_MARGIN_PX)/G_CELL : 0; }
static inline uint64_t usable_cells_h(){ return (G_IMG_H>2*G_MARGIN_PX)? (G_IMG_H-2*G_MARGIN_PX)/G_CELL : 0; }
static inline uint64_t usable_bits(){ return usable_cells_w()*usable_cells_h(); }
static inline uint64_t usable_bytes(){ return usable_bits()/8ull; }

/* io utils */
static void rnd(unsigned char* b,size_t n){ if(RAND_bytes(b,(int)n)!=1) throw std::runtime_error("RAND_bytes failed"); }
static std::vector<unsigned char> read_file(const std::string& path){
  std::ifstream f(path,std::ios::binary); if(!f) throw std::runtime_error("Cannot open: "+path);
  return std::vector<unsigned char>((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
}
static void write_file(const std::string& path,const std::vector<unsigned char>& data){
  std::ofstream f(path,std::ios::binary); if(!f) throw std::runtime_error("Cannot write: "+path);
  f.write((const char*)data.data(),(std::streamsize)data.size());
}
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

/* packers */
static std::vector<unsigned char> pack_tar(const std::string& dir){
  std::string cmd="tar -C '"+dir+"' -cf - ."; FILE* p=popen(cmd.c_str(),"r"); if(!p) throw std::runtime_error("tar spawn failed");
  std::vector<unsigned char> out; unsigned char b[1<<16];
  for(;;){ size_t n=fread(b,1,sizeof(b),p); if(n>0) out.insert(out.end(),b,b+n); if(n<sizeof(b)){ if(feof(p)) break; if(ferror(p)){ pclose(p); throw std::runtime_error("tar read error"); } } }
  int rc=pclose(p); if(rc!=0) throw std::runtime_error("tar returned non-zero"); return out;
}
static std::vector<unsigned char> pack_zip(const std::string& dir){
  char tmpl[]="/tmp/paperx_zip_XXXXXX.zip"; int fd=mkstemps(tmpl,4); if(fd==-1) throw std::runtime_error("mkstemps failed"); close(fd);
  std::string zipf=tmpl; std::string cmd="cd '"+dir+"' && zip -r -q '"+zipf+"' ."; int rc=system(cmd.c_str()); if(rc!=0) throw std::runtime_error("zip failed");
  auto data=read_file(zipf); unlink(zipf.c_str()); return data;
}

/* header */
#pragma pack(push,1)
struct Header512_v3{
  char magic[8]; uint32_t version; uint64_t payload_size_total; uint32_t page_no; uint32_t pages_total;
  uint8_t uuid[16]; uint32_t width,height,margin; uint8_t sha256_total[32];
  uint32_t kdf_id; uint32_t N,r,p; uint8_t salt[16]; uint8_t nonce[12]; uint8_t tag[16];
  uint8_t reserved[512 - 8-4-8-4-4-16-4-4-4-32 -4-4-4-4-16 -12-16];
};
#pragma pack(pop)

static void uuid16(uint8_t u[16]){ rnd(u,16); u[6]=(u[6]&0x0F)|0x40; u[8]=(u[8]&0x3F)|0x80; }
static std::string page_name(const std::string& base,uint32_t p,uint32_t total){
  std::string b=base; if(b.size()<4||b.substr(b.size()-4)!=".pdf") b+=".pdf";
  if(total==1) return b; auto dot=b.rfind(".pdf"); char buf[32]; std::snprintf(buf,sizeof(buf),".p%03u.pdf",p); return b.substr(0,dot)+buf;
}

/* ISO A-series */
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

/* raster */
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

/* crypto */
struct KdfCtx{ uint32_t N,r,p; unsigned char salt[16], key[32]; };
static const uint64_t SCRYPT_MAXMEM=256ull*1024*1024;
static void kdf_from_header(const unsigned char* pw,size_t pwlen,KdfCtx& k,const Header512_v3& H){
  k.N=H.N; k.r=H.r; k.p=H.p; std::memcpy(k.salt,H.salt,16);
  if(EVP_PBE_scrypt((const char*)pw,pwlen,k.salt,16,k.N,k.r,k.p,SCRYPT_MAXMEM,k.key,32)!=1)
    throw std::runtime_error("scrypt failed");
}
static void kdf_make(const unsigned char* pw,size_t pwlen, uint32_t& N, uint32_t& r, uint32_t& p, unsigned char salt[16], unsigned char key[32]){
  N=1u<<15; r=8; p=1; rnd(salt,16);
  if(EVP_PBE_scrypt((const char*)pw,pwlen,salt,16,N,r,p,SCRYPT_MAXMEM,key,32)!=1)
    throw std::runtime_error("scrypt failed");
}

/* AES-GCM */
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

/* PDF with embedded PAPERX */
struct PdfBuf{ std::vector<unsigned char> b; std::vector<size_t> xref; void put(const std::string& s){ b.insert(b.end(),s.begin(),s.end()); } void putbin(const unsigned char* p,size_t n){ b.insert(b.end(),p,p+n);} size_t off()const{return b.size();}};
static void write_pdf_page(const std::string& pdf,const std::vector<unsigned char>& img,const std::vector<unsigned char>& block){
  PdfBuf P;
  P.put("%PDF-1.4\n%âãÏÓ\n");
  P.xref.push_back(P.off()); P.put("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
  P.xref.push_back(P.off()); P.put("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
  P.xref.push_back(P.off()); { char buf[256]; std::snprintf(buf,sizeof(buf),
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /XObject << /Im0 4 0 R >> >> /MediaBox [0 0 %u %u] /Contents 5 0 R >>\nendobj\n",
    G_IMG_W,G_IMG_H); P.put(buf); }
  P.xref.push_back(P.off()); { char hdr[256]; std::snprintf(hdr,sizeof(hdr),
    "4 0 obj\n<< /Type /XObject /Subtype /Image /Width %u /Height %u /ColorSpace /DeviceGray /BitsPerComponent 8 /Length %zu >>\nstream\n",
    G_IMG_W,G_IMG_H,(size_t)img.size()); P.put(hdr); P.putbin(img.data(),img.size()); P.put("\nendstream\nendobj\n"); }
  P.xref.push_back(P.off()); { P.put("5 0 obj\n<< /Length 35 >>\nstream\nq\n"); char m[128]; std::snprintf(m,sizeof(m),"%u 0 0 %u 0 0 cm\n",G_IMG_W,G_IMG_H); P.put(m); P.put("/Im0 Do\nQ\nendstream\nendobj\n"); }
  P.xref.push_back(P.off()); { char hdr[256]; std::snprintf(hdr,sizeof(hdr),"6 0 obj\n<< /Type /PAPERX /Length %zu >>\nstream\n",(size_t)block.size()); P.put(hdr); P.putbin(block.data(),block.size()); P.put("\nendstream\nendobj\n"); }
  size_t xref_pos=P.off();
  P.put("xref\n0 7\n0000000000 65535 f \n");
  for(size_t i=0;i<P.xref.size();++i){ char line[32]; std::snprintf(line,sizeof(line),"%010zu 00000 n \n",P.xref[i]); P.put(line); }
  P.put("trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n"); { char num[32]; std::snprintf(num,sizeof(num),"%zu\n",xref_pos); P.put(num);} P.put("%%EOF\n");
  std::ofstream f(pdf,std::ios::binary); if(!f) throw std::runtime_error("Cannot write: "+pdf); f.write((const char*)P.b.data(),(std::streamsize)P.b.size());
}

/* password sources */
struct Pw{ std::vector<unsigned char> v; };
static Pw pw_from_file(const std::string& path){ Pw pw; pw.v=read_file(path); return pw; }
static Pw pw_from_string(const std::string& s){ Pw pw; pw.v.assign(s.begin(),s.end()); return pw; }
static Pw pw_from_tty(){ return pw_from_string(prompt_pwd("Password: ")); }

/* PAPERX stream reader by /Length */
static std::vector<unsigned char> read_paperx_from_pdf(const std::string& path){
  auto buf = read_file(path);
  const std::string key = "/Type /PAPERX";
  auto pos = std::search(buf.begin(), buf.end(), key.begin(), key.end());
  if(pos==buf.end()) throw std::runtime_error("PAPERX stream not found in: "+path);

  const std::string LKEY = "/Length";
  auto lpos = std::search(pos, buf.end(), LKEY.begin(), LKEY.end());
  if(lpos==buf.end()) throw std::runtime_error("Length not found for PAPERX: "+path);
  lpos += LKEY.size();
  auto it = lpos; while(it!=buf.end() && (*it==' '||*it=='\t'||*it=='\r'||*it=='\n')) ++it;
  if(it==buf.end() || !std::isdigit((unsigned char)*it)) throw std::runtime_error("Unsupported /Length (not a direct number)");
  size_t length = 0;
  while(it!=buf.end() && std::isdigit((unsigned char)*it)){ length = length*10 + (size_t)(*it - '0'); ++it; }

  const unsigned char s1[]="stream\n", s2[]="stream\r\n";
  auto p2 = std::search(it, buf.end(), s1, s1+7);
  if(p2==buf.end()) p2 = std::search(it, buf.end(), s2, s2+8);
  if(p2==buf.end()) throw std::runtime_error("stream not found: "+path);
  size_t data_off = (size_t)(p2 - buf.begin()) + ((p2[6]=='\n') ? 7 : 8);
  if(data_off + length > buf.size()) throw std::runtime_error("Truncated PAPERX stream");
  return std::vector<unsigned char>(buf.begin()+data_off, buf.begin()+data_off+length);
}

/* helpers */
static void draw_image_and_write(const std::string& pdf,const std::vector<unsigned char>& block){
  std::vector<unsigned char> img((size_t)G_IMG_W*(size_t)G_IMG_H,255);
  draw_markers(img); bits_to_image(img,block); write_pdf_page(pdf,img,block);
}

/* encode/decode core */
static void encode_cmd(const std::string& input,const std::string& out_base,const Pw& pw,const std::string& type, bool tag_nanotech){
  ui::banner();
  ui::step("reading input");
  std::vector<unsigned char> plain;
  if(is_dir(input)){
    if(type=="zip"){ ui::step("packing directory as ZIP"); plain=pack_zip(input); }
    else           { ui::step("packing directory as TAR"); plain=pack_tar(input); }
    if(!ui::quiet) std::cerr<<"   size: "<<plain.size()<<" bytes\n";
  }else{
    plain=read_file(input); if(!ui::quiet) std::cerr<<"   size: "<<plain.size()<<" bytes\n";
  }
  auto sha=SHA256::hash(plain);

  ui::step("deriving key (scrypt)");
  uint32_t N,r,p; unsigned char salt[16], key[32];
  kdf_make(pw.v.data(),pw.v.size(),N,r,p,salt,key);
  ui::ok("kdf ready");

  uint64_t cap=usable_bytes(); if(cap<=512) throw std::runtime_error("Invalid page geometry or too large cell/margins");
  uint64_t per=cap-512; uint32_t pages=(uint32_t)((plain.size()+per-1)/per); if(pages==0) pages=1;
  uint8_t uuid[16]; uuid16(uuid);

  if(tag_nanotech){
    ui::warn("nanotech preset is a metadata tag; physical 500TB-per-sheet is not feasible with printing.");
  }

  for(uint32_t pg=1; pg<=pages; ++pg){
    uint64_t off=(uint64_t)(pg-1)*per, take=std::min<uint64_t>(per,plain.size()-off);
    std::vector<unsigned char> chunk; if(take>0) chunk.assign(plain.begin()+off,plain.begin()+off+take);

    Header512_v3 H{}; std::memcpy(H.magic,"PAPERX\0",8); H.version=3;
    H.payload_size_total=plain.size(); H.page_no=pg; H.pages_total=pages;
    std::memcpy(H.uuid,uuid,16); H.width=G_IMG_W; H.height=G_IMG_H; H.margin=G_MARGIN_PX;
    std::memcpy(H.sha256_total,sha.data(),32);
    H.kdf_id=1; H.N=N; H.r=r; H.p=p; std::memcpy(H.salt,salt,16);
    rnd(H.nonce,12);
    // reserved tags:
    // [0..4): "NANO"+v when tag_nanotech; [10..13]="TYPE", [14..17]="TAR"/"ZIP"
    if(tag_nanotech){ H.reserved[0]='N'; H.reserved[1]='A'; H.reserved[2]='N'; H.reserved[3]='O'; H.reserved[4]=1; H.reserved[5]=(uint8_t)G_CELL; }
    H.reserved[10]='T'; H.reserved[11]='Y'; H.reserved[12]='P'; H.reserved[13]='E';
    if(type=="zip"){ H.reserved[14]='Z'; H.reserved[15]='I'; H.reserved[16]='P'; }
    else           { H.reserved[14]='T'; H.reserved[15]='A'; H.reserved[16]='R'; }

    std::vector<unsigned char> cipher(chunk.size()); int len=0,outl=0;
    EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx,EVP_aes_256_gcm(),nullptr,nullptr,nullptr);
    EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,12,nullptr);
    EVP_EncryptInit_ex(ctx,nullptr,nullptr,key,H.nonce);
    if(!chunk.empty()){ EVP_EncryptUpdate(ctx,cipher.data(),&len,chunk.data(),(int)chunk.size()); outl=len; }
    EVP_EncryptFinal_ex(ctx,cipher.data()+outl,&len); outl+=len;
    EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,16,H.tag);
    EVP_CIPHER_CTX_free(ctx);
    cipher.resize(outl);

    std::vector<unsigned char> block(512 + cipher.size());
    std::memcpy(block.data(),&H,512);
    if(!cipher.empty()) std::memcpy(block.data()+512,cipher.data(),cipher.size());

    std::string pdf=page_name(out_base,pg,pages);
    ui::step("writing "+pdf);
    draw_image_and_write(pdf,block);
  }
  ui::ok("done");
}

static void decode_cmd(const std::vector<std::string>& pdfs,const std::string& out_file,const Pw& pw){
  ui::banner();
  if(pdfs.empty()) throw std::runtime_error("No input PDFs");

  ui::step("reading first page");
  auto block0=read_paperx_from_pdf(pdfs[0]);
  if(block0.size()<512) throw std::runtime_error("Block too small in first PDF");
  Header512_v3 H0{}; std::memcpy(&H0,block0.data(),512);
  if(std::memcmp(H0.magic,"PAPERX\0",8)!=0 || H0.version!=3) throw std::runtime_error("Unsupported header");

  // adopt geometry from the file
  G_IMG_W = H0.width; G_IMG_H = H0.height; G_MARGIN_PX = H0.margin;

  uint64_t total=H0.payload_size_total, cap=usable_bytes(), per=cap-512;

  ui::step("deriving key (scrypt) and validating password");
  KdfCtx k0; kdf_from_header(pw.v.data(),pw.v.size(),k0,H0);
  { std::vector<unsigned char> c0(block0.begin()+512,block0.end()); (void)aes_dec(k0.key,H0.nonce,c0,H0.tag); ui::ok("password OK"); }

  std::vector<bool> seen(H0.pages_total+1,false);
  struct Part{ uint32_t no; std::vector<unsigned char> plain; };
  std::vector<Part> parts; parts.reserve(H0.pages_total);

  for(const auto& f: pdfs){
    ui::step("reading "+f);
    auto block=read_paperx_from_pdf(f);
    if(block.size()<512) throw std::runtime_error("Block too small in "+f);
    Header512_v3 H{}; std::memcpy(&H,block.data(),512);
    if(std::memcmp(H.magic,"PAPERX\0",8)!=0 || H.version!=3) throw std::runtime_error("Bad header: "+f);
    if(std::memcmp(H.uuid,H0.uuid,16)!=0) throw std::runtime_error("Mixed volumes: "+f);
    if(H.payload_size_total!=total || H.pages_total!=H0.pages_total) throw std::runtime_error("Inconsistent pages: "+f);

    KdfCtx k; kdf_from_header(pw.v.data(),pw.v.size(),k,H);
    uint64_t off=(uint64_t)(H.page_no-1)*per; uint64_t need=(off<total)?std::min<uint64_t>(per,total-off):0;

    std::vector<unsigned char> cipher(block.begin()+512,block.end());
    auto plain=aes_dec(k.key,H.nonce,cipher,H.tag);
    if(plain.size()<need) throw std::runtime_error("Truncated page data");
    parts.push_back(Part{H.page_no,std::move(plain)});
    seen[H.page_no]=true;
  }

  for(uint32_t i=1;i<=H0.pages_total;i++) if(!seen[i]) ui::warn("missing page p"+std::to_string(i));

  std::sort(parts.begin(),parts.end(),[](const Part&a,const Part&b){return a.no<b.no;});
  std::vector<unsigned char> assembled; assembled.reserve(total);
  for(auto& P: parts){
    uint64_t off=(uint64_t)(P.no-1)*per; uint64_t need=(off<total)?std::min<uint64_t>(per,total-off):0;
    assembled.insert(assembled.end(),P.plain.begin(),P.plain.begin()+need);
  }
  assembled.resize((size_t)total);

  auto sha=SHA256::hash(assembled);
  if(std::memcmp(sha.data(),H0.sha256_total,32)!=0) throw std::runtime_error("SHA-256(total) mismatch");

  ui::step("writing output "+out_file);
  write_file(out_file,assembled);
  ui::ok("decoded");
}

/* CLI */
static void usage(const char* argv0){
  std::cerr<<"Usage:\n"
           <<"  "<<argv0<<" encode [--password <ascii>] [--bin <pwfile>] [--type <zip|tar>] [--page <A0|A1|A2|A3|A4|WxHmm>] [--dpi <int>] [--margin-mm <mm>] [--cell <px>] [--nanotech] [--folder <DIR>] [--quiet] [--no-tty] <input_path> [out_base]\n"
           <<"  "<<argv0<<" decode [--password <ascii>] [--bin <pwfile>] [--folder <DIR>] [--quiet] [--no-tty] <page1.pdf> [page2.pdf ...] [out_file]\n";
}

/* page parser */
static bool parse_custom_mm(const std::string& s, double& wmm, double& hmm){
  if(s.size()<4) return false;
  if(s.substr(s.size()-2)!="mm") return false;
  auto x = s.find('x');
  if(x==std::string::npos) return false;
  std::string ws=s.substr(0,x);
  std::string hs=s.substr(x+1, s.size()-2-(x+1));
  char* e1=nullptr; char* e2=nullptr;
  double w=std::strtod(ws.c_str(), &e1);
  double h=std::strtod(hs.c_str(), &e2);
  if(e1==ws.c_str() || e2==hs.c_str()) return false;
  wmm=w; hmm=h; return true;
}

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
      std::vector<std::string> pages;
      std::string out_path;
      if(!outdir.empty()){
        // all remaining args are PDFs
        for(int j=i;j<argc;++j) pages.push_back(argv[j]);
        if(pages.empty()) { usage(argv[0]); return 1; }
        ensure_dir(outdir);
        // detect TYPE from header to choose extension
        auto block0=read_paperx_from_pdf(pages[0]);
        Header512_v3 H0{}; if(block0.size()>=512) std::memcpy(&H0,block0.data(),512);
        std::string ext = "tar";
        if(H0.reserved[10]=='T' && H0.reserved[11]=='Y' && H0.reserved[12]=='P' && H0.reserved[13]=='E'){
          if(H0.reserved[14]=='Z' && H0.reserved[15]=='I' && H0.reserved[16]=='P') ext="zip";
        }
        std::string base = path_stem(path_basename(pages[0]));
        out_path = join2(outdir, base + "." + ext);
      }else{
        if(argc-i<2){ usage(argv[0]); return 1; }
        for(int j=i;j<argc-1;++j) pages.push_back(argv[j]);
        out_path = argv[argc-1];
      }
      decode_cmd(pages,out_path,pw);
    }else{
      usage(argv[0]); return 1;
    }
  }catch(const std::exception& e){
    ui::fail(e.what()); return 2;
  }
  return 0;
}
