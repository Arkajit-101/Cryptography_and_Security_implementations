/* RSA decryption victim with variable-time modular reduction.
   Times each decryption with CPUID-serialized RDTSC (see Kocher timing snippet).
   stdin : <n_hex> <d_hex> <reps>   then one ciphertext hex per line
   stdout: <ciphertext_hex>,<min_cycles>,<opcount>   per line            */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
typedef uint32_t u32; typedef uint64_t u64;
#define L 300                       /* limbs (base 2^16): handles big moduli */
typedef struct { u32 a[L]; int n; } BN;

static void norm(BN*x){ while(x->n>1 && x->a[x->n-1]==0) x->n--; }
static int cmp(const BN*x,const BN*y){
  if(x->n!=y->n) return x->n<y->n?-1:1;
  for(int i=x->n-1;i>=0;i--) if(x->a[i]!=y->a[i]) return x->a[i]<y->a[i]?-1:1;
  return 0; }
static void sub(BN*x,const BN*y){ int b=0;
  for(int i=0;i<x->n;i++){ int d=(int)x->a[i]-(i<y->n?(int)y->a[i]:0)-b;
    if(d<0){d+=65536;b=1;}else b=0; x->a[i]=d; } norm(x); }
static void scshl(const BN*nn,u32 q,int sh,BN*out){     /* out=(nn<<16*sh)*q */
  memset(out,0,sizeof(*out)); u64 c=0;
  for(int i=0;i<nn->n;i++){ u64 v=(u64)nn->a[i]*q+c; out->a[i+sh]=v&65535; c=v>>16; }
  int i=nn->n; while(c){ out->a[i+sh]=c&65535; c>>=16; i++; }
  out->n=nn->n+sh+2; if(out->n>L)out->n=L; norm(out); }
static int reduce(BN*R,const BN*N){                     /* R%=N, ret #corrections */
  norm(R); if(cmp(R,N)<0) return 0;
  int qd=R->n-N->n+1, corr=0; u32 top=N->a[N->n-1];
  for(int j=qd-1;j>=0;j--){ int p=j+N->n-1; u64 hi=0;
    if(p+1<R->n) hi=((u64)R->a[p+1]<<16); if(p<R->n) hi+=R->a[p];
    u32 q=(u32)(hi/top); if(q>65535)q=65535;
    BN t; scshl(N,q,j,&t);
    while(cmp(&t,R)>0){ BN s; scshl(N,1,j,&s); sub(&t,&s); corr++; }
    sub(R,&t);
    BN sh; scshl(N,1,j,&sh);
    while(cmp(R,&sh)>=0){ sub(R,&sh); corr++; } }
  return corr; }
static int mulmod(BN*r,const BN*a,const BN*b,const BN*N){
  BN p; memset(&p,0,sizeof(p));
  for(int i=0;i<a->n;i++){ u64 c=0;
    for(int j=0;j<b->n;j++){ u64 v=(u64)a->a[i]*b->a[j]+p.a[i+j]+c; p.a[i+j]=v&65535; c=v>>16; }
    int k=i+b->n; while(c){ u64 v=p.a[k]+c; p.a[k]=v&65535; c=v>>16; k++; } }
  p.n=a->n+b->n+1; if(p.n>L)p.n=L; norm(&p);
  int corr=reduce(&p,N); *r=p; return corr; }
/* CPUID-serialized RDTSC, exactly like the shared timing snippet */
static inline u64 tsc(){ u32 lo,hi;
  __asm__ volatile("xorl %%eax,%%eax\n cpuid":::"%eax","%ebx","%ecx","%edx");
  __asm__ volatile("rdtsc":"=a"(lo),"=d"(hi));
  __asm__ volatile("xorl %%eax,%%eax\n cpuid":::"%eax","%ebx","%ecx","%edx");
  return ((u64)hi<<32)|lo; }
static void hex2bn(const char*s,BN*x){ memset(x,0,sizeof(*x)); int len=strlen(s),limb=0,bit=0; x->n=1;
  for(int i=len-1;i>=0;i--){ int c=s[i]; int v=c<='9'?c-'0':(c|32)-'a'+10;
    x->a[limb]|=v<<bit; bit+=4; if(bit==16){bit=0;limb++; if(limb>=x->n)x->n=limb+1;} }
  if(x->n>L)x->n=L; norm(x); }
/* one decryption c^d mod N; counts corrections into *op */
static void decrypt(const BN*C,const BN*D,const BN*N,int w,int*op){
  BN s; memset(&s,0,sizeof(s)); s.a[0]=1; s.n=1; int corr=0;
  for(int k=w-1;k>=0;k--){ BN t; corr+=mulmod(&t,&s,&s,N); s=t;
    if((D->a[k/16]>>(k%16))&1){ corr+=mulmod(&t,&s,C,N); s=t; } }
  *op=corr; }
int main(){
  char nh[20000],dh[20000],ch[20000]; int reps;
  if(scanf("%s %s %d",nh,dh,&reps)!=3) return 1;
  BN N,D; hex2bn(nh,&N); hex2bn(dh,&D);
  int w=0; for(int i=D.n-1;i>=0;i--){int b; for(b=15;b>=0;b--) if(D.a[i]>>b){w=i*16+b+1;goto d;}} d:;
  while(scanf("%s",ch)==1){ BN C; hex2bn(ch,&C);
    int op=0; u64 best=~0ULL;
    for(int r=0;r<reps;r++){ int o; u64 t0=tsc(); decrypt(&C,&D,&N,w,&o); u64 t1=tsc();
      if(t1-t0<best)best=t1-t0; op=o; }
    printf("%s,%llu,%d\n",ch,(unsigned long long)best,op); }
  return 0; }
