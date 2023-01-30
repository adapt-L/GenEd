#include <ctype.h>

//derived from supercop's ref10 (https://bench.cr.yp.to/supercop.html)

uint64_t sha512_load_bigendian(const uint8_t *x){
	return (uint64_t) (x[7]) \
	| (((uint64_t) (x[6])) << 8) \
	| (((uint64_t) (x[5])) << 16) \
	| (((uint64_t) (x[4])) << 24) \
	| (((uint64_t) (x[3])) << 32) \
	| (((uint64_t) (x[2])) << 40) \
	| (((uint64_t) (x[1])) << 48) \
	| (((uint64_t) (x[0])) << 56);
}
void sha512_store_bigendian(uint8_t *x,uint64_t u){
	x[7] = u; u >>= 8;
	x[6] = u; u >>= 8;
	x[5] = u; u >>= 8;
	x[4] = u; u >>= 8;
	x[3] = u; u >>= 8;
	x[2] = u; u >>= 8;
	x[1] = u; u >>= 8;
	x[0] = u;
}
#define SHA512_SHR(x,c) ((x) >> (c))
#define SHA512_ROTR(x,c) (((x) >> (c)) | ((x) << (64 - (c))))
#define SHA512_Ch(x,y,z) ((x & y) ^ (~x & z))
#define SHA512_Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA512_Sigma0(x) (SHA512_ROTR(x,28) ^ SHA512_ROTR(x,34) ^ SHA512_ROTR(x,39))
#define SHA512_Sigma1(x) (SHA512_ROTR(x,14) ^ SHA512_ROTR(x,18) ^ SHA512_ROTR(x,41))
#define SHA512_sigma0(x) (SHA512_ROTR(x, 1) ^ SHA512_ROTR(x, 8) ^ SHA512_SHR(x,7))
#define SHA512_sigma1(x) (SHA512_ROTR(x,19) ^ SHA512_ROTR(x,61) ^ SHA512_SHR(x,6))
#define SHA512_M(w0,w14,w9,w1) w0 = SHA512_sigma1(w14) + w9 + SHA512_sigma0(w1) + w0;
#define SHA512_EXPAND \
	SHA512_M(w0 ,w14,w9 ,w1 ) \
	SHA512_M(w1 ,w15,w10,w2 ) \
	SHA512_M(w2 ,w0 ,w11,w3 ) \
	SHA512_M(w3 ,w1 ,w12,w4 ) \
	SHA512_M(w4 ,w2 ,w13,w5 ) \
	SHA512_M(w5 ,w3 ,w14,w6 ) \
	SHA512_M(w6 ,w4 ,w15,w7 ) \
	SHA512_M(w7 ,w5 ,w0 ,w8 ) \
	SHA512_M(w8 ,w6 ,w1 ,w9 ) \
	SHA512_M(w9 ,w7 ,w2 ,w10) \
	SHA512_M(w10,w8 ,w3 ,w11) \
	SHA512_M(w11,w9 ,w4 ,w12) \
	SHA512_M(w12,w10,w5 ,w13) \
	SHA512_M(w13,w11,w6 ,w14) \
	SHA512_M(w14,w12,w7 ,w15) \
	SHA512_M(w15,w13,w8 ,w0 )
#define SHA512_F(w,k) \
	T1 = h + SHA512_Sigma1(e) + SHA512_Ch(e,f,g) + k + w; \
	T2 = SHA512_Sigma0(a) + SHA512_Maj(a,b,c); \
	h = g; \
	g = f; \
	f = e; \
	e = d + T1; \
	d = c; \
	c = b; \
	b = a; \
	a = T1 + T2;
int sha512_blocks(uint8_t *statebytes,const uint8_t *in,uint64_t inlen){
	uint64_t state[8];
	uint64_t a;
	uint64_t b;
	uint64_t c;
	uint64_t d;
	uint64_t e;
	uint64_t f;
	uint64_t g;
	uint64_t h;
	uint64_t T1;
	uint64_t T2;
	a = sha512_load_bigendian(statebytes +  0); state[0] = a;
	b = sha512_load_bigendian(statebytes +  8); state[1] = b;
	c = sha512_load_bigendian(statebytes + 16); state[2] = c;
	d = sha512_load_bigendian(statebytes + 24); state[3] = d;
	e = sha512_load_bigendian(statebytes + 32); state[4] = e;
	f = sha512_load_bigendian(statebytes + 40); state[5] = f;
	g = sha512_load_bigendian(statebytes + 48); state[6] = g;
	h = sha512_load_bigendian(statebytes + 56); state[7] = h;
	while(inlen >= 128){
		uint64_t w0  = sha512_load_bigendian(in +   0);
		uint64_t w1  = sha512_load_bigendian(in +   8);
		uint64_t w2  = sha512_load_bigendian(in +  16);
		uint64_t w3  = sha512_load_bigendian(in +  24);
		uint64_t w4  = sha512_load_bigendian(in +  32);
		uint64_t w5  = sha512_load_bigendian(in +  40);
		uint64_t w6  = sha512_load_bigendian(in +  48);
		uint64_t w7  = sha512_load_bigendian(in +  56);
		uint64_t w8  = sha512_load_bigendian(in +  64);
		uint64_t w9  = sha512_load_bigendian(in +  72);
		uint64_t w10 = sha512_load_bigendian(in +  80);
		uint64_t w11 = sha512_load_bigendian(in +  88);
		uint64_t w12 = sha512_load_bigendian(in +  96);
		uint64_t w13 = sha512_load_bigendian(in + 104);
		uint64_t w14 = sha512_load_bigendian(in + 112);
		uint64_t w15 = sha512_load_bigendian(in + 120);
		SHA512_F(w0 ,0x428a2f98d728ae22ULL)
		SHA512_F(w1 ,0x7137449123ef65cdULL)
		SHA512_F(w2 ,0xb5c0fbcfec4d3b2fULL)
		SHA512_F(w3 ,0xe9b5dba58189dbbcULL)
		SHA512_F(w4 ,0x3956c25bf348b538ULL)
		SHA512_F(w5 ,0x59f111f1b605d019ULL)
		SHA512_F(w6 ,0x923f82a4af194f9bULL)
		SHA512_F(w7 ,0xab1c5ed5da6d8118ULL)
		SHA512_F(w8 ,0xd807aa98a3030242ULL)
		SHA512_F(w9 ,0x12835b0145706fbeULL)
		SHA512_F(w10,0x243185be4ee4b28cULL)
		SHA512_F(w11,0x550c7dc3d5ffb4e2ULL)
		SHA512_F(w12,0x72be5d74f27b896fULL)
		SHA512_F(w13,0x80deb1fe3b1696b1ULL)
		SHA512_F(w14,0x9bdc06a725c71235ULL)
		SHA512_F(w15,0xc19bf174cf692694ULL)
		SHA512_EXPAND
		SHA512_F(w0 ,0xe49b69c19ef14ad2ULL)
		SHA512_F(w1 ,0xefbe4786384f25e3ULL)
		SHA512_F(w2 ,0x0fc19dc68b8cd5b5ULL)
		SHA512_F(w3 ,0x240ca1cc77ac9c65ULL)
		SHA512_F(w4 ,0x2de92c6f592b0275ULL)
		SHA512_F(w5 ,0x4a7484aa6ea6e483ULL)
		SHA512_F(w6 ,0x5cb0a9dcbd41fbd4ULL)
		SHA512_F(w7 ,0x76f988da831153b5ULL)
		SHA512_F(w8 ,0x983e5152ee66dfabULL)
		SHA512_F(w9 ,0xa831c66d2db43210ULL)
		SHA512_F(w10,0xb00327c898fb213fULL)
		SHA512_F(w11,0xbf597fc7beef0ee4ULL)
		SHA512_F(w12,0xc6e00bf33da88fc2ULL)
		SHA512_F(w13,0xd5a79147930aa725ULL)
		SHA512_F(w14,0x06ca6351e003826fULL)
		SHA512_F(w15,0x142929670a0e6e70ULL)
		SHA512_EXPAND
		SHA512_F(w0 ,0x27b70a8546d22ffcULL)
		SHA512_F(w1 ,0x2e1b21385c26c926ULL)
		SHA512_F(w2 ,0x4d2c6dfc5ac42aedULL)
		SHA512_F(w3 ,0x53380d139d95b3dfULL)
		SHA512_F(w4 ,0x650a73548baf63deULL)
		SHA512_F(w5 ,0x766a0abb3c77b2a8ULL)
		SHA512_F(w6 ,0x81c2c92e47edaee6ULL)
		SHA512_F(w7 ,0x92722c851482353bULL)
		SHA512_F(w8 ,0xa2bfe8a14cf10364ULL)
		SHA512_F(w9 ,0xa81a664bbc423001ULL)
		SHA512_F(w10,0xc24b8b70d0f89791ULL)
		SHA512_F(w11,0xc76c51a30654be30ULL)
		SHA512_F(w12,0xd192e819d6ef5218ULL)
		SHA512_F(w13,0xd69906245565a910ULL)
		SHA512_F(w14,0xf40e35855771202aULL)
		SHA512_F(w15,0x106aa07032bbd1b8ULL)
		SHA512_EXPAND
		SHA512_F(w0 ,0x19a4c116b8d2d0c8ULL)
		SHA512_F(w1 ,0x1e376c085141ab53ULL)
		SHA512_F(w2 ,0x2748774cdf8eeb99ULL)
		SHA512_F(w3 ,0x34b0bcb5e19b48a8ULL)
		SHA512_F(w4 ,0x391c0cb3c5c95a63ULL)
		SHA512_F(w5 ,0x4ed8aa4ae3418acbULL)
		SHA512_F(w6 ,0x5b9cca4f7763e373ULL)
		SHA512_F(w7 ,0x682e6ff3d6b2b8a3ULL)
		SHA512_F(w8 ,0x748f82ee5defb2fcULL)
		SHA512_F(w9 ,0x78a5636f43172f60ULL)
		SHA512_F(w10,0x84c87814a1f0ab72ULL)
		SHA512_F(w11,0x8cc702081a6439ecULL)
		SHA512_F(w12,0x90befffa23631e28ULL)
		SHA512_F(w13,0xa4506cebde82bde9ULL)
		SHA512_F(w14,0xbef9a3f7b2c67915ULL)
		SHA512_F(w15,0xc67178f2e372532bULL)
		SHA512_EXPAND
		SHA512_F(w0 ,0xca273eceea26619cULL)
		SHA512_F(w1 ,0xd186b8c721c0c207ULL)
		SHA512_F(w2 ,0xeada7dd6cde0eb1eULL)
		SHA512_F(w3 ,0xf57d4f7fee6ed178ULL)
		SHA512_F(w4 ,0x06f067aa72176fbaULL)
		SHA512_F(w5 ,0x0a637dc5a2c898a6ULL)
		SHA512_F(w6 ,0x113f9804bef90daeULL)
		SHA512_F(w7 ,0x1b710b35131c471bULL)
		SHA512_F(w8 ,0x28db77f523047d84ULL)
		SHA512_F(w9 ,0x32caab7b40c72493ULL)
		SHA512_F(w10,0x3c9ebe0a15c9bebcULL)
		SHA512_F(w11,0x431d67c49c100d4cULL)
		SHA512_F(w12,0x4cc5d4becb3e42b6ULL)
		SHA512_F(w13,0x597f299cfc657e2aULL)
		SHA512_F(w14,0x5fcb6fab3ad6faecULL)
		SHA512_F(w15,0x6c44198c4a475817ULL)
		a += state[0];
		b += state[1];
		c += state[2];
		d += state[3];
		e += state[4];
		f += state[5];
		g += state[6];
		h += state[7];
		state[0] = a;
		state[1] = b;
		state[2] = c;
		state[3] = d;
		state[4] = e;
		state[5] = f;
		state[6] = g;
		state[7] = h;
		in += 128;
		inlen -= 128;
	}
	sha512_store_bigendian(statebytes +  0,state[0]);
	sha512_store_bigendian(statebytes +  8,state[1]);
	sha512_store_bigendian(statebytes + 16,state[2]);
	sha512_store_bigendian(statebytes + 24,state[3]);
	sha512_store_bigendian(statebytes + 32,state[4]);
	sha512_store_bigendian(statebytes + 40,state[5]);
	sha512_store_bigendian(statebytes + 48,state[6]);
	sha512_store_bigendian(statebytes + 56,state[7]);
	return inlen;
}
const uint8_t sha512_iv[64] = {
	0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
	0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
	0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
	0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
	0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
	0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
	0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
	0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
};
int sha512_hash(uint8_t *out,const uint8_t *in,uint64_t inlen){
	uint8_t h[64];
	uint8_t padded[256];
	uint64_t i;
	uint64_t bytes = inlen;
	for(i = 0; i < 64; ++i)
		h[i] = sha512_iv[i];
	sha512_blocks(h,in,inlen);
	in += inlen;
	inlen &= 127;
	in -= inlen;
	for(i = 0; i < inlen; ++i)
		padded[i] = in[i];
	padded[inlen] = 0x80;
	if(inlen < 112){
		for(i = inlen + 1; i < 119; ++i)
			padded[i] = 0;
		padded[119] = bytes >> 61;
		padded[120] = bytes >> 53;
		padded[121] = bytes >> 45;
		padded[122] = bytes >> 37;
		padded[123] = bytes >> 29;
		padded[124] = bytes >> 21;
		padded[125] = bytes >> 13;
		padded[126] = bytes >> 5;
		padded[127] = bytes << 3;
		sha512_blocks(h,padded,128);
	}else{
		for(i = inlen + 1; i < 247; ++i)
			padded[i] = 0;
		padded[247] = bytes >> 61;
		padded[248] = bytes >> 53;
		padded[249] = bytes >> 45;
		padded[250] = bytes >> 37;
		padded[251] = bytes >> 29;
		padded[252] = bytes >> 21;
		padded[253] = bytes >> 13;
		padded[254] = bytes >> 5;
		padded[255] = bytes << 3;
		sha512_blocks(h,padded,256);
	}
	for(i = 0; i < 64; ++i)
		out[i] = h[i];
  return 0;
}

typedef int32_t fe[10];
void fe_0(fe h){
	h[0] = 0;
	h[1] = 0;
	h[2] = 0;
	h[3] = 0;
	h[4] = 0;
	h[5] = 0;
	h[6] = 0;
	h[7] = 0;
	h[8] = 0;
	h[9] = 0;
}
void fe_1(fe h){
	h[0] = 1;
	h[1] = 0;
	h[2] = 0;
	h[3] = 0;
	h[4] = 0;
	h[5] = 0;
	h[6] = 0;
	h[7] = 0;
	h[8] = 0;
	h[9] = 0;
}
void fe_cmov(fe f,const fe g,uint32_t b){
	int32_t f0 = f[0];
	int32_t f1 = f[1];
	int32_t f2 = f[2];
	int32_t f3 = f[3];
	int32_t f4 = f[4];
	int32_t f5 = f[5];
	int32_t f6 = f[6];
	int32_t f7 = f[7];
	int32_t f8 = f[8];
	int32_t f9 = f[9];
	int32_t g0 = g[0];
	int32_t g1 = g[1];
	int32_t g2 = g[2];
	int32_t g3 = g[3];
	int32_t g4 = g[4];
	int32_t g5 = g[5];
	int32_t g6 = g[6];
	int32_t g7 = g[7];
	int32_t g8 = g[8];
	int32_t g9 = g[9];
	int32_t x0 = f0 ^ g0;
	int32_t x1 = f1 ^ g1;
	int32_t x2 = f2 ^ g2;
	int32_t x3 = f3 ^ g3;
	int32_t x4 = f4 ^ g4;
	int32_t x5 = f5 ^ g5;
	int32_t x6 = f6 ^ g6;
	int32_t x7 = f7 ^ g7;
	int32_t x8 = f8 ^ g8;
	int32_t x9 = f9 ^ g9;
	b = -b;
	x0 &= b;
	x1 &= b;
	x2 &= b;
	x3 &= b;
	x4 &= b;
	x5 &= b;
	x6 &= b;
	x7 &= b;
	x8 &= b;
	x9 &= b;
	f[0] = f0 ^ x0;
	f[1] = f1 ^ x1;
	f[2] = f2 ^ x2;
	f[3] = f3 ^ x3;
	f[4] = f4 ^ x4;
	f[5] = f5 ^ x5;
	f[6] = f6 ^ x6;
	f[7] = f7 ^ x7;
	f[8] = f8 ^ x8;
	f[9] = f9 ^ x9;
}
void fe_copy(fe h,const fe f){
	int32_t f0 = f[0];
	int32_t f1 = f[1];
	int32_t f2 = f[2];
	int32_t f3 = f[3];
	int32_t f4 = f[4];
	int32_t f5 = f[5];
	int32_t f6 = f[6];
	int32_t f7 = f[7];
	int32_t f8 = f[8];
	int32_t f9 = f[9];
	h[0] = f0;
	h[1] = f1;
	h[2] = f2;
	h[3] = f3;
	h[4] = f4;
	h[5] = f5;
	h[6] = f6;
	h[7] = f7;
	h[8] = f8;
	h[9] = f9;
}
void fe_tobytes(uint8_t *s,const fe h){
	int32_t h0 = h[0];
	int32_t h1 = h[1];
	int32_t h2 = h[2];
	int32_t h3 = h[3];
	int32_t h4 = h[4];
	int32_t h5 = h[5];
	int32_t h6 = h[6];
	int32_t h7 = h[7];
	int32_t h8 = h[8];
	int32_t h9 = h[9];
	int32_t q;
	int32_t carry0;
	int32_t carry1;
	int32_t carry2;
	int32_t carry3;
	int32_t carry4;
	int32_t carry5;
	int32_t carry6;
	int32_t carry7;
	int32_t carry8;
	int32_t carry9;
	q = (19 * h9 + (((int32_t) 1) << 24)) >> 25;
	q = (h0 + q) >> 26;
	q = (h1 + q) >> 25;
	q = (h2 + q) >> 26;
	q = (h3 + q) >> 25;
	q = (h4 + q) >> 26;
	q = (h5 + q) >> 25;
	q = (h6 + q) >> 26;
	q = (h7 + q) >> 25;
	q = (h8 + q) >> 26;
	q = (h9 + q) >> 25;
	h0 += 19 * q;
	carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
	carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
	carry2 = h2 >> 26; h3 += carry2; h2 -= carry2 << 26;
	carry3 = h3 >> 25; h4 += carry3; h3 -= carry3 << 25;
	carry4 = h4 >> 26; h5 += carry4; h4 -= carry4 << 26;
	carry5 = h5 >> 25; h6 += carry5; h5 -= carry5 << 25;
	carry6 = h6 >> 26; h7 += carry6; h6 -= carry6 << 26;
	carry7 = h7 >> 25; h8 += carry7; h7 -= carry7 << 25;
	carry8 = h8 >> 26; h9 += carry8; h8 -= carry8 << 26;
	carry9 = h9 >> 25;               h9 -= carry9 << 25;
	s[0] = h0 >> 0;
	s[1] = h0 >> 8;
	s[2] = h0 >> 16;
	s[3] = (h0 >> 24) | (h1 << 2);
	s[4] = h1 >> 6;
	s[5] = h1 >> 14;
	s[6] = (h1 >> 22) | (h2 << 3);
	s[7] = h2 >> 5;
	s[8] = h2 >> 13;
	s[9] = (h2 >> 21) | (h3 << 5);
	s[10] = h3 >> 3;
	s[11] = h3 >> 11;
	s[12] = (h3 >> 19) | (h4 << 6);
	s[13] = h4 >> 2;
	s[14] = h4 >> 10;
	s[15] = h4 >> 18;
	s[16] = h5 >> 0;
	s[17] = h5 >> 8;
	s[18] = h5 >> 16;
	s[19] = (h5 >> 24) | (h6 << 1);
	s[20] = h6 >> 7;
	s[21] = h6 >> 15;
	s[22] = (h6 >> 23) | (h7 << 3);
	s[23] = h7 >> 5;
	s[24] = h7 >> 13;
	s[25] = (h7 >> 21) | (h8 << 4);
	s[26] = h8 >> 4;
	s[27] = h8 >> 12;
	s[28] = (h8 >> 20) | (h9 << 6);
	s[29] = h9 >> 2;
	s[30] = h9 >> 10;
	s[31] = h9 >> 18;
}
void fe_add(fe h,const fe f,const fe g){
	int32_t f0 = f[0];
	int32_t f1 = f[1];
	int32_t f2 = f[2];
	int32_t f3 = f[3];
	int32_t f4 = f[4];
	int32_t f5 = f[5];
	int32_t f6 = f[6];
	int32_t f7 = f[7];
	int32_t f8 = f[8];
	int32_t f9 = f[9];
	int32_t g0 = g[0];
	int32_t g1 = g[1];
	int32_t g2 = g[2];
	int32_t g3 = g[3];
	int32_t g4 = g[4];
	int32_t g5 = g[5];
	int32_t g6 = g[6];
	int32_t g7 = g[7];
	int32_t g8 = g[8];
	int32_t g9 = g[9];
	int32_t h0 = f0 + g0;
	int32_t h1 = f1 + g1;
	int32_t h2 = f2 + g2;
	int32_t h3 = f3 + g3;
	int32_t h4 = f4 + g4;
	int32_t h5 = f5 + g5;
	int32_t h6 = f6 + g6;
	int32_t h7 = f7 + g7;
	int32_t h8 = f8 + g8;
	int32_t h9 = f9 + g9;
	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
	h[5] = h5;
	h[6] = h6;
	h[7] = h7;
	h[8] = h8;
	h[9] = h9;
}
void fe_sub(fe h,const fe f,const fe g){
	int32_t f0 = f[0];
	int32_t f1 = f[1];
	int32_t f2 = f[2];
	int32_t f3 = f[3];
	int32_t f4 = f[4];
	int32_t f5 = f[5];
	int32_t f6 = f[6];
	int32_t f7 = f[7];
	int32_t f8 = f[8];
	int32_t f9 = f[9];
	int32_t g0 = g[0];
	int32_t g1 = g[1];
	int32_t g2 = g[2];
	int32_t g3 = g[3];
	int32_t g4 = g[4];
	int32_t g5 = g[5];
	int32_t g6 = g[6];
	int32_t g7 = g[7];
	int32_t g8 = g[8];
	int32_t g9 = g[9];
	int32_t h0 = f0 - g0;
	int32_t h1 = f1 - g1;
	int32_t h2 = f2 - g2;
	int32_t h3 = f3 - g3;
	int32_t h4 = f4 - g4;
	int32_t h5 = f5 - g5;
	int32_t h6 = f6 - g6;
	int32_t h7 = f7 - g7;
	int32_t h8 = f8 - g8;
	int32_t h9 = f9 - g9;
	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
	h[5] = h5;
	h[6] = h6;
	h[7] = h7;
	h[8] = h8;
	h[9] = h9;
}
void fe_neg(fe h,const fe f){
	int32_t f0 = f[0];
	int32_t f1 = f[1];
	int32_t f2 = f[2];
	int32_t f3 = f[3];
	int32_t f4 = f[4];
	int32_t f5 = f[5];
	int32_t f6 = f[6];
	int32_t f7 = f[7];
	int32_t f8 = f[8];
	int32_t f9 = f[9];
	int32_t h0 = -f0;
	int32_t h1 = -f1;
	int32_t h2 = -f2;
	int32_t h3 = -f3;
	int32_t h4 = -f4;
	int32_t h5 = -f5;
	int32_t h6 = -f6;
	int32_t h7 = -f7;
	int32_t h8 = -f8;
	int32_t h9 = -f9;
	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
	h[5] = h5;
	h[6] = h6;
	h[7] = h7;
	h[8] = h8;
	h[9] = h9;
}
int fe_isnegative(const fe f){
	uint8_t s[32];
	fe_tobytes(s,f);
	return s[0] & 1;
}
void fe_mul(fe h,const fe f,const fe g){
	int32_t f0 = f[0];
	int32_t f1 = f[1];
	int32_t f2 = f[2];
	int32_t f3 = f[3];
	int32_t f4 = f[4];
	int32_t f5 = f[5];
	int32_t f6 = f[6];
	int32_t f7 = f[7];
	int32_t f8 = f[8];
	int32_t f9 = f[9];
	int32_t g0 = g[0];
	int32_t g1 = g[1];
	int32_t g2 = g[2];
	int32_t g3 = g[3];
	int32_t g4 = g[4];
	int32_t g5 = g[5];
	int32_t g6 = g[6];
	int32_t g7 = g[7];
	int32_t g8 = g[8];
	int32_t g9 = g[9];
	int32_t g1_19 = 19 * g1; 
	int32_t g2_19 = 19 * g2;
	int32_t g3_19 = 19 * g3;
	int32_t g4_19 = 19 * g4;
	int32_t g5_19 = 19 * g5;
	int32_t g6_19 = 19 * g6;
	int32_t g7_19 = 19 * g7;
	int32_t g8_19 = 19 * g8;
	int32_t g9_19 = 19 * g9;
	int32_t f1_2 = 2 * f1;
	int32_t f3_2 = 2 * f3;
	int32_t f5_2 = 2 * f5;
	int32_t f7_2 = 2 * f7;
	int32_t f9_2 = 2 * f9;
	int64_t f0g0    = f0   * (int64_t) g0;
	int64_t f0g1    = f0   * (int64_t) g1;
	int64_t f0g2    = f0   * (int64_t) g2;
	int64_t f0g3    = f0   * (int64_t) g3;
	int64_t f0g4    = f0   * (int64_t) g4;
	int64_t f0g5    = f0   * (int64_t) g5;
	int64_t f0g6    = f0   * (int64_t) g6;
	int64_t f0g7    = f0   * (int64_t) g7;
	int64_t f0g8    = f0   * (int64_t) g8;
	int64_t f0g9    = f0   * (int64_t) g9;
	int64_t f1g0    = f1   * (int64_t) g0;
	int64_t f1g1_2  = f1_2 * (int64_t) g1;
	int64_t f1g2    = f1   * (int64_t) g2;
	int64_t f1g3_2  = f1_2 * (int64_t) g3;
	int64_t f1g4    = f1   * (int64_t) g4;
	int64_t f1g5_2  = f1_2 * (int64_t) g5;
	int64_t f1g6    = f1   * (int64_t) g6;
	int64_t f1g7_2  = f1_2 * (int64_t) g7;
	int64_t f1g8    = f1   * (int64_t) g8;
	int64_t f1g9_38 = f1_2 * (int64_t) g9_19;
	int64_t f2g0    = f2   * (int64_t) g0;
	int64_t f2g1    = f2   * (int64_t) g1;
	int64_t f2g2    = f2   * (int64_t) g2;
	int64_t f2g3    = f2   * (int64_t) g3;
	int64_t f2g4    = f2   * (int64_t) g4;
	int64_t f2g5    = f2   * (int64_t) g5;
	int64_t f2g6    = f2   * (int64_t) g6;
	int64_t f2g7    = f2   * (int64_t) g7;
	int64_t f2g8_19 = f2   * (int64_t) g8_19;
	int64_t f2g9_19 = f2   * (int64_t) g9_19;
	int64_t f3g0    = f3   * (int64_t) g0;
	int64_t f3g1_2  = f3_2 * (int64_t) g1;
	int64_t f3g2    = f3   * (int64_t) g2;
	int64_t f3g3_2  = f3_2 * (int64_t) g3;
	int64_t f3g4    = f3   * (int64_t) g4;
	int64_t f3g5_2  = f3_2 * (int64_t) g5;
	int64_t f3g6    = f3   * (int64_t) g6;
	int64_t f3g7_38 = f3_2 * (int64_t) g7_19;
	int64_t f3g8_19 = f3   * (int64_t) g8_19;
	int64_t f3g9_38 = f3_2 * (int64_t) g9_19;
	int64_t f4g0    = f4   * (int64_t) g0;
	int64_t f4g1    = f4   * (int64_t) g1;
	int64_t f4g2    = f4   * (int64_t) g2;
	int64_t f4g3    = f4   * (int64_t) g3;
	int64_t f4g4    = f4   * (int64_t) g4;
	int64_t f4g5    = f4   * (int64_t) g5;
	int64_t f4g6_19 = f4   * (int64_t) g6_19;
	int64_t f4g7_19 = f4   * (int64_t) g7_19;
	int64_t f4g8_19 = f4   * (int64_t) g8_19;
	int64_t f4g9_19 = f4   * (int64_t) g9_19;
	int64_t f5g0    = f5   * (int64_t) g0;
	int64_t f5g1_2  = f5_2 * (int64_t) g1;
	int64_t f5g2    = f5   * (int64_t) g2;
	int64_t f5g3_2  = f5_2 * (int64_t) g3;
	int64_t f5g4    = f5   * (int64_t) g4;
	int64_t f5g5_38 = f5_2 * (int64_t) g5_19;
	int64_t f5g6_19 = f5   * (int64_t) g6_19;
	int64_t f5g7_38 = f5_2 * (int64_t) g7_19;
	int64_t f5g8_19 = f5   * (int64_t) g8_19;
	int64_t f5g9_38 = f5_2 * (int64_t) g9_19;
	int64_t f6g0    = f6   * (int64_t) g0;
	int64_t f6g1    = f6   * (int64_t) g1;
	int64_t f6g2    = f6   * (int64_t) g2;
	int64_t f6g3    = f6   * (int64_t) g3;
	int64_t f6g4_19 = f6   * (int64_t) g4_19;
	int64_t f6g5_19 = f6   * (int64_t) g5_19;
	int64_t f6g6_19 = f6   * (int64_t) g6_19;
	int64_t f6g7_19 = f6   * (int64_t) g7_19;
	int64_t f6g8_19 = f6   * (int64_t) g8_19;
	int64_t f6g9_19 = f6   * (int64_t) g9_19;
	int64_t f7g0    = f7   * (int64_t) g0;
	int64_t f7g1_2  = f7_2 * (int64_t) g1;
	int64_t f7g2    = f7   * (int64_t) g2;
	int64_t f7g3_38 = f7_2 * (int64_t) g3_19;
	int64_t f7g4_19 = f7   * (int64_t) g4_19;
	int64_t f7g5_38 = f7_2 * (int64_t) g5_19;
	int64_t f7g6_19 = f7   * (int64_t) g6_19;
	int64_t f7g7_38 = f7_2 * (int64_t) g7_19;
	int64_t f7g8_19 = f7   * (int64_t) g8_19;
	int64_t f7g9_38 = f7_2 * (int64_t) g9_19;
	int64_t f8g0    = f8   * (int64_t) g0;
	int64_t f8g1    = f8   * (int64_t) g1;
	int64_t f8g2_19 = f8   * (int64_t) g2_19;
	int64_t f8g3_19 = f8   * (int64_t) g3_19;
	int64_t f8g4_19 = f8   * (int64_t) g4_19;
	int64_t f8g5_19 = f8   * (int64_t) g5_19;
	int64_t f8g6_19 = f8   * (int64_t) g6_19;
	int64_t f8g7_19 = f8   * (int64_t) g7_19;
	int64_t f8g8_19 = f8   * (int64_t) g8_19;
	int64_t f8g9_19 = f8   * (int64_t) g9_19;
	int64_t f9g0    = f9   * (int64_t) g0;
	int64_t f9g1_38 = f9_2 * (int64_t) g1_19;
	int64_t f9g2_19 = f9   * (int64_t) g2_19;
	int64_t f9g3_38 = f9_2 * (int64_t) g3_19;
	int64_t f9g4_19 = f9   * (int64_t) g4_19;
	int64_t f9g5_38 = f9_2 * (int64_t) g5_19;
	int64_t f9g6_19 = f9   * (int64_t) g6_19;
	int64_t f9g7_38 = f9_2 * (int64_t) g7_19;
	int64_t f9g8_19 = f9   * (int64_t) g8_19;
	int64_t f9g9_38 = f9_2 * (int64_t) g9_19;
	int64_t h0 = f0g0+f1g9_38+f2g8_19+f3g7_38+f4g6_19+f5g5_38+f6g4_19+f7g3_38+f8g2_19+f9g1_38;
	int64_t h1 = f0g1+f1g0   +f2g9_19+f3g8_19+f4g7_19+f5g6_19+f6g5_19+f7g4_19+f8g3_19+f9g2_19;
	int64_t h2 = f0g2+f1g1_2 +f2g0   +f3g9_38+f4g8_19+f5g7_38+f6g6_19+f7g5_38+f8g4_19+f9g3_38;
	int64_t h3 = f0g3+f1g2   +f2g1   +f3g0   +f4g9_19+f5g8_19+f6g7_19+f7g6_19+f8g5_19+f9g4_19;
	int64_t h4 = f0g4+f1g3_2 +f2g2   +f3g1_2 +f4g0   +f5g9_38+f6g8_19+f7g7_38+f8g6_19+f9g5_38;
	int64_t h5 = f0g5+f1g4   +f2g3   +f3g2   +f4g1   +f5g0   +f6g9_19+f7g8_19+f8g7_19+f9g6_19;
	int64_t h6 = f0g6+f1g5_2 +f2g4   +f3g3_2 +f4g2   +f5g1_2 +f6g0   +f7g9_38+f8g8_19+f9g7_38;
	int64_t h7 = f0g7+f1g6   +f2g5   +f3g4   +f4g3   +f5g2   +f6g1   +f7g0   +f8g9_19+f9g8_19;
	int64_t h8 = f0g8+f1g7_2 +f2g6   +f3g5_2 +f4g4   +f5g3_2 +f6g2   +f7g1_2 +f8g0   +f9g9_38;
	int64_t h9 = f0g9+f1g8   +f2g7   +f3g6   +f4g5   +f5g4   +f6g3   +f7g2   +f8g1   +f9g0   ;
	int64_t carry0;
	int64_t carry1;
	int64_t carry2;
	int64_t carry3;
	int64_t carry4;
	int64_t carry5;
	int64_t carry6;
	int64_t carry7;
	int64_t carry8;
	int64_t carry9;
	carry0 = (h0 + (int64_t) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
	carry4 = (h4 + (int64_t) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
	carry1 = (h1 + (int64_t) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
	carry5 = (h5 + (int64_t) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
	carry2 = (h2 + (int64_t) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
	carry6 = (h6 + (int64_t) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
	carry3 = (h3 + (int64_t) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
	carry7 = (h7 + (int64_t) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
	carry4 = (h4 + (int64_t) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
	carry8 = (h8 + (int64_t) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
	carry9 = (h9 + (int64_t) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
	carry0 = (h0 + (int64_t) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
	h[5] = h5;
	h[6] = h6;
	h[7] = h7;
	h[8] = h8;
	h[9] = h9;
}
void fe_sq(fe h,const fe f){
	int32_t f0 = f[0];
	int32_t f1 = f[1];
	int32_t f2 = f[2];
	int32_t f3 = f[3];
	int32_t f4 = f[4];
	int32_t f5 = f[5];
	int32_t f6 = f[6];
	int32_t f7 = f[7];
	int32_t f8 = f[8];
	int32_t f9 = f[9];
	int32_t f0_2 = 2 * f0;
	int32_t f1_2 = 2 * f1;
	int32_t f2_2 = 2 * f2;
	int32_t f3_2 = 2 * f3;
	int32_t f4_2 = 2 * f4;
	int32_t f5_2 = 2 * f5;
	int32_t f6_2 = 2 * f6;
	int32_t f7_2 = 2 * f7;
	int32_t f5_38 = 38 * f5;
	int32_t f6_19 = 19 * f6;
	int32_t f7_38 = 38 * f7;
	int32_t f8_19 = 19 * f8;
	int32_t f9_38 = 38 * f9;
	int64_t f0f0    = f0   * (int64_t) f0;
	int64_t f0f1_2  = f0_2 * (int64_t) f1;
	int64_t f0f2_2  = f0_2 * (int64_t) f2;
	int64_t f0f3_2  = f0_2 * (int64_t) f3;
	int64_t f0f4_2  = f0_2 * (int64_t) f4;
	int64_t f0f5_2  = f0_2 * (int64_t) f5;
	int64_t f0f6_2  = f0_2 * (int64_t) f6;
	int64_t f0f7_2  = f0_2 * (int64_t) f7;
	int64_t f0f8_2  = f0_2 * (int64_t) f8;
	int64_t f0f9_2  = f0_2 * (int64_t) f9;
	int64_t f1f1_2  = f1_2 * (int64_t) f1;
	int64_t f1f2_2  = f1_2 * (int64_t) f2;
	int64_t f1f3_4  = f1_2 * (int64_t) f3_2;
	int64_t f1f4_2  = f1_2 * (int64_t) f4;
	int64_t f1f5_4  = f1_2 * (int64_t) f5_2;
	int64_t f1f6_2  = f1_2 * (int64_t) f6;
	int64_t f1f7_4  = f1_2 * (int64_t) f7_2;
	int64_t f1f8_2  = f1_2 * (int64_t) f8;
	int64_t f1f9_76 = f1_2 * (int64_t) f9_38;
	int64_t f2f2    = f2   * (int64_t) f2;
	int64_t f2f3_2  = f2_2 * (int64_t) f3;
	int64_t f2f4_2  = f2_2 * (int64_t) f4;
	int64_t f2f5_2  = f2_2 * (int64_t) f5;
	int64_t f2f6_2  = f2_2 * (int64_t) f6;
	int64_t f2f7_2  = f2_2 * (int64_t) f7;
	int64_t f2f8_38 = f2_2 * (int64_t) f8_19;
	int64_t f2f9_38 = f2   * (int64_t) f9_38;
	int64_t f3f3_2  = f3_2 * (int64_t) f3;
	int64_t f3f4_2  = f3_2 * (int64_t) f4;
	int64_t f3f5_4  = f3_2 * (int64_t) f5_2;
	int64_t f3f6_2  = f3_2 * (int64_t) f6;
	int64_t f3f7_76 = f3_2 * (int64_t) f7_38;
	int64_t f3f8_38 = f3_2 * (int64_t) f8_19;
	int64_t f3f9_76 = f3_2 * (int64_t) f9_38;
	int64_t f4f4    = f4   * (int64_t) f4;
	int64_t f4f5_2  = f4_2 * (int64_t) f5;
	int64_t f4f6_38 = f4_2 * (int64_t) f6_19;
	int64_t f4f7_38 = f4   * (int64_t) f7_38;
	int64_t f4f8_38 = f4_2 * (int64_t) f8_19;
	int64_t f4f9_38 = f4   * (int64_t) f9_38;
	int64_t f5f5_38 = f5   * (int64_t) f5_38;
	int64_t f5f6_38 = f5_2 * (int64_t) f6_19;
	int64_t f5f7_76 = f5_2 * (int64_t) f7_38;
	int64_t f5f8_38 = f5_2 * (int64_t) f8_19;
	int64_t f5f9_76 = f5_2 * (int64_t) f9_38;
	int64_t f6f6_19 = f6   * (int64_t) f6_19;
	int64_t f6f7_38 = f6   * (int64_t) f7_38;
	int64_t f6f8_38 = f6_2 * (int64_t) f8_19;
	int64_t f6f9_38 = f6   * (int64_t) f9_38;
	int64_t f7f7_38 = f7   * (int64_t) f7_38;
	int64_t f7f8_38 = f7_2 * (int64_t) f8_19;
	int64_t f7f9_76 = f7_2 * (int64_t) f9_38;
	int64_t f8f8_19 = f8   * (int64_t) f8_19;
	int64_t f8f9_38 = f8   * (int64_t) f9_38;
	int64_t f9f9_38 = f9   * (int64_t) f9_38;
	int64_t h0 = f0f0  +f1f9_76+f2f8_38+f3f7_76+f4f6_38+f5f5_38;
	int64_t h1 = f0f1_2+f2f9_38+f3f8_38+f4f7_38+f5f6_38;
	int64_t h2 = f0f2_2+f1f1_2 +f3f9_76+f4f8_38+f5f7_76+f6f6_19;
	int64_t h3 = f0f3_2+f1f2_2 +f4f9_38+f5f8_38+f6f7_38;
	int64_t h4 = f0f4_2+f1f3_4 +f2f2   +f5f9_76+f6f8_38+f7f7_38;
	int64_t h5 = f0f5_2+f1f4_2 +f2f3_2 +f6f9_38+f7f8_38;
	int64_t h6 = f0f6_2+f1f5_4 +f2f4_2 +f3f3_2 +f7f9_76+f8f8_19;
	int64_t h7 = f0f7_2+f1f6_2 +f2f5_2 +f3f4_2 +f8f9_38;
	int64_t h8 = f0f8_2+f1f7_4 +f2f6_2 +f3f5_4 +f4f4   +f9f9_38;
	int64_t h9 = f0f9_2+f1f8_2 +f2f7_2 +f3f6_2 +f4f5_2;
	int64_t carry0;
	int64_t carry1;
	int64_t carry2;
	int64_t carry3;
	int64_t carry4;
	int64_t carry5;
	int64_t carry6;
	int64_t carry7;
	int64_t carry8;
	int64_t carry9;
	carry0 = (h0 + (int64_t) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
	carry4 = (h4 + (int64_t) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
	carry1 = (h1 + (int64_t) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
	carry5 = (h5 + (int64_t) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
	carry2 = (h2 + (int64_t) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
	carry6 = (h6 + (int64_t) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
	carry3 = (h3 + (int64_t) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
	carry7 = (h7 + (int64_t) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
	carry4 = (h4 + (int64_t) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
	carry8 = (h8 + (int64_t) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
	carry9 = (h9 + (int64_t) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
	carry0 = (h0 + (int64_t) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
	h[5] = h5;
	h[6] = h6;
	h[7] = h7;
	h[8] = h8;
	h[9] = h9;
}
void fe_sq2(fe h,const fe f){
	int32_t f0 = f[0];
	int32_t f1 = f[1];
	int32_t f2 = f[2];
	int32_t f3 = f[3];
	int32_t f4 = f[4];
	int32_t f5 = f[5];
	int32_t f6 = f[6];
	int32_t f7 = f[7];
	int32_t f8 = f[8];
	int32_t f9 = f[9];
	int32_t f0_2 = 2 * f0;
	int32_t f1_2 = 2 * f1;
	int32_t f2_2 = 2 * f2;
	int32_t f3_2 = 2 * f3;
	int32_t f4_2 = 2 * f4;
	int32_t f5_2 = 2 * f5;
	int32_t f6_2 = 2 * f6;
	int32_t f7_2 = 2 * f7;
	int32_t f5_38 = 38 * f5; 
	int32_t f6_19 = 19 * f6; 
	int32_t f7_38 = 38 * f7; 
	int32_t f8_19 = 19 * f8; 
	int32_t f9_38 = 38 * f9; 
	int64_t f0f0    = f0   * (int64_t) f0;
	int64_t f0f1_2  = f0_2 * (int64_t) f1;
	int64_t f0f2_2  = f0_2 * (int64_t) f2;
	int64_t f0f3_2  = f0_2 * (int64_t) f3;
	int64_t f0f4_2  = f0_2 * (int64_t) f4;
	int64_t f0f5_2  = f0_2 * (int64_t) f5;
	int64_t f0f6_2  = f0_2 * (int64_t) f6;
	int64_t f0f7_2  = f0_2 * (int64_t) f7;
	int64_t f0f8_2  = f0_2 * (int64_t) f8;
	int64_t f0f9_2  = f0_2 * (int64_t) f9;
	int64_t f1f1_2  = f1_2 * (int64_t) f1;
	int64_t f1f2_2  = f1_2 * (int64_t) f2;
	int64_t f1f3_4  = f1_2 * (int64_t) f3_2;
	int64_t f1f4_2  = f1_2 * (int64_t) f4;
	int64_t f1f5_4  = f1_2 * (int64_t) f5_2;
	int64_t f1f6_2  = f1_2 * (int64_t) f6;
	int64_t f1f7_4  = f1_2 * (int64_t) f7_2;
	int64_t f1f8_2  = f1_2 * (int64_t) f8;
	int64_t f1f9_76 = f1_2 * (int64_t) f9_38;
	int64_t f2f2    = f2   * (int64_t) f2;
	int64_t f2f3_2  = f2_2 * (int64_t) f3;
	int64_t f2f4_2  = f2_2 * (int64_t) f4;
	int64_t f2f5_2  = f2_2 * (int64_t) f5;
	int64_t f2f6_2  = f2_2 * (int64_t) f6;
	int64_t f2f7_2  = f2_2 * (int64_t) f7;
	int64_t f2f8_38 = f2_2 * (int64_t) f8_19;
	int64_t f2f9_38 = f2   * (int64_t) f9_38;
	int64_t f3f3_2  = f3_2 * (int64_t) f3;
	int64_t f3f4_2  = f3_2 * (int64_t) f4;
	int64_t f3f5_4  = f3_2 * (int64_t) f5_2;
	int64_t f3f6_2  = f3_2 * (int64_t) f6;
	int64_t f3f7_76 = f3_2 * (int64_t) f7_38;
	int64_t f3f8_38 = f3_2 * (int64_t) f8_19;
	int64_t f3f9_76 = f3_2 * (int64_t) f9_38;
	int64_t f4f4    = f4   * (int64_t) f4;
	int64_t f4f5_2  = f4_2 * (int64_t) f5;
	int64_t f4f6_38 = f4_2 * (int64_t) f6_19;
	int64_t f4f7_38 = f4   * (int64_t) f7_38;
	int64_t f4f8_38 = f4_2 * (int64_t) f8_19;
	int64_t f4f9_38 = f4   * (int64_t) f9_38;
	int64_t f5f5_38 = f5   * (int64_t) f5_38;
	int64_t f5f6_38 = f5_2 * (int64_t) f6_19;
	int64_t f5f7_76 = f5_2 * (int64_t) f7_38;
	int64_t f5f8_38 = f5_2 * (int64_t) f8_19;
	int64_t f5f9_76 = f5_2 * (int64_t) f9_38;
	int64_t f6f6_19 = f6   * (int64_t) f6_19;
	int64_t f6f7_38 = f6   * (int64_t) f7_38;
	int64_t f6f8_38 = f6_2 * (int64_t) f8_19;
	int64_t f6f9_38 = f6   * (int64_t) f9_38;
	int64_t f7f7_38 = f7   * (int64_t) f7_38;
	int64_t f7f8_38 = f7_2 * (int64_t) f8_19;
	int64_t f7f9_76 = f7_2 * (int64_t) f9_38;
	int64_t f8f8_19 = f8   * (int64_t) f8_19;
	int64_t f8f9_38 = f8   * (int64_t) f9_38;
	int64_t f9f9_38 = f9   * (int64_t) f9_38;
	int64_t h0 = f0f0  +f1f9_76+f2f8_38+f3f7_76+f4f6_38+f5f5_38;
	int64_t h1 = f0f1_2+f2f9_38+f3f8_38+f4f7_38+f5f6_38;
	int64_t h2 = f0f2_2+f1f1_2 +f3f9_76+f4f8_38+f5f7_76+f6f6_19;
	int64_t h3 = f0f3_2+f1f2_2 +f4f9_38+f5f8_38+f6f7_38;
	int64_t h4 = f0f4_2+f1f3_4 +f2f2   +f5f9_76+f6f8_38+f7f7_38;
	int64_t h5 = f0f5_2+f1f4_2 +f2f3_2 +f6f9_38+f7f8_38;
	int64_t h6 = f0f6_2+f1f5_4 +f2f4_2 +f3f3_2 +f7f9_76+f8f8_19;
	int64_t h7 = f0f7_2+f1f6_2 +f2f5_2 +f3f4_2 +f8f9_38;
	int64_t h8 = f0f8_2+f1f7_4 +f2f6_2 +f3f5_4 +f4f4   +f9f9_38;
	int64_t h9 = f0f9_2+f1f8_2 +f2f7_2 +f3f6_2 +f4f5_2;
	int64_t carry0;
	int64_t carry1;
	int64_t carry2;
	int64_t carry3;
	int64_t carry4;
	int64_t carry5;
	int64_t carry6;
	int64_t carry7;
	int64_t carry8;
	int64_t carry9;
	h0 += h0;
	h1 += h1;
	h2 += h2;
	h3 += h3;
	h4 += h4;
	h5 += h5;
	h6 += h6;
	h7 += h7;
	h8 += h8;
	h9 += h9;
	carry0 = (h0 + (int64_t) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
	carry4 = (h4 + (int64_t) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
	carry1 = (h1 + (int64_t) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
	carry5 = (h5 + (int64_t) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
	carry2 = (h2 + (int64_t) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
	carry6 = (h6 + (int64_t) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
	carry3 = (h3 + (int64_t) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
	carry7 = (h7 + (int64_t) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
	carry4 = (h4 + (int64_t) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
	carry8 = (h8 + (int64_t) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
	carry9 = (h9 + (int64_t) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
	carry0 = (h0 + (int64_t) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
	h[5] = h5;
	h[6] = h6;
	h[7] = h7;
	h[8] = h8;
	h[9] = h9;
}
void fe_invert(fe out,const fe z){
	fe t0;
	fe t1;
	fe t2;
	fe t3;
	int i;
	fe_sq(t0,z);
	for(i = 1; i < 1; ++i)
		fe_sq(t0,t0);
	fe_sq(t1,t0);
	for(i = 1;i < 2; ++i)
		fe_sq(t1,t1);
	fe_mul(t1,z,t1);
	fe_mul(t0,t0,t1);
	fe_sq(t2,t0);
	for(i = 1; i < 1; ++i)
		fe_sq(t2,t2);
	fe_mul(t1,t1,t2);
	fe_sq(t2,t1);
	for(i = 1; i < 5; ++i)
		fe_sq(t2,t2);
	fe_mul(t1,t2,t1);
	fe_sq(t2,t1);
	for(i = 1; i < 10; ++i)
		fe_sq(t2,t2);
	fe_mul(t2,t2,t1);
	fe_sq(t3,t2);
	for(i = 1; i < 20; ++i)
		fe_sq(t3,t3);
	fe_mul(t2,t3,t2);
	fe_sq(t2,t2);
	for(i = 1; i < 10; ++i)
		fe_sq(t2,t2);
	fe_mul(t1,t2,t1);
	fe_sq(t2,t1);
	for(i = 1; i < 50; ++i)
		fe_sq(t2,t2);
	fe_mul(t2,t2,t1);
	fe_sq(t3,t2);
	for(i = 1; i < 100; ++i)
		fe_sq(t3,t3);
	fe_mul(t2,t3,t2);
	fe_sq(t2,t2);
	for(i = 1; i < 50; ++i)
		fe_sq(t2,t2);
	fe_mul(t1,t2,t1);
	fe_sq(t1,t1);
	for(i = 1; i < 5; ++i)
		fe_sq(t1,t1);
	fe_mul(out,t1,t0);
	return;
}

typedef struct { fe X; fe Y; fe Z; fe T; } ge_p3;
typedef struct { fe X; fe Y; fe Z; fe T; } ge_p1p1;
typedef struct { fe X; fe Y; fe Z; } ge_p2;
typedef struct { fe yplusx; fe yminusx; fe xy2d; } ge_precomp;
void ge_madd(ge_p1p1 *r,const ge_p3 *p,const ge_precomp *q){
	fe t0;
	fe_add(r->X,p->Y,p->X);
	fe_sub(r->Y,p->Y,p->X);
	fe_mul(r->Z,r->X,q->yplusx);
	fe_mul(r->Y,r->Y,q->yminusx);
	fe_mul(r->T,q->xy2d,p->T);
	fe_add(t0,p->Z,p->Z);
	fe_sub(r->X,r->Z,r->Y);
	fe_add(r->Y,r->Z,r->Y);
	fe_add(r->Z,t0,r->T);
	fe_sub(r->T,t0,r->T);
}
void ge_p3_0(ge_p3 *h){
	fe_0(h->X);
	fe_1(h->Y);
	fe_1(h->Z);
	fe_0(h->T);
}
void ge_p3_to_p2(ge_p2 *r,const ge_p3 *p){
	fe_copy(r->X,p->X);
	fe_copy(r->Y,p->Y);
	fe_copy(r->Z,p->Z);
}
void ge_p2_dbl(ge_p1p1 *r,const ge_p2 *p){
	fe t0;
	fe_sq(r->X,p->X);
	fe_sq(r->Z,p->Y);
	fe_sq2(r->T,p->Z);
	fe_add(r->Y,p->X,p->Y);
	fe_sq(t0,r->Y);
	fe_add(r->Y,r->Z,r->X);
	fe_sub(r->Z,r->Z,r->X);
	fe_sub(r->X,t0,r->Y);
	fe_sub(r->T,r->T,r->Z);
}
void ge_p3_dbl(ge_p1p1 *r,const ge_p3 *p){
	ge_p2 q;
	ge_p3_to_p2(&q,p);
	ge_p2_dbl(r,&q);
}
void ge_p3_tobytes(uint8_t *s,const ge_p3 *h){
	fe recip;
	fe x;
	fe y;
	fe_invert(recip,h->Z);
	fe_mul(x,h->X,recip);
	fe_mul(y,h->Y,recip);
	fe_tobytes(s,y);
	s[31] ^= fe_isnegative(x) << 7;
}
void ge_precomp_0(ge_precomp *h){
	fe_1(h->yplusx);
	fe_1(h->yminusx);
	fe_0(h->xy2d);
}
void ge_p1p1_to_p2(ge_p2 *r,const ge_p1p1 *p){
	fe_mul(r->X,p->X,p->T);
	fe_mul(r->Y,p->Y,p->Z);
	fe_mul(r->Z,p->Z,p->T);
}
void ge_p1p1_to_p3(ge_p3 *r,const ge_p1p1 *p){
	fe_mul(r->X,p->X,p->T);
	fe_mul(r->Y,p->Y,p->Z);
	fe_mul(r->Z,p->Z,p->T);
	fe_mul(r->T,p->X,p->Y);
}

void cmov(ge_precomp *t,ge_precomp *u,uint8_t b){
	fe_cmov(t->yplusx,u->yplusx,b);
	fe_cmov(t->yminusx,u->yminusx,b);
	fe_cmov(t->xy2d,u->xy2d,b);
}
static ge_precomp base[32][8] = {
	#include "base.h"
};

uint8_t equal(int8_t b,int8_t c){
	uint8_t ub = b;
	uint8_t uc = c;
	uint8_t x = ub ^ uc;
	uint32_t y = x;
	y -= 1;
	y >>= 31;
	return y;
}
uint8_t negative(int8_t b){
	uint64_t x = b;
	x >>= 63;
	return x;
}
void select(ge_precomp *t,int pos,int8_t b){
	ge_precomp minust;
	uint8_t bnegative = negative(b);
	uint8_t babs = b - (((-bnegative) & b) << 1);
	ge_precomp_0(t);
	cmov(t,&base[pos][0],equal(babs,1));
	cmov(t,&base[pos][1],equal(babs,2));
	cmov(t,&base[pos][2],equal(babs,3));
	cmov(t,&base[pos][3],equal(babs,4));
	cmov(t,&base[pos][4],equal(babs,5));
	cmov(t,&base[pos][5],equal(babs,6));
	cmov(t,&base[pos][6],equal(babs,7));
	cmov(t,&base[pos][7],equal(babs,8));
	fe_copy(minust.yplusx,t->yminusx);
	fe_copy(minust.yminusx,t->yplusx);
	fe_neg(minust.xy2d,t->xy2d);
	cmov(t,&minust,bnegative);
}
void ge_scalarmult_base(ge_p3 *h,const uint8_t *a){
	int8_t e[64];
	int8_t carry;
	ge_p1p1 r;
	ge_p2 s;
	ge_precomp t;
	int i;
	for (i = 0;i < 32;++i) {
		e[2 * i + 0] = (a[i] >> 0) & 15;
		e[2 * i + 1] = (a[i] >> 4) & 15;
	}
	carry = 0;
	for (i = 0;i < 63;++i) {
		e[i] += carry;
		carry = e[i] + 8;
		carry >>= 4;
		e[i] -= carry << 4;
	}
	e[63] += carry;
	ge_p3_0(h);
	for (i = 1;i < 64;i += 2) {
		select(&t,i / 2,e[i]);
		ge_madd(&r,h,&t); ge_p1p1_to_p3(h,&r);
	}
	ge_p3_dbl(&r,h);  ge_p1p1_to_p2(&s,&r);
	ge_p2_dbl(&r,&s); ge_p1p1_to_p2(&s,&r);
	ge_p2_dbl(&r,&s); ge_p1p1_to_p2(&s,&r);
	ge_p2_dbl(&r,&s); ge_p1p1_to_p3(h,&r);
	for (i = 0;i < 64;i += 2) {
		select(&t,i / 2,e[i]);
		ge_madd(&r,h,&t); ge_p1p1_to_p3(h,&r);
	}
}

void ed25519_pubkey(uint8_t *sk, uint8_t *pk){
	uint8_t az[64];
	ge_p3 A;
	sha512_hash(az,sk,32);
	az[0] &= 248;
	az[31] &= 63;
	az[31] |= 64;
	ge_scalarmult_base(&A,az);
	ge_p3_tobytes(pk,&A);
}

void ed25519_pubkey2(uint8_t *az, uint8_t *pk){
	ge_p3 A;
	//sha512_hash(az,sk,32);
	//az[0] &= 248;
	//az[31] &= 63;
	//az[31] |= 64;
	ge_scalarmult_base(&A,az);
	ge_p3_tobytes(pk,&A);
}

