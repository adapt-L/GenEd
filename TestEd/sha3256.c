#include <ctype.h>

#define __STDC_WANT_LIB_EXT1__ 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//derived from keccak-tiny (https://github.com/coruus/keccak-tiny)

static const uint8_t sha3256_rho[24] = {
	1,  3,   6, 10, 15, 21,
	28, 36, 45, 55,  2, 14,
	27, 41, 56,  8, 25, 43,
	62, 18, 39, 61, 20, 44,
};
static const uint8_t sha3256_pi[24] = {
	10,  7, 11, 17, 18, 3,
	 5, 16,  8, 21, 24, 4,
	15, 23, 19, 13, 12, 2,
	20, 14, 22,  9, 6,  1,
};
static const uint64_t sha3256_RC[24] = {
	1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
	0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
	0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
	0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
	0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL
};
#define sha3256_rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define sha3256_REPEAT6(e) e e e e e e
#define sha3256_REPEAT24(e) sha3256_REPEAT6(e e e e)
#define sha3256_REPEAT5(e) e e e e e
#define sha3256_FOR5(v, s, e) \
	v = 0; \
	sha3256_REPEAT5(e; v += s;)
void keccakf(void* state){
	uint64_t* a = (uint64_t*)state;
	uint64_t b[5] = {0};
	uint64_t t = 0;
	uint8_t x, y;
	for(int i = 0; i < 24; i++){
		sha3256_FOR5(x, 1,
			b[x] = 0;
			sha3256_FOR5(y, 5,
				b[x] ^= a[x + y]; ))
		sha3256_FOR5(x, 1,
			sha3256_FOR5(y, 5,
				a[y + x] ^= b[(x + 4) % 5] ^ sha3256_rol(b[(x + 1) % 5], 1); ))
		t = a[1];
		x = 0;
		sha3256_REPEAT24(b[0] = a[sha3256_pi[x]];
			a[sha3256_pi[x]] = sha3256_rol(t, sha3256_rho[x]);
			t = b[0];
			x++; )
		sha3256_FOR5(y,
			5,
			sha3256_FOR5(x, 1,
				b[x] = a[y + x];)
		sha3256_FOR5(x, 1,
			a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]); ))
		a[0] ^= sha3256_RC[i];
	}
}
#define sha3256__(S) do { S } while (0)
#define sha3256_FOR(i, ST, L, S) \
	sha3256__(for (size_t i = 0; i < L; i += ST) { S; })
#define sha3256_mkapply_ds(NAME, S) \
	static inline void NAME(uint8_t* dst, \
		const uint8_t* src, \
		size_t len) { \
	sha3256_FOR(i, 1, len, S); \
  }
#define sha3256_mkapply_sd(NAME, S)                                          \
  static inline void NAME(const uint8_t* src,                        \
                          uint8_t* dst,                              \
                          size_t len) {                              \
    sha3256_FOR(i, 1, len, S);                                               \
  }

sha3256_mkapply_ds(xorin, dst[i] ^= src[i])  // xorin
sha3256_mkapply_sd(setout, dst[i] = src[i])  // setout

#define sha3256_P keccakf
#define sha3256_Plen 200

// Fold P*F over the full blocks of an input.
#define sha3256_foldP(I, L, F) \
  while (L >= rate) {  \
    F(a, I, rate);     \
    sha3256_P(a);              \
    I += rate;         \
    L -= rate;         \
  }

/** The sponge-based hash construction. **/
int sha3256_hash(uint8_t* out, size_t outlen,
                       const uint8_t* in, size_t inlen
                       ) {

	size_t rate = 200 - (256 / 4);
	uint8_t delim = 0x06;
	
								   if (outlen > (256/8)) {                                      
      return -1;                                                  
    }    
  if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= sha3256_Plen)) {
    return -1;
  }
  uint8_t a[sha3256_Plen] = {0};
  // Absorb input.
  sha3256_foldP(in, inlen, xorin);
  // Xor in the DS and pad frame.
  a[inlen] ^= delim;
  a[rate - 1] ^= 0x80;
  // Xor in the last block.
  xorin(a, in, inlen);
  // Apply P
  sha3256_P(a);
  // Squeeze output.
  sha3256_foldP(out, outlen, setout);
  setout(a, out, outlen);
  return 0;
}

