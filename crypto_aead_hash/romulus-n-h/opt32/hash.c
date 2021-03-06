#include "skinny128.h"
#include "tk_schedule.h"
#include "romulus.h"
#include <string.h>
#include <stdlib.h>

void hirose_128_128_256
	(unsigned char* h,
	 unsigned char* g,
	 const unsigned char* m) {

	unsigned char key [48];
	unsigned char hh  [16];
	int i;
    skinny_128_384_tks tks;

    memset(tks.tk1, 0x00, KEYBYTES);
	for (i = 0; i < 16; i++) { 	// assign the key for the hirose compression function
		key[i] = g[i];
		g[i]   = h[i];
		hh[i]  = h[i];
	}
	g[0] ^= 0x01;
	for (i = 0; i < 32; i++) {
		key[i+16] = m[i];
	}

    precompute_rtk2_3(tks.rtk2_3, key+16, key+32);
    precompute_rtk1(tks.rtk1, key);
	skinny128_384_plus(h, h, tks.rtk1, tks.rtk2_3);
	skinny128_384_plus(g, g, tks.rtk1, tks.rtk2_3);

	for (i = 0; i < 16; i++) {
		h[i] ^= hh[i];
		g[i] ^= hh[i];
	}
	g[0] ^= 0x01;
}

void initialize
	(unsigned char* h,
	 unsigned char* g) {

 	 unsigned char i;
	for (i = 0; i < 16; i++) {
		h[i] = 0;
		g[i] = 0;
	}
}

void pad (const unsigned char* m, unsigned char* mp, int l, int len8) {

  int i;
  for (i = 0; i < l; i++) {
    if (i < len8) {      
      mp[i] = m[i];
    }
    else if (i == l - 1) {
      mp[i] = (len8 & 0x1f);
    }
    else {
      mp[i] = 0x00;
    }      
  }
  
}

int crypto_hash
	(unsigned char *out,
	 const unsigned char *in,
	 unsigned long long inlen) {

	unsigned char h[16];
	unsigned char g[16];
	unsigned long long mlen;
	unsigned char p[32];
	unsigned char i;

	mlen = inlen;

	initialize(h,g);
	while (mlen >= 32) { // Normal loop
		hirose_128_128_256(h,g,in);
		in += 32;
		mlen -= 32;
	}
	pad(in,p,32,mlen);
	h[0] ^= 2;
	hirose_128_128_256(h,g,p);

	for (i = 0; i < 16; i++) { // Assign the output tag
		out[i] = h[i];
		out[i+16] = g[i];
	}
	return 0;
}
