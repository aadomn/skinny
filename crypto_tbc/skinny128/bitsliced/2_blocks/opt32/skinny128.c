/******************************************************************************
* Constant-time implementation of the SKINNY tweakable block ciphers.
*
* This implementation doesn't compute the ShiftRows operation. Some masks and
* shifts are applied during the MixColumns operation so that the proper bits
* are XORed together. Moreover, the row permutation within the MixColumns 
* is omitted, as well as the bit permutation at the end of the Sbox. The rows
* are synchronized with the classical after only 4 rounds. However, the Sbox
* permutation requires 8 rounds for a synchronization. To limit the impact
* on code size, we compute the permutation every 4 rounds. Therefore, this
* implementation relies on a "QUADRUPLE_ROUND" routine.
*
* For more details, see the papers at:
* https://eprint.iacr.org/2020/1123.pdf
* https://csrc.nist.gov/CSRC/media/Events/lightweight-cryptography-workshop-2020/documents/papers/fixslicing-lwc2020.pdf
*
* @author	Alexandre Adomnicai, Nanyang Technological University,
*			alexandre.adomnicai@ntu.edu.sg
*
* @date		May 2020
******************************************************************************/
#include <string.h>
#include "skinny128.h"

/****************************************************************************
* The MixColumns operation for rounds i such that (i % 4) == 0
****************************************************************************/
void mixcolumns_0(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = ROR(state[i],24) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,30);
		tmp = ROR(state[i],16) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,4);
		tmp = ROR(state[i],8) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,2);
	}
}

/****************************************************************************
* The MixColumns operation for rounds i such that (i % 4) == 1
****************************************************************************/
void mixcolumns_1(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = ROR(state[i],16) & 0x30303030;
		state[i] ^= ROR(tmp,30);
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,28);
		tmp = ROR(state[i],16) & 0x30303030;
		state[i] ^= ROR(tmp,2);
	}
}

/****************************************************************************
* The MixColumns operation for rounds i such that (i % 4) == 2
****************************************************************************/
void mixcolumns_2(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = ROR(state[i],8) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,6);
		tmp = ROR(state[i],16) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,28);
		tmp = ROR(state[i],24) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,2);
	}
}

/****************************************************************************
* The MixColumns operation for rounds i such that (i % 4) == 3
****************************************************************************/
void mixcolumns_3(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,30);
		tmp = state[i] & 0x30303030;
		state[i] ^= ROR(tmp,4);
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,26);
	}
}

/****************************************************************************
* The inverse MixColumns oepration for rounds i such that (i % 4) == 0
****************************************************************************/
void inv_mixcolumns_0(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = ROR(state[i],8) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,2);
		tmp = ROR(state[i],16) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,4);
		tmp = ROR(state[i],24) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,30);
	}
}

/****************************************************************************
* The inverse MixColumns oepration for rounds i such that (i % 4) == 1
****************************************************************************/
void inv_mixcolumns_1(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = ROR(state[i],16) & 0x30303030;
		state[i] ^= ROR(tmp,2);
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,28);
		tmp = ROR(state[i],16) & 0x30303030;
		state[i] ^= ROR(tmp,30);
	}
}

/****************************************************************************
* The inverse MixColumns oepration for rounds i such that (i % 4) == 2
****************************************************************************/
void inv_mixcolumns_2(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = ROR(state[i],24) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,2);
		tmp = ROR(state[i],16) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,28);
		tmp = ROR(state[i],8) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,6);
	}
}

/****************************************************************************
* The inverse MixColumns oepration for rounds i such that (i % 4) == 3
****************************************************************************/
void inv_mixcolumns_3(u32* state) {
	u32 tmp;
	for(int i = 0; i < 8; i++) {
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,26);
		tmp = state[i] & 0x30303030;
		state[i] ^= ROR(tmp,4);
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,30);
	}
}

/****************************************************************************
* Adds the tweakey (including the round constants) to the state
****************************************************************************/
void add_tweakey(u32* state, u32* tk) {
	state[0] ^= tk[0];
	state[1] ^= tk[1]; 
	state[2] ^= tk[2];
	state[3] ^= tk[3];
	state[4] ^= tk[4];
	state[5] ^= tk[5];
	state[6] ^= tk[6];
	state[7] ^= tk[7];
}

/****************************************************************************
* Encryption of 2 blocks in parallel using SKINNY-128-128
****************************************************************************/
void skinny128_128_encrypt(u8* ctext, const u8* ptext, const tweakey tk, 
					u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis) {
	u32 state[8];
	u32 rtk[8*SKINNY128_128_ROUNDS];
	precompute_tk(rtk, tk, tk_bis, SKINNY128_128_ROUNDS);
	packing(state, ptext, ptext_bis);
	QUADRUPLE_ROUND(state, rtk);
	QUADRUPLE_ROUND(state, rtk+32);
	QUADRUPLE_ROUND(state, rtk+64);
	QUADRUPLE_ROUND(state, rtk+96);
	QUADRUPLE_ROUND(state, rtk+128);
	QUADRUPLE_ROUND(state, rtk+160);
	QUADRUPLE_ROUND(state, rtk+192);
	QUADRUPLE_ROUND(state, rtk+224);
	QUADRUPLE_ROUND(state, rtk+256);
	QUADRUPLE_ROUND(state, rtk+288);
	unpacking(ctext, ctext_bis, state);
}

/****************************************************************************
* Encryption of 2 blocks in parallel using SKINNY-128-256
****************************************************************************/
void skinny128_256_encrypt(u8* ctext, const u8* ptext, const tweakey tk, 
					u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis) {
	u32 state[8];
	u32 rtk[8*SKINNY128_256_ROUNDS];
	precompute_tk(rtk, tk, tk_bis, SKINNY128_256_ROUNDS);
	packing(state, ptext, ptext_bis);
	QUADRUPLE_ROUND(state, rtk);
	QUADRUPLE_ROUND(state, rtk+32);
	QUADRUPLE_ROUND(state, rtk+64);
	QUADRUPLE_ROUND(state, rtk+96);
	QUADRUPLE_ROUND(state, rtk+128);
	QUADRUPLE_ROUND(state, rtk+160);
	QUADRUPLE_ROUND(state, rtk+192);
	QUADRUPLE_ROUND(state, rtk+224);
	QUADRUPLE_ROUND(state, rtk+256);
	QUADRUPLE_ROUND(state, rtk+288);
	QUADRUPLE_ROUND(state, rtk+320);
	QUADRUPLE_ROUND(state, rtk+352);
	unpacking(ctext, ctext_bis, state);
}

/****************************************************************************
* Encryption of 2 blocks in parallel using SKINNY-128-384
****************************************************************************/
void skinny128_384_encrypt(u8* ctext, const u8* ptext, const tweakey tk, 
					u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis) {
	u32 state[8];
	u32 rtk[8*SKINNY128_384_ROUNDS];
	precompute_tk(rtk, tk, tk_bis, SKINNY128_384_ROUNDS);
	packing(state, ptext, ptext_bis);
	QUADRUPLE_ROUND(state, rtk);
	QUADRUPLE_ROUND(state, rtk+32);
	QUADRUPLE_ROUND(state, rtk+64);
	QUADRUPLE_ROUND(state, rtk+96);
	QUADRUPLE_ROUND(state, rtk+128);
	QUADRUPLE_ROUND(state, rtk+160);
	QUADRUPLE_ROUND(state, rtk+192);
	QUADRUPLE_ROUND(state, rtk+224);
	QUADRUPLE_ROUND(state, rtk+256);
	QUADRUPLE_ROUND(state, rtk+288);
	QUADRUPLE_ROUND(state, rtk+320);
	QUADRUPLE_ROUND(state, rtk+352);
	QUADRUPLE_ROUND(state, rtk+384);
	QUADRUPLE_ROUND(state, rtk+416);
	unpacking(ctext, ctext_bis, state);
}

/****************************************************************************
* Decryption of 2 blocks in parallel using SKINNY-128-128
****************************************************************************/
void skinny128_128_decrypt(u8* ptext, const u8* ctext, const tweakey tk, 
					u8* ptext_bis, const u8* ctext_bis, const tweakey tk_bis) {
	u32 state[8];
	u32 rtk[8*SKINNY128_128_ROUNDS];
	precompute_tk(rtk, tk, tk_bis, SKINNY128_128_ROUNDS);
	packing(state, ctext, ctext_bis);
	INV_QUADRUPLE_ROUND(state, rtk+288);
	INV_QUADRUPLE_ROUND(state, rtk+256);
	INV_QUADRUPLE_ROUND(state, rtk+224);
	INV_QUADRUPLE_ROUND(state, rtk+192);
	INV_QUADRUPLE_ROUND(state, rtk+160);
	INV_QUADRUPLE_ROUND(state, rtk+128);
	INV_QUADRUPLE_ROUND(state, rtk+96);
	INV_QUADRUPLE_ROUND(state, rtk+64);
	INV_QUADRUPLE_ROUND(state, rtk+32);
	INV_QUADRUPLE_ROUND(state, rtk);
	unpacking(ptext, ptext_bis, state);
}

/****************************************************************************
* Decryption of 2 blocks in parallel using SKINNY-128-256
****************************************************************************/
void skinny128_256_decrypt(u8* ptext, const u8* ctext, const tweakey tk, 
					u8* ptext_bis, const u8* ctext_bis, const tweakey tk_bis) {
	u32 state[8];
	u32 rtk[8*SKINNY128_256_ROUNDS];
	precompute_tk(rtk, tk, tk_bis, SKINNY128_256_ROUNDS);
	packing(state, ctext, ctext_bis);
	INV_QUADRUPLE_ROUND(state, rtk+352);
	INV_QUADRUPLE_ROUND(state, rtk+320);
	INV_QUADRUPLE_ROUND(state, rtk+288);
	INV_QUADRUPLE_ROUND(state, rtk+256);
	INV_QUADRUPLE_ROUND(state, rtk+224);
	INV_QUADRUPLE_ROUND(state, rtk+192);
	INV_QUADRUPLE_ROUND(state, rtk+160);
	INV_QUADRUPLE_ROUND(state, rtk+128);
	INV_QUADRUPLE_ROUND(state, rtk+96);
	INV_QUADRUPLE_ROUND(state, rtk+64);
	INV_QUADRUPLE_ROUND(state, rtk+32);
	INV_QUADRUPLE_ROUND(state, rtk);
	unpacking(ptext, ptext_bis, state);
}

/****************************************************************************
* Decryption of 2 blocks in parallel using SKINNY-128-384
****************************************************************************/
void skinny128_384_decrypt(u8* ptext, const u8* ctext, const tweakey tk, 
					u8* ptext_bis, const u8* ctext_bis, const tweakey tk_bis) {
	u32 state[8];
	u32 rtk[8*SKINNY128_384_ROUNDS];
	precompute_tk(rtk, tk, tk_bis, SKINNY128_384_ROUNDS);
	packing(state, ctext, ctext_bis);
	INV_QUADRUPLE_ROUND(state, rtk+416);
	INV_QUADRUPLE_ROUND(state, rtk+384);
	INV_QUADRUPLE_ROUND(state, rtk+352);
	INV_QUADRUPLE_ROUND(state, rtk+320);
	INV_QUADRUPLE_ROUND(state, rtk+288);
	INV_QUADRUPLE_ROUND(state, rtk+256);
	INV_QUADRUPLE_ROUND(state, rtk+224);
	INV_QUADRUPLE_ROUND(state, rtk+192);
	INV_QUADRUPLE_ROUND(state, rtk+160);
	INV_QUADRUPLE_ROUND(state, rtk+128);
	INV_QUADRUPLE_ROUND(state, rtk+96);
	INV_QUADRUPLE_ROUND(state, rtk+64);
	INV_QUADRUPLE_ROUND(state, rtk+32);
	INV_QUADRUPLE_ROUND(state, rtk);
	unpacking(ptext, ptext_bis, state);
}
