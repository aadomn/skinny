/******************************************************************************
* Constant-time implementation of the SKINNY-128 tweakable block ciphers.
*
* This implementation doesn't compute the ShiftRows operation. Some masks and
* shifts are applied during the MixColumns operation so that the proper bits
* are XORed together. Moreover, the row permutation within the MixColumns 
* is omitted, as well as the bit permutation at the end of the Sbox. The rows
* are synchronized with the classical after only 4 rounds. Therefore, this 
* implementation relies on a "QUADRUPLE_ROUND" routine.
*
* The Sbox computation takes advantage of some symmetry in the 8-bit Sbox to
* turn it into a 4-bit S-box computation. Although the last bit permutation
* within the Sbox is not computed, the bit ordering is synchronized with the 
* classical representation after 2 calls.
*
* For more details, see the papers at:
* https://eprint.iacr.org/2020/1123.pdf
* https://csrc.nist.gov/CSRC/media/Events/lightweight-cryptography-workshop-2020/documents/papers/fixslicing-lwc2020.pdf
*
* @author	Alexandre Adomnicai, Nanyang Technological University,
*			alexandre.adomnicai@ntu.edu.sg
*
* @date		June 2020
******************************************************************************/
#include "skinny128.h"

/******************************************************************************
* The MixColumns operation for rounds i such that (i % 4) == 0
******************************************************************************/
void mixcolumns_0(u32* state) {
	u32 tmp;
	for(int i = 0; i < 4; i++) {
		tmp = ROR(state[i],24) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,30);
		tmp = ROR(state[i],16) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,4);
		tmp = ROR(state[i],8) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,2);
	}
}

/******************************************************************************
* The MixColumns operation for rounds i such that (i % 4) == 1
******************************************************************************/
void mixcolumns_1(u32* state) {
	u32 tmp;
	for(int i = 0; i < 4; i++) {
		tmp = ROR(state[i],16) & 0x30303030;
		state[i] ^= ROR(tmp,30);
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,28);
		tmp = ROR(state[i],16) & 0x30303030;
		state[i] ^= ROR(tmp,2);
	}
}

/******************************************************************************
* The MixColumns operation for rounds i such that (i % 4) == 2
******************************************************************************/
void mixcolumns_2(u32* state) {
	u32 tmp;
	for(int i = 0; i < 4; i++) {
		tmp = ROR(state[i],8) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,6);
		tmp = ROR(state[i],16) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,28);
		tmp = ROR(state[i],24) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,2);
	}
}

/******************************************************************************
* The MixColumns operation for rounds i such that (i % 4) == 3
******************************************************************************/
void mixcolumns_3(u32* state) {
	u32 tmp;
	for(int i = 0; i < 4; i++) {
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,30);
		tmp = state[i] & 0x30303030;
		state[i] ^= ROR(tmp,4);
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,26);
	}
}

/******************************************************************************
* The inverse MixColumns operation for rounds i such that (i % 4) == 0
******************************************************************************/
void inv_mixcolumns_0(u32* state) {
	u32 tmp;
	for(int i = 0; i < 4; i++) {
		tmp = ROR(state[i],8) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,2);
		tmp = ROR(state[i],16) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,4);
		tmp = ROR(state[i],24) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,30);
	}
}

/******************************************************************************
* The inverse MixColumns operation for rounds i such that (i % 4) == 1
******************************************************************************/
void inv_mixcolumns_1(u32* state) {
	u32 tmp;
	for(int i = 0; i < 4; i++) {
		tmp = ROR(state[i],16) & 0x30303030;
		state[i] ^= ROR(tmp,2);
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,28);
		tmp = ROR(state[i],16) & 0x30303030;
		state[i] ^= ROR(tmp,30);
	}
}

/******************************************************************************
* The inverse MixColumns operation for rounds i such that (i % 4) == 2
******************************************************************************/
void inv_mixcolumns_2(u32* state) {
	u32 tmp;
	for(int i = 0; i < 4; i++) {
		tmp = ROR(state[i],24) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,2);
		tmp = ROR(state[i],16) & 0x0c0c0c0c;
		state[i] ^= ROR(tmp,28);
		tmp = ROR(state[i],8) & 0xc0c0c0c0;
		state[i] ^= ROR(tmp,6);
	}
}

/******************************************************************************
* The inverse MixColumns operation for rounds i such that (i % 4) == 3
******************************************************************************/
void inv_mixcolumns_3(u32* state) {
	u32 tmp;
	for(int i = 0; i < 4; i++) {
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,26);
		tmp = state[i] & 0x30303030;
		state[i] ^= ROR(tmp,4);
		tmp = state[i] & 0x03030303;
		state[i] ^= ROR(tmp,30);
	}
}

/******************************************************************************
* Encryption of a single block without any operation mode using SKINNY-128-128
******************************************************************************/
void skinny128_128_encrypt(u8* ctext, const u8* ptext, const tweakey tk) {
	u32 tmp;
	u32 state[4];
	u32 rtk[4*SKINNY128_128_ROUNDS];
	precompute_tk(rtk, tk, SKINNY128_128_ROUNDS);
	packing(state, ptext);
	QUADRUPLE_ROUND(state, rtk);
	QUADRUPLE_ROUND(state, rtk+16);
	QUADRUPLE_ROUND(state, rtk+32);
	QUADRUPLE_ROUND(state, rtk+48);
	QUADRUPLE_ROUND(state, rtk+64);
	QUADRUPLE_ROUND(state, rtk+80);
	QUADRUPLE_ROUND(state, rtk+96);
	QUADRUPLE_ROUND(state, rtk+112);
	QUADRUPLE_ROUND(state, rtk+128);
	QUADRUPLE_ROUND(state, rtk+144);
	unpacking(ctext, state);
}

/******************************************************************************
* Encryption of a single block without any operation mode using SKINNY-128-256
******************************************************************************/
void skinny128_256_encrypt(u8* ctext, const u8* ptext, const tweakey tk) {
	u32 tmp;
	u32 state[4];
	u32 rtk[4*SKINNY128_256_ROUNDS];
	precompute_tk(rtk, tk, SKINNY128_256_ROUNDS);
	packing(state, ptext);
	QUADRUPLE_ROUND(state, rtk);
	QUADRUPLE_ROUND(state, rtk+16);
	QUADRUPLE_ROUND(state, rtk+32);
	QUADRUPLE_ROUND(state, rtk+48);
	QUADRUPLE_ROUND(state, rtk+64);
	QUADRUPLE_ROUND(state, rtk+80);
	QUADRUPLE_ROUND(state, rtk+96);
	QUADRUPLE_ROUND(state, rtk+112);
	QUADRUPLE_ROUND(state, rtk+128);
	QUADRUPLE_ROUND(state, rtk+144);
	QUADRUPLE_ROUND(state, rtk+160);
	QUADRUPLE_ROUND(state, rtk+176);
	unpacking(ctext, state);
}

/******************************************************************************
* Encryption of a single block without any operation mode using SKINNY-128-384
******************************************************************************/
void skinny128_384_encrypt(u8* ctext, const u8* ptext, const tweakey tk) {
	u32 tmp;
	u32 state[4];
	u32 rtk[4*SKINNY128_384_ROUNDS];
	precompute_tk(rtk, tk, SKINNY128_384_ROUNDS);
	packing(state, ptext);
	QUADRUPLE_ROUND(state, rtk);
	QUADRUPLE_ROUND(state, rtk+16);
	QUADRUPLE_ROUND(state, rtk+32);
	QUADRUPLE_ROUND(state, rtk+48);
	QUADRUPLE_ROUND(state, rtk+64);
	QUADRUPLE_ROUND(state, rtk+80);
	QUADRUPLE_ROUND(state, rtk+96);
	QUADRUPLE_ROUND(state, rtk+112);
	QUADRUPLE_ROUND(state, rtk+128);
	QUADRUPLE_ROUND(state, rtk+144);
	QUADRUPLE_ROUND(state, rtk+160);
	QUADRUPLE_ROUND(state, rtk+176);
	QUADRUPLE_ROUND(state, rtk+192);
	QUADRUPLE_ROUND(state, rtk+208);
	unpacking(ctext, state);
}

/******************************************************************************
* Decryption of a single block without any operation mode using SKINNY-128-128
******************************************************************************/
void skinny128_128_decrypt(u8* ptext, const u8* ctext, const tweakey tk) {
	u32 tmp;
	u32 state[4];
	u32 rtk[4*SKINNY128_128_ROUNDS];
	precompute_tk(rtk, tk, SKINNY128_128_ROUNDS);
	packing(state, ctext);
	INV_QUADRUPLE_ROUND(state, rtk+144);
	INV_QUADRUPLE_ROUND(state, rtk+128);
	INV_QUADRUPLE_ROUND(state, rtk+112);
	INV_QUADRUPLE_ROUND(state, rtk+96);
	INV_QUADRUPLE_ROUND(state, rtk+80);
	INV_QUADRUPLE_ROUND(state, rtk+64);
	INV_QUADRUPLE_ROUND(state, rtk+48);
	INV_QUADRUPLE_ROUND(state, rtk+32);
	INV_QUADRUPLE_ROUND(state, rtk+16);
	INV_QUADRUPLE_ROUND(state, rtk);
	unpacking(ptext, state);
}

/******************************************************************************
* Decryption of a single block without any operation mode using SKINNY-128-256
******************************************************************************/
void skinny128_256_decrypt(u8* ptext, const u8* ctext, const tweakey tk) {
	u32 tmp;
	u32 state[4];
	u32 rtk[4*SKINNY128_256_ROUNDS];
	precompute_tk(rtk, tk, SKINNY128_256_ROUNDS);
	packing(state, ctext);
	INV_QUADRUPLE_ROUND(state, rtk+176);
	INV_QUADRUPLE_ROUND(state, rtk+160);
	INV_QUADRUPLE_ROUND(state, rtk+144);
	INV_QUADRUPLE_ROUND(state, rtk+128);
	INV_QUADRUPLE_ROUND(state, rtk+112);
	INV_QUADRUPLE_ROUND(state, rtk+96);
	INV_QUADRUPLE_ROUND(state, rtk+80);
	INV_QUADRUPLE_ROUND(state, rtk+64);
	INV_QUADRUPLE_ROUND(state, rtk+48);
	INV_QUADRUPLE_ROUND(state, rtk+32);
	INV_QUADRUPLE_ROUND(state, rtk+16);
	INV_QUADRUPLE_ROUND(state, rtk);
	unpacking(ptext, state);
}

/******************************************************************************
* Decryption of a single block without any operation mode using SKINNY-128-384
******************************************************************************/
void skinny128_384_decrypt(u8* ptext, const u8* ctext, const tweakey tk) {
	u32 tmp;
	u32 state[4];
	u32 rtk[4*SKINNY128_384_ROUNDS];
	precompute_tk(rtk, tk, SKINNY128_384_ROUNDS);
	packing(state, ctext);
	INV_QUADRUPLE_ROUND(state, rtk+208);
	INV_QUADRUPLE_ROUND(state, rtk+192);
	INV_QUADRUPLE_ROUND(state, rtk+176);
	INV_QUADRUPLE_ROUND(state, rtk+160);
	INV_QUADRUPLE_ROUND(state, rtk+144);
	INV_QUADRUPLE_ROUND(state, rtk+128);
	INV_QUADRUPLE_ROUND(state, rtk+112);
	INV_QUADRUPLE_ROUND(state, rtk+96);
	INV_QUADRUPLE_ROUND(state, rtk+80);
	INV_QUADRUPLE_ROUND(state, rtk+64);
	INV_QUADRUPLE_ROUND(state, rtk+48);
	INV_QUADRUPLE_ROUND(state, rtk+32);
	INV_QUADRUPLE_ROUND(state, rtk+16);
	INV_QUADRUPLE_ROUND(state, rtk);
	unpacking(ptext, state);
}
