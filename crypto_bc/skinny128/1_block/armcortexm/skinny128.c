/******************************************************************************
* Fixsliced implementation of SKINNY-128 tweakable block ciphers.
* Processes a single block at a time.
* See 'skinny128.s' for ARM assembly implementations of the core functions.
*
* @author	Alexandre Adomnicai, Nanyang Technological University,
*			alexandre.adomnicai@ntu.edu.sg
*
* @date		May 2020
******************************************************************************/
#include <stdio.h>
#include <string.h>
#include "skinny128.h"

/******************************************************************************
* Encryption of a single block without any operation mode using SKINNY-128-128
******************************************************************************/
void skinny128_128_encrypt(u8* ctext, const u8* ptext, const tweakey tk) {
	u32 rtk[4*SKINNY128_128_ROUNDS];
    memset(rtk, 0x00, 16*SKINNY128_128_ROUNDS);
    tkschedule_perm(rtk, tk.tk1, SKINNY128_128_ROUNDS);
    skinny128_128(ctext, rtk, ptext);
}

/******************************************************************************
* Encryption of a single block without any operation mode using SKINNY-128-256
******************************************************************************/
void skinny128_256_encrypt(u8* ctext, const u8* ptext, const tweakey tk) {
	u32 rtk[4*SKINNY128_256_ROUNDS];
    memset(rtk, 0x00, 16*SKINNY128_256_ROUNDS);
    tkschedule_lfsr_2(rtk, tk.tk2, SKINNY128_256_ROUNDS);
    tkschedule_perm(rtk, tk.tk1, SKINNY128_256_ROUNDS);
    skinny128_256(ctext, rtk, ptext);
}

/******************************************************************************
* Encryption of a single block without any operation mode using SKINNY-128-384
******************************************************************************/
void skinny128_384_encrypt(u8* ctext, const u8* ptext, const tweakey tk) {
	u32 rtk[4*SKINNY128_384_ROUNDS];
    tkschedule_lfsr(rtk, tk.tk2, tk.tk3, SKINNY128_384_ROUNDS);
    tkschedule_perm(rtk, tk.tk1, SKINNY128_384_ROUNDS);
    skinny128_384(ctext, rtk, ptext);
}

/******************************************************************************
* Encryption of a single block without any operation mode using SKINNY-128-384+
******************************************************************************/
void skinny128_384_plus_encrypt(u8* ctext, const u8* ptext, const tweakey tk) {
    u32 rtk[4*SKINNY128_128_ROUNDS];
    tkschedule_lfsr(rtk, tk.tk2, tk.tk3, SKINNY128_128_ROUNDS);
    tkschedule_perm(rtk, tk.tk1, SKINNY128_128_ROUNDS);
    skinny128_128(ctext, rtk, ptext);
}

/******************************************************************************
* Decryption of a single block without any operation mode using SKINNY-128-128
******************************************************************************/
void skinny128_128_decrypt(u8* ctext, const u8* ptext, const tweakey tk) {
	u32 rtk[4*SKINNY128_128_ROUNDS];
    memset(rtk, 0x00, 16*SKINNY128_128_ROUNDS);
    tkschedule_perm(rtk, tk.tk1, SKINNY128_128_ROUNDS);
    skinny128_128_inv(ctext, rtk, ptext);
}

/******************************************************************************
* Decryption of a single block without any operation mode using SKINNY-128-256
******************************************************************************/
void skinny128_256_decrypt(u8* ctext, const u8* ptext, const tweakey tk) {
	u32 rtk[4*SKINNY128_256_ROUNDS];
    memset(rtk, 0x00, 16*SKINNY128_256_ROUNDS);
    tkschedule_lfsr_2(rtk, tk.tk2, SKINNY128_256_ROUNDS);
    tkschedule_perm(rtk, tk.tk1, SKINNY128_256_ROUNDS);
    skinny128_256_inv(ctext, rtk, ptext);
}

/******************************************************************************
* Decryption of a single block without any operation mode using SKINNY-128-384
******************************************************************************/
void skinny128_384_decrypt(u8* ctext, const u8* ptext, const tweakey tk) {
	u32 rtk[4*SKINNY128_384_ROUNDS];
    tkschedule_lfsr(rtk, tk.tk2, tk.tk3, SKINNY128_384_ROUNDS);
    tkschedule_perm(rtk, tk.tk1, SKINNY128_384_ROUNDS);
    skinny128_384_inv(ctext, rtk, ptext);
}

/******************************************************************************
* Decryption of a single block without any operation mode using SKINNY-128-384+
******************************************************************************/
void skinny128_384_plus_decrypt(u8* ptext, const u8* ctext, const tweakey tk) {
    u32 rtk[4*SKINNY128_128_ROUNDS];
    tkschedule_lfsr(rtk, tk.tk2, tk.tk3, SKINNY128_128_ROUNDS);
    tkschedule_perm(rtk, tk.tk1, SKINNY128_128_ROUNDS);
    skinny128_128_inv(ptext, rtk, ctext);
}