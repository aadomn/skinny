/******************************************************************************
* Fixsliced implementation of SKINNY-128 tweakable block ciphers.
* Processes 2 blocks at a time.
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
* Encryption of 2 blocks without any operation mode using SKINNY-128-128
******************************************************************************/
void skinny128_128_encrypt(u8* ctext, const u8* ptext, const tweakey tk, 
                    u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis) {
	u32 rtk[8*SKINNY128_128_ROUNDS];
    memset(rtk, 0x00, 32*SKINNY128_128_ROUNDS);
    pack_tk1(rtk, tk.tk1, tk_bis.tk1, SKINNY128_128_ROUNDS);
    tkschedule_perm(rtk, SKINNY128_128_ROUNDS);
    skinny128_128(ctext, ctext_bis, ptext, ptext_bis, rtk);
}

/******************************************************************************
* Encryption of 2 blocks without any operation mode using SKINNY-128-256
******************************************************************************/
void skinny128_256_encrypt(u8* ctext, const u8* ptext, const tweakey tk, 
                    u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis) {
	u32 rtk[8*SKINNY128_256_ROUNDS];
    memset(rtk, 0x00, 32*SKINNY128_256_ROUNDS);
    pack_tk1(rtk, tk.tk1, tk_bis.tk1, SKINNY128_256_ROUNDS);
    tkschedule_lfsr_2(rtk, tk.tk2, tk_bis.tk2, SKINNY128_256_ROUNDS);
    tkschedule_perm(rtk, SKINNY128_256_ROUNDS);
    skinny128_256(ctext, ctext_bis, ptext, ptext_bis, rtk);
}

/******************************************************************************
* Encryption of 2 blocks without any operation mode using SKINNY-128-384
******************************************************************************/
void skinny128_384_encrypt(u8* ctext, const u8* ptext, const tweakey tk, 
                    u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis) {
	u32 rtk[8*SKINNY128_384_ROUNDS];
    memset(rtk, 0x00, 32*SKINNY128_384_ROUNDS);
    pack_tk1(rtk, tk.tk1, tk_bis.tk1, SKINNY128_384_ROUNDS);
    tkschedule_lfsr_2(rtk, tk.tk2, tk_bis.tk2, SKINNY128_384_ROUNDS);
    tkschedule_lfsr_3(rtk, tk.tk3, tk_bis.tk3, SKINNY128_384_ROUNDS);
    tkschedule_perm(rtk, SKINNY128_384_ROUNDS);
    skinny128_384(ctext, ctext_bis, ptext, ptext_bis, rtk);
}

/******************************************************************************
* Encryption of 2 blocks without any operation mode using SKINNY-128-384+
******************************************************************************/
void skinny128_384_plus_encrypt(u8* ctext, const u8* ptext, const tweakey tk, 
                    u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis) {
    u32 rtk[8*SKINNY128_128_ROUNDS];
    memset(rtk, 0x00, 32*SKINNY128_128_ROUNDS);
    pack_tk1(rtk, tk.tk1, tk_bis.tk1, SKINNY128_128_ROUNDS);
    tkschedule_lfsr_2(rtk, tk.tk2, tk_bis.tk2, SKINNY128_128_ROUNDS);
    tkschedule_lfsr_3(rtk, tk.tk3, tk_bis.tk3, SKINNY128_128_ROUNDS);
    tkschedule_perm(rtk, SKINNY128_128_ROUNDS);
    skinny128_128(ctext, ctext_bis, ptext, ptext_bis, rtk);
}

/******************************************************************************
* Decryption of 2 blocks without any operation mode using SKINNY-128-128
******************************************************************************/
void skinny128_128_decrypt(u8* ptext, const u8* ctext, const tweakey tk, 
                    u8* ptext_bis, const u8* ctext_bis, const tweakey tk_bis) {
    u32 rtk[8*SKINNY128_128_ROUNDS];
    memset(rtk, 0x00, 32*SKINNY128_128_ROUNDS);
    pack_tk1(rtk, tk.tk1, tk_bis.tk1, SKINNY128_128_ROUNDS);
    tkschedule_perm(rtk, SKINNY128_128_ROUNDS);
    skinny128_128_inv(ptext, ptext_bis, ctext, ctext_bis, rtk);
}

/******************************************************************************
* Decryption of 2 blocks without any operation mode using SKINNY-128-256
******************************************************************************/
void skinny128_256_decrypt(u8* ptext, const u8* ctext, const tweakey tk, 
                    u8* ptext_bis, const u8* ctext_bis, const tweakey tk_bis) {
    u32 rtk[8*SKINNY128_256_ROUNDS];
    memset(rtk, 0x00, 32*SKINNY128_256_ROUNDS);
    pack_tk1(rtk, tk.tk1, tk_bis.tk1, SKINNY128_256_ROUNDS);
    tkschedule_lfsr_2(rtk, tk.tk2, tk_bis.tk2, SKINNY128_256_ROUNDS);
    tkschedule_perm(rtk, SKINNY128_256_ROUNDS);
    skinny128_256_inv(ptext, ptext_bis, ctext, ctext_bis, rtk);
}

/******************************************************************************
* Decryption of 2 blocks without any operation mode using SKINNY-128-384
******************************************************************************/
void skinny128_384_decrypt(u8* ptext, const u8* ctext, const tweakey tk, 
                    u8* ptext_bis, const u8* ctext_bis, const tweakey tk_bis) {
    u32 rtk[8*SKINNY128_384_ROUNDS];
    memset(rtk, 0x00, 32*SKINNY128_384_ROUNDS);
    pack_tk1(rtk, tk.tk1, tk_bis.tk1, SKINNY128_384_ROUNDS);
    tkschedule_lfsr_2(rtk, tk.tk2, tk_bis.tk2, SKINNY128_384_ROUNDS);
    tkschedule_lfsr_3(rtk, tk.tk3, tk_bis.tk3, SKINNY128_384_ROUNDS);
    tkschedule_perm(rtk, SKINNY128_384_ROUNDS);
    skinny128_384_inv(ptext, ptext_bis, ctext, ctext_bis, rtk);
}

/******************************************************************************
* Decryption of 2 blocks without any operation mode using SKINNY-128-384+
******************************************************************************/
void skinny128_384_plus_decrypt(u8* ptext, const u8* ctext, const tweakey tk, 
                    u8* ptext_bis, const u8* ctext_bis, const tweakey tk_bis) {
    u32 rtk[8*SKINNY128_128_ROUNDS];
    memset(rtk, 0x00, 32*SKINNY128_128_ROUNDS);
    pack_tk1(rtk, tk.tk1, tk_bis.tk1, SKINNY128_128_ROUNDS);
    tkschedule_lfsr_2(rtk, tk.tk2, tk_bis.tk2, SKINNY128_128_ROUNDS);
    tkschedule_lfsr_3(rtk, tk.tk3, tk_bis.tk3, SKINNY128_128_ROUNDS);
    tkschedule_perm(rtk, SKINNY128_128_ROUNDS);
    skinny128_128_inv(ptext, ptext_bis, ctext, ctext_bis, rtk);
}