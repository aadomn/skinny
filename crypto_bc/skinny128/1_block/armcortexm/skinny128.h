#ifndef SKINNY128_H_
#define SKINNY128_H_

#include "tk_schedule.h"

#define SKINNY128_128_ROUNDS	40
#define SKINNY128_256_ROUNDS	48
#define SKINNY128_384_ROUNDS	56

// ARM assembly functions defined in skinny128.s
extern void skinny128_128(u8* ctext, const u32* rtk, const u8* ptext);
extern void skinny128_256(u8* ctext, const u32* rtk, const u8* ptext);
extern void skinny128_384(u8* ctext, const u32* rtk, const u8* ptext);
extern void skinny128_128_inv(u8* ptext, const u32* rtk, const u8* ctext);
extern void skinny128_256_inv(u8* ptext, const u32* rtk, const u8* ctext);
extern void skinny128_384_inv(u8* ptext, const u32* rtk, const u8* ctext);
extern void tkschedule_perm(u32* rtk, const u8* key, const int rounds);
extern void tkschedule_lfsr_2(u32* rtk, const u8* key, const int rounds);
extern void tkschedule_lfsr(u32* rtk, const u8* tk2, const u8* tk3, int rounds);

void skinny128_128_encrypt(u8* ctext, const u8* ptext, const tweakey tk);
void skinny128_128_decrypt(u8* ctext, const u8* ptext, const tweakey tk);
void skinny128_256_encrypt(u8* ctext, const u8* ptext, const tweakey tk);
void skinny128_256_decrypt(u8* ctext, const u8* ptext, const tweakey tk);
void skinny128_384_encrypt(u8* ctext, const u8* ptext, const tweakey tk);
void skinny128_384_decrypt(u8* ctext, const u8* ptext, const tweakey tk);
void skinny128_384_plus_encrypt(u8* ctext, const u8* ptext, const tweakey tk);
void skinny128_384_plus_decrypt(u8* ctext, const u8* ptext, const tweakey tk);

#endif  // SKINNY128_H_