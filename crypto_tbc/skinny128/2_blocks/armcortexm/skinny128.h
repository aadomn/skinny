#ifndef SKINNY128_H_
#define SKINNY128_H_
#include "tk_schedule.h"

#define SKINNY128_128_ROUNDS	40
#define SKINNY128_256_ROUNDS	48
#define SKINNY128_384_ROUNDS	56

// ARM assembly functions defined in skinny128.s
extern void skinny128_128(u8* ctext, u8* ctext_bis, const u8* ptext,
					const u8* ptext_bis, const u32* rtk);
extern void skinny128_256(u8* ctext, u8* ctext_bis, const u8* ptext,
					const u8* ptext_bis, const u32* rtk);
extern void skinny128_384(u8* ctext, u8* ctext_bis, const u8* ptext,
					const u8* ptext_bis, const u32* rtk);
extern void skinny128_128_inv(u8* ptext, u8* ptext_bis, const u8* ctext,
					const u8* ctext_bis, const u32* rtk);
extern void skinny128_256_inv(u8* ptext, u8* ptext_bis, const u8* ctext,
					const u8* ctext_bis, const u32* rtk);
extern void skinny128_384_inv(u8* ptext, u8* ptext_bis, const u8* ctext,
					const u8* ctext_bis, const u32* rtk);
extern void tkschedule_lfsr_2(u32* rtk, const u8* tk2, const u8* tk2_bis,
					const int rounds);
extern void pack_tk1(u32* rtk, const u8* tk2, const u8* tk2_bis,
					const int rounds);
extern void tkschedule_lfsr_3(u32* rtk, const u8* tk3, const u8* tk3_bis,
					const int rounds);
extern void tkschedule_perm(u32* rtk, int rounds);

void skinny128_128_encrypt(u8* ctext, const u8* ptext, const tweakey tk, 
					u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis);
void skinny128_128_decrypt(u8* ctext, const u8* ptext, const tweakey tk, 
					u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis);
void skinny128_256_encrypt(u8* ctext, const u8* ptext, const tweakey tk, 
					u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis);
void skinny128_256_decrypt(u8* ctext, const u8* ptext, const tweakey tk, 
					u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis);
void skinny128_384_encrypt(u8* ctext, const u8* ptext, const tweakey tk, 
					u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis);
void skinny128_384_decrypt(u8* ctext, const u8* ptext, const tweakey tk, 
					u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis);
void skinny128_384_plus_encrypt(u8* ctext, const u8* ptext, const tweakey tk, 
					u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis);
void skinny128_384_plus_decrypt(u8* ctext, const u8* ptext, const tweakey tk, 
					u8* ctext_bis, const u8* ptext_bis, const tweakey tk_bis);

#endif  // SKINNY128_H_