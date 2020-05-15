#ifndef SKINNY128_H_
#define SKINNY128_H_
#include "tk_schedule.h"

void skinny128_128_encrypt(u8* ctext, const u8* ptext, const tweakey tk);
void skinny128_128_decrypt(u8* ctext, const u8* ptext, const tweakey tk);
void skinny128_256_encrypt(u8* ctext, const u8* ptext, const tweakey tk);
void skinny128_256_decrypt(u8* ctext, const u8* ptext, const tweakey tk);
void skinny128_384_decrypt(u8* ctext, const u8* ptext, const tweakey tk);
void skinny128_384_encrypt(u8* ctext, const u8* ptext, const tweakey tk);

#define SKINNY128_128_ROUNDS	40
#define SKINNY128_256_ROUNDS	48
#define SKINNY128_384_ROUNDS	56

#define QUADRUPLE_ROUND(state, tk) ({					\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	state[1] ^= ~(state[2] | state[3]);					\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	state[1] ^= (state[2] | state[3]);					\
	SWAPMOVE(state[3], state[0], 0x55555555, 0);		\
	state[0] ^= (tk)[0];								\
	state[1] ^= (tk)[1];								\
	state[2] ^= (tk)[2];								\
	state[3] ^= (tk)[3];								\
	mixcolumns_0(state);								\
	state[1] ^= ~(state[2] | state[3]); 				\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	state[1] ^= ~(state[2] | state[3]);					\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	state[3] ^= (state[0] | state[1]);					\
	SWAPMOVE(state[1], state[2], 0x55555555, 0);		\
	state[0] ^= (tk)[4];								\
	state[1] ^= (tk)[5];								\
	state[2] ^= (tk)[6];								\
	state[3] ^= (tk)[7];								\
	mixcolumns_1(state);								\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	state[1] ^= ~(state[2] | state[3]);					\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	state[1] ^= (state[2] | state[3]);					\
	SWAPMOVE(state[3], state[0], 0x55555555, 0);		\
	state[0] ^= (tk)[8];								\
	state[1] ^= (tk)[9];								\
	state[2] ^= (tk)[10];								\
	state[3] ^= (tk)[11];								\
	mixcolumns_2(state);								\
	state[1] ^= ~(state[2] | state[3]); 				\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	state[1] ^= ~(state[2] | state[3]);					\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	state[3] ^= (state[0] | state[1]);					\
	SWAPMOVE(state[1], state[2], 0x55555555, 0);		\
	state[0] ^= (tk)[12];								\
	state[1] ^= (tk)[13];								\
	state[2] ^= (tk)[14];								\
	state[3] ^= (tk)[15];								\
	mixcolumns_3(state);								\
})

#define INV_QUADRUPLE_ROUND(state, tk) ({				\
	inv_mixcolumns_3(state);							\
	state[0] ^= (tk)[12];								\
	state[1] ^= (tk)[13];								\
	state[2] ^= (tk)[14];								\
	state[3] ^= (tk)[15];								\
	SWAPMOVE(state[1], state[2], 0x55555555, 0);		\
	state[3] ^= (state[0] | state[1]);					\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	state[1] ^= ~(state[2] | state[3]);					\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	state[1] ^= ~(state[2] | state[3]); 				\
	inv_mixcolumns_2(state); 							\
	state[0] ^= (tk)[8];								\
	state[1] ^= (tk)[9];								\
	state[2] ^= (tk)[10];								\
	state[3] ^= (tk)[11];								\
	SWAPMOVE(state[3], state[0], 0x55555555, 0);		\
	state[1] ^= (state[2] | state[3]);					\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	state[1] ^= ~(state[2] | state[3]);					\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	state[3] ^= ~(state[0] | state[1]);					\
	inv_mixcolumns_1(state); 							\
	state[0] ^= (tk)[4];								\
	state[1] ^= (tk)[5];								\
	state[2] ^= (tk)[6];								\
	state[3] ^= (tk)[7];								\
	SWAPMOVE(state[1], state[2], 0x55555555, 0);		\
	state[3] ^= (state[0] | state[1]);					\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	state[1] ^= ~(state[2] | state[3]);					\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	state[1] ^= ~(state[2] | state[3]); 				\
	inv_mixcolumns_0(state); 							\
	state[0] ^= (tk)[0];								\
	state[1] ^= (tk)[1];								\
	state[2] ^= (tk)[2];								\
	state[3] ^= (tk)[3];								\
	SWAPMOVE(state[3], state[0], 0x55555555, 0);		\
	state[1] ^= (state[2] | state[3]);					\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	state[3] ^= ~(state[0] | state[1]);					\
	SWAPMOVE(state[0], state[3], 0x55555555, 1);		\
	SWAPMOVE(state[1], state[0], 0x55555555, 1);		\
	state[1] ^= ~(state[2] | state[3]);					\
	SWAPMOVE(state[3], state[2], 0x55555555, 1);		\
	SWAPMOVE(state[2], state[1], 0x55555555, 1);		\
	state[3] ^= ~(state[0] | state[1]);					\
})

#endif  // SKINNY128_H_
