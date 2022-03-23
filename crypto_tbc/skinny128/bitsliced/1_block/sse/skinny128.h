#ifndef SKINNY128_H_
#define SKINNY128_H_

#include "tk_schedule.h"

#define SKINNY128_128_ROUNDS 		40
#define SKINNY128_256_ROUNDS 		48
#define SKINNY128_384_ROUNDS 		56
#define SKINNY128_384_PLUS_ROUNDS 	SKINNY128_128_ROUNDS

void skinny128_128(uint8_t* out, const uint8_t* in, const tweakey* tk);
void skinny128_256(uint8_t* out, const uint8_t* in, const tweakey* tk);
void skinny128_384(uint8_t* out, const uint8_t* in, const tweakey* tk);
void skinny128_384_plus(uint8_t* out, const uint8_t* in, const tweakey* tk);

#endif  // SKINNY128_H_