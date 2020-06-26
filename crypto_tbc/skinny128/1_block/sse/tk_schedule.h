#ifndef TK_SCHEDULE_H_
#define TK_SCHEDULE_H_

#include <stdint.h>
#include "immintrin.h"

typedef struct {
	uint8_t tk1[16];
	uint8_t tk2[16];
	uint8_t tk3[16];
} tweakey;

void precompute_rtk(__m128i* rtk, const tweakey* tk, int rounds);
void precompute_rtk_plus(__m128i* rtk, const tweakey* tk);

#endif  // TK_SCHEDULE_H_