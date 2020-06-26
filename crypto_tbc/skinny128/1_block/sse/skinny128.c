/******************************************************************************
* Constant-time implementation of SKINNY-128 tweakable block ciphers using
* SSE instructions.
* This code aims at providing an efficient implementation of SKINNY-128 when
* processing a single block at once (i.e. for operation modes without
* parallelism such as Romulus) on CPUs that enjoy SIMD instructions.
*
* @author 	Alexandre Adomnicai, Nanyang Technological University, Singapore
* 			alexandre.adomnicai@ntu.edu.sg
*
* @date 	June 2020
******************************************************************************/
#include <string.h>
#include "skinny128.h"

// masks for fixsliced MixColumns
#define MASK_0 	_mm_set_epi32(0x80808080, 0x01000302, 0x0a09080b, 0x80808080)
#define MASK_1 	_mm_set_epi32(0x080b0a09, 0x80808080, 0x80808080, 0x80808080)
#define MASK_2 	_mm_set_epi32(0x80808080, 0x80808080, 0x0f0e0d0c, 0x05040706)
#define MASK_3 	_mm_set_epi32(0x80808080, 0x05040706, 0x80808080, 0x80808080)
#define MASK_4 	_mm_set_epi32(0x00030201, 0x80808080, 0x80808080, 0x09080b0a)
#define MASK_5 	_mm_set_epi32(0x80808080, 0x80808080, 0x02010003, 0x80808080)
#define MASK_6 	_mm_set_epi32(0x07060504, 0x0f0e0d0c, 0x80808080, 0x80808080)
#define MASK_7 	_mm_set_epi32(0x80808080, 0x80808080, 0x80808080, 0x0f0e0d0c)

// permutation to match the inner-fixsliced sbox representation
#define IN_PERMUTATION(x) ({									\
	tmp0 = _mm_and_si128(x, _mm_set1_epi32(0x03030303));		\
	tmp0 = _mm_slli_epi32(tmp0, 2);								\
	tmp1 = _mm_and_si128(x, _mm_set1_epi32(0x10101010));		\
	tmp0 = _mm_or_si128(tmp0, _mm_slli_epi32(tmp1, 3));			\
	tmp1 = _mm_and_si128(x, _mm_set1_epi32(0x0c0c0c0c));		\
	tmp0 = _mm_or_si128(tmp0, _mm_srli_epi32(tmp1, 2));			\
	tmp1 = _mm_and_si128(x, _mm_set1_epi32(0xe0e0e0e0));		\
	(x) = _mm_or_si128(tmp0, _mm_srli_epi32(tmp1, 1));			\
}) 

// inverse permutation of 'IN_PERMUTATION'
#define OUT_PERMUTATION(x) ({									\
	tmp0 = _mm_and_si128(x, _mm_set1_epi32(0x70707070));		\
	tmp0 = _mm_slli_epi32(tmp0, 1);								\
	tmp1 = _mm_and_si128(x, _mm_set1_epi32(0x03030303));		\
	tmp0 = _mm_or_si128(tmp0, _mm_slli_epi32(tmp1, 2));			\
	tmp1 = _mm_and_si128(x, _mm_set1_epi32(0x80808080));		\
	tmp0 = _mm_or_si128(tmp0, _mm_srli_epi32(tmp1, 3));			\
	tmp1 = _mm_and_si128(x, _mm_set1_epi32(0x0c0c0c0c));		\
	(x) = _mm_or_si128(tmp0, _mm_srli_epi32(tmp1, 2));			\
})

// 1st sbox according to the inner-fixsliced representation
#define SBOX_0(x) ({											\
	tmp0 	= _mm_and_si128(x, _mm_srli_epi32(x, 1));			\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x21212121));	\
	(x) 	= _mm_xor_si128(x, _mm_slli_epi32(tmp0, 2));		\
	tmp0 	= _mm_and_si128(x, _mm_set1_epi32(0xfefefefe));		\
	tmp0 	= _mm_srli_epi32(tmp0, 1);							\
	tmp1 	= _mm_and_si128(x, _mm_set1_epi32(0x01010101));		\
	tmp0 	= _mm_or_si128(tmp0, _mm_slli_epi32(tmp1, 7));		\
	tmp0 	= _mm_and_si128(tmp0, _mm_srli_epi32(tmp0, 5));		\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x06060606));	\
	(x)		= _mm_xor_si128(x, _mm_slli_epi32(tmp0, 3));		\
	tmp0 	= _mm_and_si128(x, _mm_srli_epi32(x, 1));			\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x12121212));	\
	(x) 	= _mm_xor_si128(x, _mm_slli_epi32(tmp0, 2));		\
	tmp0 	= _mm_and_si128(x, _mm_srli_epi32(x, 3));			\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x18181818));	\
	(x) 	= _mm_xor_si128(x, _mm_srli_epi32(tmp0, 3));		\
	tmp0 	= _mm_and_si128(x, _mm_set1_epi32(0x9f9f9f9f));		\
	tmp1 	= _mm_and_si128(x, _mm_set1_epi32(0x40404040));		\
	tmp0 	= _mm_or_si128(tmp0, _mm_srli_epi32(tmp1, 1));		\
	tmp1 	= _mm_and_si128(x, _mm_set1_epi32(0x20202020));		\
	(x) 	= _mm_or_si128(tmp0, _mm_slli_epi32(tmp1, 1));		\
})

// 2nd sbox according to the inner-fixsliced representation
#define SBOX_1(x) ({											\
	tmp0 	= _mm_and_si128(x, _mm_srli_epi32(x, 3));			\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x18181818));	\
	(x) 	= _mm_xor_si128(x, _mm_srli_epi32(tmp0, 3));		\
	tmp0 	= _mm_and_si128(x, _mm_srli_epi32(x, 1));			\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x21212121));	\
	(x) 	= _mm_xor_si128(x, _mm_slli_epi32(tmp0, 2));		\
	tmp0 	= _mm_and_si128(x, _mm_set1_epi32(0xfefefefe));		\
	tmp0 	= _mm_srli_epi32(tmp0, 1);							\
	tmp1 	= _mm_and_si128(x, _mm_set1_epi32(0x01010101));		\
	tmp0 	= _mm_or_si128(tmp0, _mm_slli_epi32(tmp1, 7));		\
	tmp0 	= _mm_and_si128(tmp0, _mm_srli_epi32(tmp0, 5));		\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x06060606));	\
	(x)		= _mm_xor_si128(x, _mm_slli_epi32(tmp0, 3));		\
	tmp0 	= _mm_and_si128(x, _mm_srli_epi32(x, 1));			\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x12121212));	\
	(x) 	= _mm_xor_si128(x, _mm_slli_epi32(tmp0, 2));		\
	tmp0 	= _mm_and_si128(x, _mm_set1_epi32(0x6f6f6f6f));		\
	tmp1 	= _mm_and_si128(x, _mm_set1_epi32(0x80808080));		\
	tmp0 	= _mm_or_si128(tmp0, _mm_srli_epi32(tmp1, 3));		\
	tmp1 	= _mm_and_si128(x, _mm_set1_epi32(0x10101010));		\
	(x) 	= _mm_or_si128(tmp0, _mm_slli_epi32(tmp1, 3));		\
})

// 3rd sbox according to the inner-fixsliced representation
#define SBOX_2(x) ({											\
	tmp0 	= _mm_and_si128(x, _mm_srli_epi32(x, 1));			\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x12121212));	\
	(x) 	= _mm_xor_si128(x, _mm_slli_epi32(tmp0, 2));		\
	tmp0 	= _mm_and_si128(x, _mm_srli_epi32(x, 3));			\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x18181818));	\
	(x) 	= _mm_xor_si128(x, _mm_srli_epi32(tmp0, 3));		\
	tmp0 	= _mm_and_si128(x, _mm_srli_epi32(x, 1));			\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x21212121));	\
	(x) 	= _mm_xor_si128(x, _mm_slli_epi32(tmp0, 2));		\
	tmp0 	= _mm_and_si128(x, _mm_set1_epi32(0xfefefefe));		\
	tmp0 	= _mm_srli_epi32(tmp0, 1);							\
	tmp1 	= _mm_and_si128(x, _mm_set1_epi32(0x01010101));		\
	tmp0 	= _mm_or_si128(tmp0, _mm_slli_epi32(tmp1, 7));		\
	tmp0 	= _mm_and_si128(tmp0, _mm_srli_epi32(tmp0, 5));		\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x06060606));	\
	(x)		= _mm_xor_si128(x, _mm_slli_epi32(tmp0, 3));		\
	tmp0 	= _mm_and_si128(x, _mm_set1_epi32(0xf9f9f9f9));		\
	tmp1 	= _mm_and_si128(x, _mm_set1_epi32(0x04040404));		\
	tmp0 	= _mm_or_si128(tmp0, _mm_srli_epi32(tmp1, 1));		\
	tmp1 	= _mm_and_si128(x, _mm_set1_epi32(0x02020202));		\
	(x) 	= _mm_or_si128(tmp0, _mm_slli_epi32(tmp1, 1));		\
})

// 4th sbox according to the inner-fixsliced representation
#define SBOX_3(x) ({ 											\
	tmp0 	= _mm_and_si128(x, _mm_set1_epi32(0xfefefefe));		\
	tmp0 	= _mm_srli_epi32(tmp0, 1);							\
	tmp1 	= _mm_and_si128(x, _mm_set1_epi32(0x01010101));		\
	tmp0 	= _mm_or_si128(tmp0, _mm_slli_epi32(tmp1, 7));		\
	tmp0 	= _mm_and_si128(tmp0, _mm_srli_epi32(tmp0, 5));		\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x06060606));	\
	(x) 	= _mm_xor_si128(x, _mm_slli_epi32(tmp0, 3));		\
	tmp0 	= _mm_and_si128(x, _mm_srli_epi32(x, 1));			\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x12121212));	\
	(x) 	= _mm_xor_si128(x, _mm_slli_epi32(tmp0, 2));		\
	tmp0 	= _mm_and_si128(x, _mm_srli_epi32(x, 3));			\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x18181818));	\
	(x) 	= _mm_xor_si128(x, _mm_srli_epi32(tmp0, 3));		\
	tmp0 	= _mm_and_si128(x, _mm_srli_epi32(x, 1));			\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x21212121));	\
	(x) 	= _mm_xor_si128(x, _mm_slli_epi32(tmp0, 2));		\
	tmp0 	= _mm_and_si128(x, _mm_set1_epi32(0xf6f6f6f6));		\
	tmp1 	= _mm_and_si128(x, _mm_set1_epi32(0x08080808));		\
	tmp0 	= _mm_or_si128(tmp0, _mm_srli_epi32(tmp1, 3));		\
	tmp1 	= _mm_and_si128(x, _mm_set1_epi32(0x01010101));		\
	(x) 	= _mm_or_si128(tmp0, _mm_slli_epi32(tmp1, 3));		\
})

// MixColumns (the row permutation is omitted)
#define MIXCOLUMNS(x, m0, m1) ({								\
	(x) = _mm_xor_si128(x, _mm_shuffle_epi8(x, m0));			\
	(x)	= _mm_xor_si128(x, _mm_shuffle_epi8(x, m1));			\
})

// Add round tweakey (includes the rconsts and NOTs for the Sbox)
#define ADDROUNDTWEAKEY(x, rtk) ((x) = _mm_xor_si128(x, (rtk)))

// Quadruple round routine
#define QUADRUPLE_ROUND(x, rtk) ({								\
	SBOX_0(x);													\
	ADDROUNDTWEAKEY(x, *(rtk));									\
	MIXCOLUMNS(x,  MASK_0, MASK_1);								\
	SBOX_1(x);													\
	ADDROUNDTWEAKEY(x, *(rtk+1));								\
	MIXCOLUMNS(x,  MASK_2, MASK_3);								\
	SBOX_2(x);													\
	ADDROUNDTWEAKEY(x, *(rtk+2));								\
	MIXCOLUMNS(x, MASK_4, MASK_5);								\
	SBOX_3(x);													\
	ADDROUNDTWEAKEY(x, *(rtk+3));								\
	MIXCOLUMNS(x, MASK_6, MASK_7);								\
})

/******************************************************************************
* Core function for SKINNY128 encryption.
* Note that the main loop relies on a quadruple round routine. Even though the
* bit ordering within bytes loop every 8 rounds, the permutations to apply are
* the same every 4 rounds.
* To enjoy the inner-fixslice Sbox representation, a bit permutation has to be
* applied on every byte at the beginning and at the end of the function.
******************************************************************************/
void core_skinny128_enc(uint8_t* out, const uint8_t* in,
				const __m128i* rtk, int rounds) {
	// load the 16-byte input in a 128-bit register
	__m128i tmp0, tmp1, state = _mm_loadu_si128((__m128i*)in);
	// apply a permutation on the state to enhance Sboxes calculations
	IN_PERMUTATION(state);
	// negates the whole state for Sbox computations
	// only done at start, then NOT are performed within ARTK operations
	state = _mm_xor_si128(state, _mm_set1_epi32(0xffffffff));
	// core routine relies on quadruple rounds
	for(int i = 0; i < rounds; i += 4)
		QUADRUPLE_ROUND(state, rtk+i);
	// apply a permutation to match the expected output representation
	OUT_PERMUTATION(state);
	// store the 128-bit state register at the output address
	_mm_storeu_si128((__m128i*)out, state);
}

/******************************************************************************
* Encryption of a single block using SKINNY-128-128 without any operation mode.
******************************************************************************/
void skinny128_128_enc(uint8_t* out, const uint8_t* in, const tweakey* tk) {
  	__m128i rtk[SKINNY128_128_ROUNDS];
    precompute_rtk(rtk, tk, SKINNY128_128_ROUNDS);
    core_skinny128_enc(out, in, rtk, SKINNY128_128_ROUNDS);
}

/******************************************************************************
* Encryption of a single block using SKINNY-128-256 without any operation mode.
******************************************************************************/
void skinny128_256_enc(uint8_t* out, const uint8_t* in, const tweakey* tk) {
  	__m128i rtk[SKINNY128_256_ROUNDS];
    precompute_rtk(rtk, tk, SKINNY128_256_ROUNDS);
    core_skinny128_enc(out, in, rtk, SKINNY128_256_ROUNDS);
}

/******************************************************************************
* Encryption of a single block using SKINNY-128-384 without any operation mode.
******************************************************************************/
void skinny128_384_enc(uint8_t* out, const uint8_t* in, const tweakey* tk) {
  	__m128i rtk[SKINNY128_384_ROUNDS];
    precompute_rtk(rtk, tk, SKINNY128_384_ROUNDS);
    core_skinny128_enc(out, in, rtk, SKINNY128_384_ROUNDS);
}

/******************************************************************************
* Encryption of a single block using SKINNY-128-384+ without any operation mode.
******************************************************************************/
void skinny128_384_plus_enc(uint8_t* out, const uint8_t* in, const tweakey* tk) {
  	__m128i rtk[SKINNY128_384_PLUS_ROUNDS];
    precompute_rtk_plus(rtk, tk);
    core_skinny128_enc(out, in, rtk, SKINNY128_384_PLUS_ROUNDS);
}
