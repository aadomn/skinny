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
#include "skinny128.h"

// compute x = LFSR2(y) on all bytes within y
#define LFSR2(x, y) ({ 											\
	tmp0 	= _mm_slli_epi32((y), 2);							\
	tmp0 	= _mm_xor_si128(tmp0, (y)); 						\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x80808080));	\
	tmp0 	= _mm_srli_epi32(tmp0, 7); 							\
	(x) 	= _mm_add_epi8((y), (y)); 							\
	(x) 	= _mm_or_si128((x), tmp0); 							\
})

// compute x = LFSR3(y) on all bytes within y
#define LFSR3(x, y) ({ 											\
	tmp0 	= _mm_srli_epi32((y), 6);							\
	tmp0 	= _mm_xor_si128(tmp0, (y)); 						\
	tmp0 	= _mm_and_si128(tmp0, _mm_set1_epi32(0x01010101));	\
	tmp0 	= _mm_slli_epi32(tmp0, 7); 							\
	(x) 	= _mm_srli_epi32((y), 1); 							\
	(x) 	= _mm_and_si128((x), _mm_set1_epi32(0x7f7f7f7f));	\
	(x) 	= _mm_or_si128((x), tmp0); 							\
})

// _m128i masks to apply the tweakey schedule permutation
#define PERM_1 	_mm_set_epi32(0x0e0d0c0f, 0x0b0a0908, 0x07060504, 0x03020100)
#define PERM_2 	_mm_set_epi32(0x0b0c0e0a, 0x080f090d, 0x04060203, 0x01050007)
#define PERM_4 	_mm_set_epi32(0x080d0a0c, 0x0b0f0e09, 0x04000502, 0x03070601)
#define PERM_6 	_mm_set_epi32(0x0a090e08, 0x0b0c0f0d, 0x01060002, 0x07050304)
#define PERM_8 	_mm_set_epi32(0x09080f0c, 0x0a0b0e0d, 0x04010007, 0x02030605)
#define PERM_10 _mm_set_epi32(0x0a0f090b, 0x0d0c0e08, 0x07010302, 0x06000504)
#define PERM_12 _mm_set_epi32(0x0d080b0f, 0x0a0c090e, 0x07050003, 0x02040106)
#define PERM_14 _mm_set_epi32(0x0b0e090d, 0x0a0f0c08, 0x06010503, 0x04000207)

// _m128i masks to extract half of the tweakey state
#define MASK_0 	_mm_set_epi32(0x00000000, 0x00000000, 0xffffffff, 0xffffffff)
#define MASK_1 	_mm_set_epi32(0xffffffff, 0xffffffff, 0x00000000, 0x00000000)

// _m128i masks to integrate the rconsts and the NOT (for Sbox) within the tweakeys at round i
#define RC_0(i) _mm_set_epi32(0xffffffff, 0xfffffffd, rc[i] >> 4, rc[i] & 0x0f)
#define RC_1(i)	_mm_set_epi32((rc[i] & 0xf) << 8, 0xffffffff, 0xfdffffff, rc[i] >> 4)
#define RC_2(i)	_mm_set_epi32((rc[i] & 0xf0) << 4, (rc[i] & 0xf) << 24, 0xffffffff, 0xfdffffff)
#define RC_3(i) _mm_set_epi32(0xfffffffd, (rc[i] & 0xf0) << 20, (rc[i] & 0xf) << 16, 0xffffffff)
#define RC_4(i) _mm_set_epi32(0xffffffff, 0xfffdffff, (rc[i] & 0xf0) << 12, (rc[i] & 0xf) << 16)
#define RC_5(i) _mm_set_epi32((rc[i] & 0xf) << 24, 0xffffffff, 0xfffffdff, (rc[i] & 0xf0) << 12)
#define RC_6(i) _mm_set_epi32((rc[i] & 0xf0) << 20, (rc[i] & 0x0f) << 8, 0xffffffff, 0xfffffdff)
#define RC_7(i) _mm_set_epi32(0xfffdffff, (rc[i] & 0xf0) << 4, rc[i] & 0x0f, 0xffffffff)

// the Skinny round constants
static uint8_t rc[56] = {
	0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B,
	0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E,
	0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30,
	0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38,
	0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
	0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04,
	0x09, 0x13, 0x26, 0x0C, 0x19, 0x32, 0x25, 0x0A};

/******************************************************************************
* Precompute all values for LFSR2(TK2) and put the results into the round
* tweakey array.
* Note that the LFSR is always applied on the entire state and therefore half 
* of the round tweakey array is empty.
******************************************************************************/
static void precompute_lfsr_tk2(__m128i* rtk, const unsigned char* tk2, const int rounds) {
	__m128i tmp0;
	rtk[0] = _mm_loadu_si128((__m128i*)tk2);
	LFSR2(rtk[1], rtk[0]);
	for(int i = 3; i < rounds; i+=2)
		LFSR2(rtk[i], rtk[i-2]);
}

/******************************************************************************
* Precompute all values for LFSR3(TK3) and XOR the results with LFSR2(TK2) 
* values contained in the round tweakey array. 
* Note that the LFSR is always applied on the entire state and therefore half 
* of the round tweakey array is empty.
******************************************************************************/
static void precompute_lfsr_tk3(__m128i* rtk, const unsigned char* tk3, const int rounds) {
	__m128i tmp0, rtk3_new, rtk3_old;
	rtk3_old = _mm_loadu_si128((__m128i*)tk3);
	rtk[0] = _mm_xor_si128(rtk[0], rtk3_old);
	for(int i = 1; i < rounds; i+=4) {
		LFSR3(rtk3_new, rtk3_old);
		rtk[i] = _mm_xor_si128(rtk[i], rtk3_new);
		LFSR3(rtk3_old, rtk3_new);
		rtk[i+2] = _mm_xor_si128(rtk[i+2], rtk3_old);
	}
}

/******************************************************************************
* Byte-wise bit permutation to be applied on round tweakeys for rounds i s.t.
* i % 4 = 0.
* In the classical representation, during the add round tweakey in such rounds
* we have:
* 			c  d  h  e  g  b  a  f 		<- state bits (byte-wise)
* 					XOR
* 			a  b  c  d  e  f  g  h 		<- round tweakey bits (byte-wise)
* However because the bit ordering is changed to enjoy the inner-fixsliced
* representation, we now have:
* 			d  b  a  c  g  h  e  f 		<- state bits (byte-wise)
* 					XOR
* 			b  f  g  a  e  c  d  h 		<- round tweakey bits (byte-wise)
******************************************************************************/
static inline __m128i perm_bits_0(__m128i x) {
	__m128i res, tmp;
	res = _mm_and_si128(x, _mm_set1_epi32(0x09090909));
	tmp = _mm_and_si128(x, _mm_set1_epi32(0x40404040));
	res = _mm_or_si128(res, _mm_slli_epi32(tmp, 1));
	tmp = _mm_and_si128(x, _mm_set1_epi32(0x06060606));
	res = _mm_or_si128(res, _mm_slli_epi32(tmp, 4));
	tmp = _mm_and_si128(x, _mm_set1_epi32(0xb0b0b0b0));
	res = _mm_or_si128(res, _mm_srli_epi32(tmp, 3));
	return res;
}

/******************************************************************************
* Byte-wise bit permutation to be applied on round tweakeys for rounds i s.t.
* i % 4 = 1.
* In the classical representation, during the add round tweakey in such rounds
* we have:
* 			h  e  f  g  a  d  c  b 		<- state bits (byte-wise)
* 					XOR
* 			a  b  c  d  e  f  g  h 		<- round tweakey bits (byte-wise)
* However because the bit ordering is changed to enjoy the inner-fixsliced
* representation, we now have:
* 			c  b  a  d  g  h  e  f 		<- state bits (byte-wise)
* 					XOR
* 			g  h  e  f  d  a  b  c 		<- round tweakey bits (byte-wise)
******************************************************************************/
static inline __m128i perm_bits_1(__m128i x) {
	__m128i res, tmp;
	res = _mm_and_si128(x, _mm_set1_epi32(0x0c0c0c0c));
	tmp = _mm_and_si128(x, _mm_set1_epi32(0x03030303));
	res = _mm_or_si128(_mm_slli_epi32(res, 2), _mm_slli_epi32(tmp, 6));
	tmp = _mm_and_si128(x, _mm_set1_epi32(0xe0e0e0e0));
	res = _mm_or_si128(res, _mm_srli_epi32(tmp, 5));
	tmp = _mm_and_si128(x, _mm_set1_epi32(0x10101010));
	res = _mm_or_si128(res, _mm_srli_epi32(tmp, 1));
	return res;
}

/******************************************************************************
* Byte-wise bit permutation to be applied on round tweakeys for rounds i s.t.
* i % 4 = 2.
* In the classical representation, during the add round tweakey in such rounds
* we have:
* 			f  g  b  a  c  e  h  d 		<- state bits (byte-wise)
* 					XOR
* 			a  b  c  d  e  f  g  h 		<- round tweakey bits (byte-wise)
* However because the bit ordering is changed to enjoy the inner-fixsliced
* representation, we now have:
* 			c  b  a  d  g  e  h  f 		<- state bits (byte-wise)
* 					XOR
* 			e  c  d  h  b  f  g  a 		<- round tweakey bits (byte-wise)
******************************************************************************/
static inline __m128i perm_bits_2(__m128i x) {
	__m128i res, tmp;
	res = _mm_and_si128(x, _mm_set1_epi32(0x06060606));
	tmp = _mm_and_si128(x, _mm_set1_epi32(0x30303030));
	res = _mm_or_si128(res, _mm_slli_epi32(tmp, 1));
	tmp = _mm_and_si128(x, _mm_set1_epi32(0x09090909));
	res = _mm_or_si128(res, _mm_slli_epi32(tmp, 4));
	tmp = _mm_and_si128(x, _mm_set1_epi32(0x80808080));
	res = _mm_or_si128(res, _mm_srli_epi32(tmp, 7));
	tmp = _mm_and_si128(x, _mm_set1_epi32(0x40404040));
	res = _mm_or_si128(res, _mm_srli_epi32(tmp, 3));
	return res;
}

/******************************************************************************
* Byte-wise bit permutation to be applied on round tweakeys for rounds i s.t.
* i % 4 = 3.
* In the classical representation, during the add round tweakey in such rounds
* we have:
* 			b  a  d  c  h  g  f  e 		<- state bits (byte-wise)
* 					XOR
* 			a  b  c  d  e  f  g  h 		<- round tweakey bits (byte-wise)
* However because the bit ordering is changed to enjoy the inner-fixsliced
* representation, we now have:
* 			c  b  a  d  f  e  h  g 		<- state bits (byte-wise)
* 					XOR
* 			e  c  d  h  b  f  g  a 		<- round tweakey bits (byte-wise)
******************************************************************************/
static inline __m128i perm_bits_3(__m128i x) {
	__m128i res, tmp;
	res = _mm_and_si128(x, _mm_set1_epi32(0x03030303));
	tmp = _mm_and_si128(x, _mm_set1_epi32(0x10101010));
	res = _mm_or_si128(_mm_slli_epi32(res, 2), _mm_slli_epi32(tmp, 3));
	tmp = _mm_and_si128(x, _mm_set1_epi32(0x0c0c0c0c));
	res = _mm_or_si128(res, _mm_srli_epi32(tmp, 2));
	tmp = _mm_and_si128(x, _mm_set1_epi32(0xe0e0e0e0));
	res = _mm_or_si128(res, _mm_srli_epi32(tmp, 1));
	return res;
}

/******************************************************************************
* Apply the tweakey permutation on all round tweakeys.
* Take as input LFSR2(TK2) ^ LFSR3(TK3) and TK1 and returns
* P(LFSR2(TK2) ^ LFSR3(TK3) ^ TK1).
* Round constants and NOTs for Sbox calculations are also integrated within the
* round tweakey to speed up the SKINNY-128 core routine execution.
******************************************************************************/
static void permute_rtk(__m128i* rtk, const unsigned char* tk1, const int rounds) {
	int test;
	__m128i tmp0, tmp1, rtk1;
	rtk1 	= _mm_loadu_si128((__m128i*)tk1);
	tmp0 	= _mm_xor_si128(rtk[0], rtk1); 					// XOR TK1 to LFSR2(TK2) ^ LFSR3(TK3)
	for(int i = 0; i < rounds; i+=8) {
		test 		= (i % 16 < 8) ? 1 : 0; 				// var to apply the right power of P
		rtk[i] 		= _mm_and_si128(tmp0, MASK_0); 			// extract half of the tk state 
		rtk[i]  	= _mm_xor_si128(rtk[i], RC_0(i)); 		// add the rconst and NOT for the Sbox
		rtk[i] 		= perm_bits_0(rtk[i]); 					// 8-bit permutation to match inner-fixslicing
		rtk[i+1] 	= _mm_xor_si128(rtk[i+1], rtk1); 		// XOR TK1 to LFSR2(TK2) ^ LFSR3(TK3) 
		if (test)
			tmp0 	= _mm_shuffle_epi8(rtk[i+1], PERM_2); 	// apply P^2 to TK1 ^ LFSR2(TK2) ^ LFSR3(TK3) 
		else
			tmp0 	= _mm_shuffle_epi8(rtk[i+1], PERM_10); 	// apply P^10 to TK1 ^ LFSR2(TK2) ^ LFSR3(TK3) 
		rtk[i+1]  	= _mm_and_si128(tmp0, MASK_1); 			// only extract half of the tk state 
		tmp1 		= _mm_srli_si128(rtk[i+1], 12); 		// 32-bit words reordering to match fixslicing
		rtk[i+1] 	= _mm_slli_si128(rtk[i+1], 4); 			// 32-bit words reordering to match fixslicing
		rtk[i+1] 	= _mm_or_si128(rtk[i+1], tmp1); 		// 32-bit words reordering to match fixslicing
		rtk[i+1]  	= _mm_xor_si128(rtk[i+1], RC_1(i+1));  	// add the rconst and NOTs for the Sbox
		rtk[i+1] 	= perm_bits_1(rtk[i+1]); 				// 8-bit permutation to match inner-fixslicing
		rtk[i+2] 	= _mm_and_si128(tmp0, MASK_0); 			// extract half of the tk state 
		rtk[i+2] 	= _mm_slli_si128(rtk[i+2], 8); 			// 32-bit words reordering to match fixslicing
		rtk[i+2]  	= _mm_xor_si128(rtk[i+2], RC_2(i+2));  	// add the rconst and NOTs for the Sbox
		rtk[i+2] 	= perm_bits_2(rtk[i+2]); 				// 8-bit permutation to match inner-fixslicing
		rtk[i+3] 	= _mm_xor_si128(rtk[i+3], rtk1); 		// XOR TK1 to LFSR2(TK2) ^ LFSR3(TK3)
		if (test)
			tmp0 	= _mm_shuffle_epi8(rtk[i+3], PERM_4);	// apply P^4 to TK1 ^ LFSR2(TK2) ^ LFSR3(TK3)
		else
			tmp0 	= _mm_shuffle_epi8(rtk[i+3], PERM_12);	// apply P^12 to TK1 ^ LFSR2(TK2) ^ LFSR3(TK3)
		rtk[i+3]  	= _mm_and_si128(tmp0, MASK_1); 			// extract half of the tk state 
		rtk[i+3] 	= _mm_srli_si128(rtk[i+3], 4); 			// 32-bit words reordering to match fixslicing
		rtk[i+3]  	= _mm_xor_si128(rtk[i+3], RC_3(i+3));  	// add the rconst and NOTs for the Sbox
		rtk[i+3] 	= perm_bits_3(rtk[i+3]); 				// 8-bit permutation to match inner-fixslicing
		rtk[i+4] 	= _mm_and_si128(tmp0, MASK_0); 			// extract half of the tk state 
		rtk[i+4]  	= _mm_xor_si128(rtk[i+4], RC_4(i+4));  	// add the rconst and NOTs for the Sbox
		rtk[i+4] 	= perm_bits_0(rtk[i+4]); 				// 8-bit permutation to match inner-fixslicing
		rtk[i+5] 	= _mm_xor_si128(rtk[i+5], rtk1); 		// XOR TK1 to LFSR2(TK2) ^ LFSR3(TK3)
		if (test)
			tmp0 	= _mm_shuffle_epi8(rtk[i+5], PERM_6); 	// apply P^6 to TK1 ^ LFSR2(TK2) ^ LFSR3(TK3)
		else
			tmp0 	= _mm_shuffle_epi8(rtk[i+5], PERM_14); 	// apply P^14 to TK1 ^ LFSR2(TK2) ^ LFSR3(TK3)
		rtk[i+5]  	= _mm_and_si128(tmp0, MASK_1); 			// extract half of the tk state 
		tmp1 		= _mm_srli_si128(rtk[i+5], 12); 		// 32-bit words reordering to match fixslicing
		rtk[i+5] 	= _mm_slli_si128(rtk[i+5], 4); 			// 32-bit words reordering to match fixslicing
		rtk[i+5] 	= _mm_or_si128(rtk[i+5], tmp1); 		// 32-bit words reordering to match fixslicing
		rtk[i+5]  	= _mm_xor_si128(rtk[i+5], RC_5(i+5));  	// add the rconst and NOTs for the Sbox
		rtk[i+5] 	= perm_bits_1(rtk[i+5]); 				// 8-bit permutation to match inner-fixslicing
		rtk[i+6] 	= _mm_and_si128(tmp0, MASK_0); 			// extract half of the tk state 
		rtk[i+6] 	= _mm_slli_si128(rtk[i+6], 8); 			// 32-bit words reordering to match fixslicing
		rtk[i+6]  	= _mm_xor_si128(rtk[i+6], RC_6(i+6));  	// add the rconst and NOTs for the Sbox
		rtk[i+6] 	= perm_bits_2(rtk[i+6]); 				// 8-bit permutation to match inner-fixslicing
		rtk[i+7] 	= _mm_xor_si128(rtk[i+7], rtk1); 		// XOR TK1 to LFSR2(TK2) ^ LFSR3(TK3)
		if (test)
			tmp0 	= _mm_shuffle_epi8(rtk[i+7], PERM_8); 	// apply P^8 to TK1 ^ LFSR2(TK2) ^ LFSR3(TK3)
		else
			tmp0 	= _mm_shuffle_epi8(rtk[i+7], PERM_1); 	// apply dummy permutation for code compliance
		rtk[i+7]  	= _mm_and_si128(tmp0, MASK_1); 			// extract half of the tk state 
		rtk[i+7] 	= _mm_srli_si128(rtk[i+7], 4); 			// 32-bit words reordering to match fixslicing
		rtk[i+7]  	= _mm_xor_si128(rtk[i+7], RC_7(i+7));  	// add the rconst and NOTs for the Sbox
		rtk[i+7] 	= perm_bits_3(rtk[i+7]); 				// 8-bit permutation to match inner-fixslicing
	}
	rtk[rounds-1] = _mm_xor_si128(rtk[rounds-1], _mm_set_epi32(0, 0xffffffff, 0xffffffff, 0));
}

/******************************************************************************
* Precompute all the round tweakeys for SKINNY-128 tweakable block ciphers.
******************************************************************************/
void precompute_rtk(__m128i* rtk, const tweakey* tk, int rounds) {
	for(int i = 0; i < rounds; i++)
		rtk[i] = _mm_set1_epi32(0x00000000);
	if (rounds >= SKINNY128_256_ROUNDS)
		precompute_lfsr_tk2(rtk, tk->tk2, rounds);
	if (rounds == SKINNY128_384_ROUNDS)
		precompute_lfsr_tk3(rtk, tk->tk3, rounds);
	permute_rtk(rtk, tk->tk1, rounds);
}

/******************************************************************************
* Precompute all the round tweakeys for the Skinny128-384-plus version.
******************************************************************************/
void precompute_rtk_plus(__m128i* rtk, const tweakey* tk) {
	precompute_lfsr_tk2(rtk, tk->tk2, SKINNY128_384_PLUS_ROUNDS);
	precompute_lfsr_tk3(rtk, tk->tk3, SKINNY128_384_PLUS_ROUNDS);
	permute_rtk(rtk, tk->tk1, SKINNY128_384_PLUS_ROUNDS);
}
