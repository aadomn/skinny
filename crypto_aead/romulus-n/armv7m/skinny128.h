#ifndef SKINNY128_H_
#define SKINNY128_H_

#include <stdint.h>

#define SKINNY128_384_ROUNDS    40
#define TWEAKEYBYTES            16
#define BLOCKBYTES              16
#define TKPERMORDER             16

/**
 * Apply Skinny-128-384+ to an input block 'in' and store the result into the
 * output block 'out'.
 * 
 * Round tweakeys are expected to be precomputed and divided into two distinct
 * arrays:
 *      - 'rtk_2_3' which contains rtk2 ^ rtk3 ^ rconsts for all rounds
 *      - 'rtk1' which contains rtk1 for 16 rounds only (loop over 16 rounds)
 */
extern void skinny128_384_plus(
    uint8_t out[BLOCKBYTES],
    const uint8_t in[BLOCKBYTES],
    const uint8_t rtk_1[TKPERMORDER*BLOCKBYTES/2],
    const uint8_t rtk2_3[SKINNY128_384_ROUNDS*BLOCKBYTES]
);

/**
 * Precomputes LFSR2(tk2) ^ LFSR3(tk3) for a given number of rounds.
 * 
 * Output round tweakeys are in fixsliced representation.
 */
extern void tks_lfsr_23(
    uint8_t rtk_23[SKINNY128_384_ROUNDS*BLOCKBYTES],
    const uint8_t tk_2[TWEAKEYBYTES],
    const uint8_t tk_3[TWEAKEYBYTES],
    const int rounds
);

/**
 * Apply the tweakey permutation to round tweakeys for 40 rounds.
 * 
 * Input/output round tweakeys are expected to be in fixsliced representation.
 */
extern void tks_perm_23(
    uint8_t rtk_23[SKINNY128_384_ROUNDS*BLOCKBYTES]
);

/**
 * Apply the tweakey permutation to round tweakeys for 16 rounds.
 * Because half of TK1 is always null in Romulus-N, rtk1 only contains half
 * round tweakey material to save some CPU cycles.
 * 
 * Input tk1 is expected to be in byte-wise representation while output round
 * tweakeys are in fixsliced representation.
 */
extern void tk_schedule_1(
    uint8_t rtk_1[TKPERMORDER*BLOCKBYTES/2],
    const uint8_t tk_1[TWEAKEYBYTES]
);

/**
 * Calculation of round tweakeys related to TK1, TK2 and TK3 (full TK schedule)
 */
inline void tk_schedule_23(
    uint8_t rtk_23[SKINNY128_384_ROUNDS*BLOCKBYTES],
    const uint8_t tk_2[TWEAKEYBYTES],
    const uint8_t tk_3[TWEAKEYBYTES])
{
    tks_lfsr_23(rtk_23, tk_2, tk_3, SKINNY128_384_ROUNDS);
    tks_perm_23(rtk_23);
};

/**
 * Calculation of round tweakeys related to TK1, TK2 and TK3 (full TK schedule)
 */
inline void tk_schedule_123(
    uint8_t rtk_1[TKPERMORDER*BLOCKBYTES/2],
    uint8_t rtk_23[SKINNY128_384_ROUNDS*BLOCKBYTES],
    const uint8_t tk_1[TWEAKEYBYTES],
    const uint8_t tk_2[TWEAKEYBYTES],
    const uint8_t tk_3[TWEAKEYBYTES])
{
    tks_schedule_1(rtk_1, tk_1);
    tks_lfsr_23(rtk_23, tk_2, tk_3, SKINNY128_384_ROUNDS);
    tks_perm_23(rtk_23);
};

#endif  // SKINNY128_H_
