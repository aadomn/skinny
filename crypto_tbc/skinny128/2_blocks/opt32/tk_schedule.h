#ifndef TK_SCHEDULE_BS_H_
#define TK_SCHEDULE_BS_H_

#include <stdint.h>

typedef uint8_t 	u8;
typedef uint32_t 	u32;

typedef struct {
	u8 tk1[16];
	u8 tk2[16];
	u8 tk3[16];
} tweakey;
	
void packing(u32* out, const u8* in, const u8* in_bis);
void unpacking(u8* out, u8* out_bis, u32 *in);
void precompute_tk(u32* rtk, const tweakey tk, const tweakey tk_bis,
				int rounds);

#define ROR(x,y) (((x) >> (y)) | ((x) << (32 - (y))))

#define LFSR2(tk) ({				\
	tmp = (tk)[0] ^ (tk)[2];		\
	(tk)[0] = (tk)[1]; 				\
	(tk)[1] = (tk)[2];				\
	(tk)[2] = (tk)[3];				\
	(tk)[3] = (tk)[4];				\
	(tk)[4] = (tk)[5];				\
	(tk)[5] = (tk)[6];				\
	(tk)[6] = (tk)[7];				\
	(tk)[7] = tmp;					\
})

#define LFSR3(tk) ({				\
	tmp = (tk)[7] ^ (tk)[1]; 		\
	(tk)[7] = (tk)[6];				\
	(tk)[6] = (tk)[5];				\
	(tk)[5] = (tk)[4];				\
	(tk)[4] = (tk)[3];				\
	(tk)[3] = (tk)[2];				\
	(tk)[2] = (tk)[1];				\
	(tk)[1] = (tk)[0];				\
	(tk)[0] = tmp;					\
})

#define XOR_BLOCKS(x,y) ({ 			\
	(x)[0] ^= (y)[0];				\
	(x)[1] ^= (y)[1];				\
	(x)[2] ^= (y)[2];				\
	(x)[3] ^= (y)[3];				\
	(x)[4] ^= (y)[4];				\
	(x)[5] ^= (y)[5];				\
	(x)[6] ^= (y)[6];				\
	(x)[7] ^= (y)[7];				\
})

#define SWAPMOVE(a, b, mask, n)	({	\
	tmp = (b ^ (a >> n)) & mask;	\
	b ^= tmp;						\
	a ^= (tmp << n);				\
})

#define LE_LOAD(x, y) 				\
	*(x) = (((u32)(y)[3] << 24) | 	\
		((u32)(y)[2] << 16) 	| 	\
		((u32)(y)[1] << 8) 		| 	\
		(y)[0]);

#define LE_STORE(x, y)				\
	(x)[0] = (y) & 0xff; 			\
	(x)[1] = ((y) >> 8) & 0xff; 	\
	(x)[2] = ((y) >> 16) & 0xff; 	\
	(x)[3] = (y) >> 24;

#endif  // TK_SCHEDULE_BS_H_