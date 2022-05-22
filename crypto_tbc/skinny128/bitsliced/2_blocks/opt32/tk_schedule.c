/*******************************************************************************
* Implementation of the tweakey schedule to match the fixsliced representation.
* 
* For more details, see the paper at:
* https://csrc.nist.gov/CSRC/media/Events/lightweight-cryptography-workshop-2020/documents/papers/fixslicing-lwc2020.pdf
*
* @author	Alexandre Adomnicai, Nanyang Technological University,
*			alexandre.adomnicai@ntu.edu.sg
*
* @date		June 2020
*******************************************************************************/
#include <string.h>
#include "skinny128.h"

/****************************************************************************
* The round constants according to the fixsliced representation.
* Instaed of using a look-up table of 448 32-bit words, it can be computed on
* the fly from the rconsts in byte-wise representation:
*
* u8 rconst[56] = {
*    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B,
*    0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E,
*    0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30,
*    0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38,
*    0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
*    0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04,
*    0x09, 0x13, 0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a};
*
* void transp_rconst_8(u32* tk, const int rounds) {
*	u32 tmp;
*	memset(tk, 0x00, 32*rounds);
*	for(int i = 0; i < rounds; i++) {
*		switch (i%8) {
*			case 0:
*				tmp = ((rconst[i] >> 3) & 0x1) << 6; 	//rc3
*				tk[8*i+6] ^= (tmp | (tmp << 1)); 		//rc3||rc3
*				tmp = ((rconst[i] >> 2) & 0x1) << 6; 	//rc2
*				tk[8*i+1] ^= (tmp | (tmp << 1)); 		//rc2||rc2
*				tmp = (((rconst[i] >> 1) & 0x1) << 6); 	//rc1
*				tmp |= ((rconst[i] >> 5) << 4); 		//rc5
*				tmp |= (1 << 2);						//c2
*				tk[8*i] ^= (tmp | (tmp << 1)); 			//rc1||rc1, rc5||rc5, c2||c2
*				tmp = ((rconst[i] & 0x1) << 6); 		//rc0
*				tmp |= (((rconst[i] >> 4) & 0x1) << 4); //rc4
*				tk[8*i+5] ^= (tmp | (tmp << 1)); 		//rc0||rc0, rc4||rc4
*				tk[i*8 + 0] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 1] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 3] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 4] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 6] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 7] ^= 0xffffffff; 				//for SBox calculations
*			break;
*			case 1:
*				tmp = ((rconst[i] >> 3) & 0x1) << 8; 	//rc3
*				tk[8*i] ^= (tmp | (tmp << 1)); 			//rc3||rc3
*				tmp = ((rconst[i] >> 2) & 0x1) << 8; 	//rc2
*				tk[8*i+3] ^= (tmp | (tmp << 1)); 		//rc2||rc2
*				tmp = (((rconst[i] >> 1) & 0x1) << 8); 	//rc1
*				tmp |= ((rconst[i] >> 5) << 6);			//rc5
*				tmp |= (1 << 28); 						//c2
*				tk[8*i+2] ^= (tmp | (tmp << 1)); 		//rc1||rc1, rc5||rc5, c2||c2
*				tmp = ((rconst[i] & 0x1) << 8); 		//rc0
*				tmp |= (((rconst[i] >> 4) & 0x1) << 6); //rc4
*				tk[8*i+1] ^= (tmp | (tmp << 1)); 		//rc0||rc0, rc4||rc4
*				tk[i*8 + 0] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 2] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 3] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 4] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 5] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 6] ^= 0xffffffff; 				//for SBox calculations
*			break;
*			case 2:
*				tmp = ((rconst[i] >> 3) & 0x1) << 26; 	//rc3
*				tk[8*i+2] ^=  (tmp | (tmp << 1)); 		//rc3||rc3
*				tmp = ((rconst[i] >> 2) & 0x1) << 26; 	//rc2
*				tk[8*i+4] ^=  (tmp | (tmp << 1)); 		//rc2||rc2
*				tmp = (((rconst[i] >> 1) & 0x1) << 26);	//rc1
*				tmp |= ((rconst[i] >> 5) << 8);			//rc5
*				tmp |= (1 << 30); 						//c2
*				tk[8*i+7] ^=  (tmp | (tmp << 1)); 		//rc1||rc1, rc5||rc5
*				tmp = ((rconst[i] & 0x1) << 26); 		//rc0
*				tmp |= (((rconst[i] >> 4) & 0x1) << 8); //rc4
*				tk[8*i+3] ^=  (tmp | (tmp << 1)); 		//rc0||rc0, rc4||rc4
*				tk[i*8 + 0] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 1] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 2] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 4] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 6] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 7] ^= 0xffffffff; 				//for SBox calculations
*			break;
*			case 3:
*				tmp = ((rconst[i] >> 3) & 0x1) << 20; 	//rc3
*				tk[8*i+7] ^= (tmp | (tmp << 1)); 		//rc3||rc3
*				tmp = ((rconst[i] >> 2) & 0x1) << 20; 	//rc2
*				tk[8*i+6] ^= (tmp | (tmp << 1)); 		//rc2||rc2
*				tmp = (((rconst[i] >> 1) & 0x1) << 20); //rc1
*				tmp |= ((rconst[i] >> 5) << 26); 		//rc5
*				tmp |= 1; 								//c2
*				tk[8*i+5] ^= (tmp | (tmp << 1)); 		//rc1||rc1, rc5||26
*				tmp = ((rconst[i] & 0x1) << 20) ; 		//rc0
*				tmp |= (((rconst[i] >> 4) & 0x1) << 26);//rc4
*				tk[8*i+4] ^= (tmp | (tmp << 1)); 		//rc0||rc0, rc4||rc4
*				tk[i*8 + 0] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 2] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 3] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 5] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 6] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 7] ^= 0xffffffff; 				//for SBox calculations
*			break;
*			case 4:
*				tmp = ((rconst[i] >> 3) & 0x1) << 22; 	//rc3
*				tk[8*i+6] ^= (tmp | (tmp << 1)); 		//rc3||rc3
*				tmp = ((rconst[i] >> 2) & 0x1) << 22; 	//rc2
*				tk[8*i+1] ^= (tmp | (tmp << 1)); 			//rc2||rc2
*				tmp = (((rconst[i] >> 1) & 0x1) << 22);	//rc1
*				tmp |= ((rconst[i] >> 5) << 20); 		//rc5
*				tmp |= (1 << 18); 						//c2
*				tk[8*i] ^= (tmp | (tmp << 1)); 		//rc1||rc1, rc5||26
*				tmp = ((rconst[i] & 0x1) << 22); 		//rc0
*				tmp |= (((rconst[i] >> 4) & 0x1) << 20);//rc4
*				tk[8*i+5] ^= (tmp | (tmp << 1)); 		//rc0||rc0, rc4||rc4
*				tk[i*8 + 0] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 1] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 3] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 4] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 6] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 7] ^= 0xffffffff; 				//for SBox calculations
*			break;
*			case 5:
*				tmp = ((rconst[i] >> 3) & 0x1) << 24; 	//rc3
*				tk[8*i] |= (tmp | (tmp << 1)); 		//rc3||rc3
*				tmp = ((rconst[i] >> 2) & 0x1) << 24; 	//rc2
*				tk[8*i+3] |= (tmp | (tmp << 1)); 		//rc2||rc2
*				tmp = (((rconst[i] >> 1) & 0x1) << 24); //rc1
*				tmp |= ((rconst[i] >> 5) << 22);		//rc5
*				tmp |= (1 << 12); 						//c2
*				tk[8*i+2] |= (tmp | (tmp << 1)); 		//rc1||rc1, rc5||26
*				tmp = ((rconst[i] & 0x1) << 24);		//rc0
*				tmp |= (((rconst[i] >> 4) & 0x1) << 22);//rc4
*				tk[8*i+1] |= (tmp | (tmp << 1)); 			//rc0||rc0, rc4||rc4
*				tk[i*8 + 0] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 2] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 3] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 4] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 5] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 6] ^= 0xffffffff; 				//for SBox calculations
*			break;
*			case 6:
*				tmp = ((rconst[i] >> 3) & 0x1) << 10; 	//rc3
*				tk[8*i+2] ^= (tmp | (tmp << 1)); 		//rc3||rc3
*				tmp = ((rconst[i] >> 2) & 0x1) << 10; 	//rc2
*				tk[8*i+4] ^= (tmp | (tmp << 1)); 		//rc2||rc2
*				tmp = (((rconst[i] >> 1) & 0x1) << 10);	//rc1
*				tmp |= ((rconst[i] >> 5) << 24);		//rc5
*				tmp |= (1 << 14); 						//c2
*				tk[8*i+7] ^= (tmp | (tmp << 1)); 		//rc1||rc1, rc5||26
*				tmp = ((rconst[i] & 0x1) << 10);		//rc0
*				tmp |= (((rconst[i] >> 4) & 0x1) << 24);//rc4
				tk[8*i+3] ^= (tmp | (tmp << 1)); 		//rc0||rc0, rc4||rc4
*				tk[i*8 + 0] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 1] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 2] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 4] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 6] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 7] ^= 0xffffffff; 				//for SBox calculations
*			break;
*			case 7:
*				tmp = ((rconst[i] >> 3) & 0x1) << 4; 	//rc3
*				tk[8*i+7] |= (tmp | (tmp << 1)); 		//rc3||rc3
*				tmp = ((rconst[i] >> 2) & 0x1) << 4; 	//rc2
*				tk[8*i+6] |= (tmp | (tmp << 1)); 		//rc2||rc2
*				tmp = (((rconst[i] >> 1) & 0x1) << 4);	//rc1
*				tmp |= ((rconst[i] >> 5) << 10);		//rc5
*				tmp |= (1 << 16); 						//c2
*				tk[8*i+5] |= (tmp | (tmp << 1)); 		//rc1||rc1, rc5||26
*				tmp = ((rconst[i] & 0x1) << 4);			//rc0
*				tmp |= (((rconst[i] >> 4) & 0x1) << 10);//rc4
*				tk[8*i+4] |= (tmp | (tmp << 1)); 		//rc0||rc0, rc4||rc4
*				tk[i*8 + 0] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 2] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 3] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 7] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 5] ^= 0xffffffff; 				//for SBox calculations
*				tk[i*8 + 6] ^= 0xffffffff; 				//for SBox calculations
*			break;
*		}
*	 }
* }
*****************************************************************************/
u32 rconst_32_bs[448] = {
	0xfffffff3, 0xffffffff, 0x00000000, 0xffffffff,
	0xffffffff, 0x000000c0, 0xffffffff, 0xffffffff, 
	0xffffffff, 0x00000300, 0xcffffcff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 
	0xffffffff, 0xffffffff, 0xffffffff, 0x0c000000,
	0xf3ffffff, 0x00000000, 0xffffffff, 0x33ffffff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
	0x00300000, 0xffcffffc, 0xffcfffff, 0xffcfffff, 
	0xff33ffff, 0xff3fffff, 0x00000000, 0xffffffff,
	0xffffffff, 0x00f00000, 0xff3fffff, 0xffffffff, 
	0xfcffffff, 0x00c00000, 0xfc3fcfff, 0xfcffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 
	0xffffffff, 0xffffffff, 0xfffff3ff, 0x03000c00,
	0xfffff3ff, 0x00000000, 0xffffffff, 0xfcff3fff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
	0x00000c30, 0xfffcf3cf, 0xffffffff, 0xffffffcf, 
	0xffffff03, 0xffffff3f, 0x00000000, 0xffffffff,
	0xffffffff, 0x000000f0, 0xffffffff, 0xffffffff, 
	0xfffffcff, 0x00000300, 0xcffffc3f, 0xfffffcff,
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 
	0xffffffff, 0xffffffff, 0xf3ffffff, 0x00000300,
	0xf3ffffff, 0x00000000, 0xffffffff, 0x33ffffff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
	0x0c000000, 0xf3fffffc, 0xffcfffff, 0xffcfffff, 
	0xffc3ffff, 0xffffffff, 0x00000000, 0xffffffff,
	0xffffffff, 0x00f00000, 0xff3fffff, 0xffffffff, 
	0xffffffff, 0x03c00000, 0xfc3fcfff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000c00,
	0xfffff3ff, 0x00000000, 0xffffffff, 0xfcff33ff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
	0x00000000, 0xfffcffcf, 0xffffffcf, 0xffffffcf, 
	0xfffffff3, 0xffffff3f, 0x00000000, 0xffffffff,
	0xffffffff, 0x000000f0, 0xffffff3f, 0xffffffff, 
	0xfffffcff, 0x000000c0, 0xcffffc3f, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 
	0xffffffff, 0xffffffff, 0xffffffff, 0x0c000300,
	0xf3ffffff, 0x00000000, 0xffffffff, 0x3ffffcff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
	0x00300000, 0xf3cffffc, 0xffffffff, 0xffcfffff, 
	0xff33ffff, 0xff3fffff, 0x00000000, 0xffffffff,
	0xffffffff, 0x00300000, 0xffffffff, 0xffffffff, 
	0xfcffffff, 0x00000000, 0xff3fcfff, 0xfcffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 
	0xffffffff, 0xffffffff, 0xfffff3ff, 0x03000000,
	0xffffffff, 0x00000000, 0xffffffff, 0xffff3fff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
	0x00000c00, 0xfffcf3ff, 0xffffffff, 0xffffffff, 
	0xffffffc3, 0xffffffff, 0x00000000, 0xffffffff,
	0xffffffff, 0x000000c0, 0xffffffff, 0xffffffff, 
	0xffffffff, 0x00000000, 0xcffffcff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 
	0xffffffff, 0xffffffff, 0xffffffff, 0x0c000000,
	0xf3ffffff, 0x00000000, 0xffffffff, 0x3fffffff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
	0x00300000, 0xffcffffc, 0xffffffff, 0xffcfffff, 
	0xff33ffff, 0xff3fffff, 0x00000000, 0xffffffff,
	0xffffffff, 0x00f00000, 0xffffffff, 0xffffffff, 
	0xfcffffff, 0x00000000, 0xfc3fcfff, 0xfcffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 
	0xffffffff, 0xffffffff, 0xfffff3ff, 0x03000000,
	0xfffff3ff, 0x00000000, 0xffffffff, 0xffff3fff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
	0x00000c00, 0xfffcf3ff, 0xffffffff, 0xffffffcf, 
	0xffffffc3, 0xffffffff, 0x00000000, 0xffffffff,
	0xffffffff, 0x000000f0, 0xffffffff, 0xffffffff, 
	0xffffffff, 0x00000300, 0xcffffc3f, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000,
	0xf3ffffff, 0x00000000, 0xffffffff, 0x33ffffff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
	0x00300000, 0xfffffffc, 0xffcfffff, 0xffcfffff, 
	0xff33ffff, 0xffffffff, 0x00000000, 0xffffffff,
	0xffffffff, 0x00f00000, 0xff3fffff, 0xffffffff, 
	0xffffffff, 0x00c00000, 0xfc3fcfff, 0xfcffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 
	0xffffffff, 0xffffffff, 0xfffff3ff, 0x00000c00,
	0xfffff3ff, 0x00000000, 0xffffffff, 0xfcff3fff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
	0x00000c00, 0xfffcffcf, 0xffffffff, 0xffffffcf, 
	0xffffffc3, 0xffffff3f, 0x00000000, 0xffffffff,
	0xffffffff, 0x00000030, 0xffffffff, 0xffffffff, 
	0xfffffcff, 0x00000300, 0xcfffff3f, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000300,
	0xffffffff, 0x00000000, 0xffffffff, 0x33ffffff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
	0x00000000, 0xf3fffffc, 0xffcfffff, 0xffffffff, 
	0xfff3ffff, 0xffffffff, 0x00000000, 0xffffffff,
	0xffffffff, 0x00000000, 0xff3fffff, 0xffffffff, 
	0xffffffff, 0x03c00000, 0xffffcfff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000,
	0xffffffff, 0x00000000, 0xffffffff, 0xfcff33ff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
	0x00000000, 0xfffcffff, 0xffffffcf, 0xffffffff, 
	0xfffffff3, 0xffffffff, 0x00000000, 0xffffffff,
	0xffffffff, 0x000000c0, 0xffffff3f, 0xffffffff, 
	0xffffffff, 0x000003c0, 0xcffffcff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000,
	0xf3ffffff, 0x00000000, 0xffffffff, 0x33fffcff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
	0x00000000, 0xfffffffc, 0xffcfffff, 0xffcfffff, 
	0xfff3ffff, 0xffffffff, 0x00000000, 0xffffffff,
	0xffffffff, 0x00f00000, 0xff3fffff, 0xffffffff, 
	0xffffffff, 0x00c00000, 0xfc3fcfff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000c00,
	0xfffff3ff, 0x00000000, 0xffffffff, 0xfcff3fff, 
	0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
	0x00000000, 0xfffcffcf, 0xffffffff, 0xffffffcf
};

/****************************************************************************
* Packs 2 input blocks B, B' into the state using a bitsliced representation.
* Once the packing process is complete, the 256-bit state consists of 8 
* 32-bit word and the input blocks bit positioning is as follows:
*
* 24 24' 56 56' 88 88' 120 120' | ... | 0 0' 32 32' 64 64' 96 96'
* 25 25' 57 57' 89 89' 121 121' | ... | 1 1' 33 33' 65 65' 97 97'
* 26 26' 58 58' 90 90' 122 122' | ... | 2 2' 34 34' 66 66' 98 98'
* 27 27' 59 59' 91 91' 123 123' | ... | 3 3' 35 35' 67 67' 99 99'
* 28 28' 60 60' 92 92' 124 124' | ... | 4 4' 36 36' 68 68' 100 100'
* 29 29' 61 61' 93 93' 125 125' | ... | 5 5' 37 37' 69 69' 101 101'
* 30 30' 62 62' 94 94' 126 126' | ... | 6 6' 38 38' 70 70' 102 102'
* 31 31' 63 63' 95 95' 127 127' | ... | 7 7' 39 39' 71 71' 103 103'
****************************************************************************/
void packing(u32* out, const u8* block0, const u8* block1) {
	u32 tmp;
	LE_LOAD(out, block0);
	LE_LOAD(out + 1, block1);
	LE_LOAD(out + 2, block0 + 4);
	LE_LOAD(out + 3, block1 + 4);
	LE_LOAD(out + 4, block0 + 8);
	LE_LOAD(out + 5, block1 + 8);
	LE_LOAD(out + 6, block0 + 12);
	LE_LOAD(out + 7, block1 + 12);
	SWAPMOVE(out[1], out[0], 0x55555555, 1);
	SWAPMOVE(out[3], out[2], 0x55555555, 1);
	SWAPMOVE(out[5], out[4], 0x55555555, 1);
	SWAPMOVE(out[7], out[6], 0x55555555, 1);
	SWAPMOVE(out[2], out[0], 0x30303030, 2);
	SWAPMOVE(out[4], out[0], 0x0c0c0c0c, 4);
	SWAPMOVE(out[6], out[0], 0x03030303, 6);
	SWAPMOVE(out[3], out[1], 0x30303030, 2);
	SWAPMOVE(out[5], out[1], 0x0c0c0c0c, 4);
	SWAPMOVE(out[7], out[1], 0x03030303, 6);
	SWAPMOVE(out[4], out[2], 0x0c0c0c0c, 2);
	SWAPMOVE(out[6], out[2], 0x03030303, 4);
	SWAPMOVE(out[5], out[3], 0x0c0c0c0c, 2);
	SWAPMOVE(out[7], out[3], 0x03030303, 4);
	SWAPMOVE(out[6], out[4], 0x03030303, 2);
	SWAPMOVE(out[7], out[5], 0x03030303, 2);
}

/****************************************************************************
* Unacks the 256-bit state into the 32-byte output byte array.
* Once the unpacking process is complete, the byte ordering within the output
* array is as follows:
*
*  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,  11,  12,  13,  14,  15,
* 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  26,  27,  28,  29,  30,  31
****************************************************************************/
void unpacking(u8* out, u8* out_bis, u32 *in) {
	u32 tmp;
	SWAPMOVE(in[6], in[4], 0x03030303, 2);
	SWAPMOVE(in[7], in[5], 0x03030303, 2);
	SWAPMOVE(in[5], in[3], 0x0c0c0c0c, 2);
	SWAPMOVE(in[7], in[3], 0x03030303, 4);
	SWAPMOVE(in[4], in[2], 0x0c0c0c0c, 2);
	SWAPMOVE(in[6], in[2], 0x03030303, 4);
	SWAPMOVE(in[7], in[1], 0x03030303, 6);
	SWAPMOVE(in[5], in[1], 0x0c0c0c0c, 4);
	SWAPMOVE(in[3], in[1], 0x30303030, 2);
	SWAPMOVE(in[6], in[0], 0x03030303, 6);
	SWAPMOVE(in[4], in[0], 0x0c0c0c0c, 4);
	SWAPMOVE(in[2], in[0], 0x30303030, 2);
	SWAPMOVE(in[1], in[0], 0x55555555, 1);
	SWAPMOVE(in[3], in[2], 0x55555555, 1);
	SWAPMOVE(in[5], in[4], 0x55555555, 1);
	SWAPMOVE(in[7], in[6], 0x55555555, 1);
	LE_STORE(out, in[0]);
	LE_STORE(out_bis, in[1]);
	LE_STORE(out + 4, in[2]);
	LE_STORE(out_bis + 4, in[3]);
	LE_STORE(out + 8, in[4]);
	LE_STORE(out_bis + 8, in[5]);
	LE_STORE(out + 12, in[6]);
	LE_STORE(out_bis + 12, in[7]);
}

/******************************************************************************
* Apply the permutation in a bitsliced manner, twice
******************************************************************************/
void permute_tk_2(u32* tk) {
	u32 tmp;
	for(int i =0; i < 8; i++) {
		tmp = tk[i];
		tk[i]  = ROR(tmp, 14) & 0xcc00cc00;
		tk[i] |= (tmp & 0x000000ff) << 16;
		tk[i] |= (tmp & 0xcc000000) >>  2;
		tk[i] |= (tmp & 0x0033cc00) >>  8;
		tk[i] |= (tmp & 0x00cc0000) >> 18;
	}
}

/******************************************************************************
* Apply the permutation in a bitsliced manner, 4 times
******************************************************************************/
void permute_tk_4(u32* tk) {
	u32 tmp;
	for(int i =0; i < 8; i++) {
		tmp = tk[i];
		tk[i]  = ROR(tmp, 22) & 0xcc0000cc;
		tk[i] |= ROR(tmp, 16) & 0x3300cc00;
		tk[i] |= ROR(tmp, 24) & 0x00cc3300;
		tk[i] |= (tmp & 0x00cc00cc) >> 2;
	}
}

/******************************************************************************
* Apply the permutation in a bitsliced manner, 6 times
******************************************************************************/
void permute_tk_6(u32* tk) {
	u32 tmp;
	for(int i =0; i < 8; i++) {
		tmp = tk[i];
		tk[i]  = ROR(tmp,  6) & 0xcccc0000;
		tk[i] |= ROR(tmp, 24) & 0x330000cc;
		tk[i] |= ROR(tmp, 10) & 0x00003333;
		tk[i] |= (tmp & 0x00cc) << 14;
		tk[i] |= (tmp & 0x3300) << 2;
	}
}

/******************************************************************************
* Apply the permutation in a bitsliced manner, 8 times
******************************************************************************/
void permute_tk_8(u32* tk) {
	u32 tmp;
	for(int i =0; i < 8; i++) {
		tmp = tk[i];
		tk[i]  = ROR(tmp, 24) & 0xcc000033;
		tk[i] |= ROR(tmp,  8) & 0x33cc0000;
		tk[i] |= ROR(tmp, 26) & 0x00333300;
		tk[i] |= (tmp & 0x00333300) >> 6;
	}
}

/******************************************************************************
* Apply the permutation in a bitsliced manner, 10 times
******************************************************************************/
void permute_tk_10(u32* tk) {
	u32 tmp;
	for(int i =0; i < 8; i++) {
		tmp = tk[i];
		tk[i]  = ROR(tmp,  8) & 0xcc330000;
		tk[i] |= ROR(tmp, 26) & 0x33000033;
		tk[i] |= ROR(tmp, 22) & 0x00cccc00;
		tk[i] |= (tmp & 0x00330000) >> 14;
		tk[i] |= (tmp & 0x0000cc00) >> 2;
	}
}

/******************************************************************************
* Apply the permutation in a bitsliced manner, 12 times
******************************************************************************/
void permute_tk_12(u32* tk) {
	u32 tmp;
	for(int i =0; i < 8; i++) {
		tmp = tk[i];
		tk[i]  = ROR(tmp,  8) & 0x0000cc33;
		tk[i] |= ROR(tmp, 30) & 0x00cc00cc;
		tk[i] |= ROR(tmp, 10) & 0x33330000;
		tk[i] |= ROR(tmp, 16) & 0xcc003300;
	}
}

/******************************************************************************
* Apply the permutation in a bitsliced manner, 14 times
******************************************************************************/
void permute_tk_14(u32* tk) {
	u32 tmp;
	for(int i =0; i < 8; i++) {
		tmp = tk[i];
		tk[i]  = ROR(tmp, 24) & 0x0033cc00;
		tk[i] |= ROR(tmp, 14) & 0x00cc0000;
		tk[i] |= ROR(tmp, 30) & 0xcc000000;
		tk[i] |= ROR(tmp, 16) & 0x000000ff;
		tk[i] |= ROR(tmp, 18) & 0x33003300;
	}
}

/******************************************************************************
* Precompute all LFSRs on TK2.
******************************************************************************/
void precompute_lfsr_tk2(u32* tk, const u8* tk2_0,
						const u8* tk2_1, const int rounds) {
	u32 tmp;
	u32 state[8];
	packing(state, tk2_0, tk2_1);
	memcpy(tk, state, 32);
	for(int i = 0 ; i < rounds; i+=2) {
		LFSR2(state);
		memcpy(tk+i*8+8, state, 32);
	}
}

/******************************************************************************
* Precompute all LFSRs on TK3
******************************************************************************/
void precompute_lfsr_tk3(u32* tk, const u8* tk3_0,
						const u8* tk3_1, const int rounds) {
	u32 tmp;
	u32 state[8];
	packing(state, tk3_0, tk3_1);
	for(int i = 0; i < 8; i++)
		tk[i] ^= state[i];
	for(int i = 0 ; i < rounds; i+=2) {
		LFSR3(state);
		tk[i*8+8] ^= state[0];
		tk[i*8+9] ^= state[1];
		tk[i*8+10] ^= state[2];
		tk[i*8+11] ^= state[3];
		tk[i*8+12] ^= state[4];
		tk[i*8+13] ^= state[5];
		tk[i*8+14] ^= state[6];
		tk[i*8+15] ^= state[7];
	}
}

/****************************************************************************
* XOR with TK with TK1 before applying the permutations.
* The key is then rearranged to match the fixsliced representation.
****************************************************************************/
void permute_tk(u32* tk, const u8* tk1_0, const u8* tk1_1, const int rounds) {
	u32 test;
	u32 tk1[8], tmp[8];
	packing(tk1, tk1_0, tk1_1);
	memcpy(tmp, tk, 32);
	XOR_BLOCKS(tmp, tk1);
	tk[0] = tmp[6] & 0xf0f0f0f0; 			//mask to extract rows 1&2 only
	tk[1] = tmp[5] & 0xf0f0f0f0;
	tk[2] = tmp[0] & 0xf0f0f0f0;
	tk[3] = tmp[1] & 0xf0f0f0f0;
	tk[4] = tmp[3] & 0xf0f0f0f0;
	tk[5] = tmp[7] & 0xf0f0f0f0;
	tk[6] = tmp[4] & 0xf0f0f0f0;
	tk[7] = tmp[2] & 0xf0f0f0f0;
	for(int i = 0 ; i < rounds; i+=8) {
		test = (i % 16 < 8) ? 1 : 0; 		//to apply the right power of P
		memcpy(tmp, tk+i*8+8, 32);
		XOR_BLOCKS(tmp, tk1);
		if (test)
			permute_tk_2(tmp); 				// applies P^2
		else
			permute_tk_10(tmp); 			// applies P^10
		tk[i*8+ 8]  = ROR(tmp[4],26) & 0xc3c3c3c3;
		tk[i*8+ 9]  = ROR(tmp[7],26) & 0xc3c3c3c3;
		tk[i*8+10]  = ROR(tmp[6],26) & 0xc3c3c3c3;
		tk[i*8+11]  = ROR(tmp[5],26) & 0xc3c3c3c3;
		tk[i*8+12]  = ROR(tmp[1],26) & 0xc3c3c3c3;
		tk[i*8+13]  = ROR(tmp[2],26) & 0xc3c3c3c3;
		tk[i*8+14]  = ROR(tmp[3],26) & 0xc3c3c3c3;
		tk[i*8+15]  = ROR(tmp[0],26) & 0xc3c3c3c3;
		tk[i*8+16]  = ROR(tmp[3],28) & 0x03030303;
		tk[i*8+16] |= ROR(tmp[3],12) & 0x0c0c0c0c;
		tk[i*8+17]  = ROR(tmp[2],28) & 0x03030303;
		tk[i*8+17] |= ROR(tmp[2],12) & 0x0c0c0c0c;
		tk[i*8+18]  = ROR(tmp[4],28) & 0x03030303;
		tk[i*8+18] |= ROR(tmp[4],12) & 0x0c0c0c0c;
		tk[i*8+19]  = ROR(tmp[7],28) & 0x03030303;
		tk[i*8+19] |= ROR(tmp[7],12) & 0x0c0c0c0c;
		tk[i*8+20]  = ROR(tmp[5],28) & 0x03030303;
		tk[i*8+20] |= ROR(tmp[5],12) & 0x0c0c0c0c;
		tk[i*8+21]  = ROR(tmp[0],28) & 0x03030303;
		tk[i*8+21] |= ROR(tmp[0],12) & 0x0c0c0c0c;
		tk[i*8+22]  = ROR(tmp[1],28) & 0x03030303;
		tk[i*8+22] |= ROR(tmp[1],12) & 0x0c0c0c0c;
		tk[i*8+23]  = ROR(tmp[6],28) & 0x03030303;
		tk[i*8+23] |= ROR(tmp[6],12) & 0x0c0c0c0c;
		memcpy(tmp, tk+i*8+24, 32);
		XOR_BLOCKS(tmp, tk1);
		if (test)
			permute_tk_4(tmp); 				// applies P^4
		else
			permute_tk_12(tmp); 			// applies P^12
		tk[i*8+24]  = ROR(tmp[1],14) & 0x30303030;
		tk[i*8+24] |= ROR(tmp[1], 6) & 0x0c0c0c0c;
		tk[i*8+25]  = ROR(tmp[0],14) & 0x30303030;
		tk[i*8+25] |= ROR(tmp[0], 6) & 0x0c0c0c0c;
		tk[i*8+26]  = ROR(tmp[3],14) & 0x30303030;
		tk[i*8+26] |= ROR(tmp[3], 6) & 0x0c0c0c0c;
		tk[i*8+27]  = ROR(tmp[2],14) & 0x30303030;
		tk[i*8+27] |= ROR(tmp[2], 6) & 0x0c0c0c0c;
		tk[i*8+28]  = ROR(tmp[7],14) & 0x30303030;
		tk[i*8+28] |= ROR(tmp[7], 6) & 0x0c0c0c0c;
		tk[i*8+29]  = ROR(tmp[6],14) & 0x30303030;
		tk[i*8+29] |= ROR(tmp[6], 6) & 0x0c0c0c0c;
		tk[i*8+30]  = ROR(tmp[5],14) & 0x30303030;
		tk[i*8+30] |= ROR(tmp[5], 6) & 0x0c0c0c0c;
		tk[i*8+31]  = ROR(tmp[4],14) & 0x30303030;
		tk[i*8+31] |= ROR(tmp[4], 6) & 0x0c0c0c0c;
		tk[i*8+32]  = ROR(tmp[6],16) & 0xf0f0f0f0;
		tk[i*8+33]  = ROR(tmp[5],16) & 0xf0f0f0f0;
		tk[i*8+34]  = ROR(tmp[0],16) & 0xf0f0f0f0;
		tk[i*8+35]  = ROR(tmp[1],16) & 0xf0f0f0f0;
		tk[i*8+36]  = ROR(tmp[3],16) & 0xf0f0f0f0;
		tk[i*8+37]  = ROR(tmp[7],16) & 0xf0f0f0f0;
		tk[i*8+38]  = ROR(tmp[4],16) & 0xf0f0f0f0;
		tk[i*8+39]  = ROR(tmp[2],16) & 0xf0f0f0f0;
		memcpy(tmp, tk+i*8+40, 32);
		XOR_BLOCKS(tmp, tk1);
		if (test)
			permute_tk_6(tmp); 				//	applies P^6
		else
			permute_tk_14(tmp); 			// applies P^14
		tk[i*8+40]  = ROR(tmp[4],10) & 0xc3c3c3c3;
		tk[i*8+41]  = ROR(tmp[7],10) & 0xc3c3c3c3;
		tk[i*8+42]  = ROR(tmp[6],10) & 0xc3c3c3c3;
		tk[i*8+43]  = ROR(tmp[5],10) & 0xc3c3c3c3;
		tk[i*8+44]  = ROR(tmp[1],10) & 0xc3c3c3c3;
		tk[i*8+45]  = ROR(tmp[2],10) & 0xc3c3c3c3;
		tk[i*8+46]  = ROR(tmp[3],10) & 0xc3c3c3c3;
		tk[i*8+47]  = ROR(tmp[0],10) & 0xc3c3c3c3;
		tk[i*8+48]  = ROR(tmp[3],12) & 0x03030303;
		tk[i*8+48] |= ROR(tmp[3],28) & 0x0c0c0c0c;
		tk[i*8+49]  = ROR(tmp[2],12) & 0x03030303;
		tk[i*8+49] |= ROR(tmp[2],28) & 0x0c0c0c0c;
		tk[i*8+50]  = ROR(tmp[4],12) & 0x03030303;
		tk[i*8+50] |= ROR(tmp[4],28) & 0x0c0c0c0c;
		tk[i*8+51]  = ROR(tmp[7],12) & 0x03030303;
		tk[i*8+51] |= ROR(tmp[7],28) & 0x0c0c0c0c;
		tk[i*8+52]  = ROR(tmp[5],12) & 0x03030303;
		tk[i*8+52] |= ROR(tmp[5],28) & 0x0c0c0c0c;
		tk[i*8+53]  = ROR(tmp[0],12) & 0x03030303;
		tk[i*8+53] |= ROR(tmp[0],28) & 0x0c0c0c0c;
		tk[i*8+54]  = ROR(tmp[1],12) & 0x03030303;
		tk[i*8+54] |= ROR(tmp[1],28) & 0x0c0c0c0c;
		tk[i*8+55]  = ROR(tmp[6],12) & 0x03030303;
		tk[i*8+55] |= ROR(tmp[6],28) & 0x0c0c0c0c;
		memcpy(tmp, tk+i*8+56, 32);
		XOR_BLOCKS(tmp, tk1);
		if (test)
			permute_tk_8(tmp); 				// applies P^8
		tk[i*8+56]  = ROR(tmp[1],30) & 0x30303030;
		tk[i*8+56] |= ROR(tmp[1],22) & 0x0c0c0c0c;
		tk[i*8+57]  = ROR(tmp[0],30) & 0x30303030;
		tk[i*8+57] |= ROR(tmp[0],22) & 0x0c0c0c0c;
		tk[i*8+58]  = ROR(tmp[3],30) & 0x30303030;
		tk[i*8+58] |= ROR(tmp[3],22) & 0x0c0c0c0c;
		tk[i*8+59]  = ROR(tmp[2],30) & 0x30303030;
		tk[i*8+59] |= ROR(tmp[2],22) & 0x0c0c0c0c;
		tk[i*8+60]  = ROR(tmp[7],30) & 0x30303030;
		tk[i*8+60] |= ROR(tmp[7],22) & 0x0c0c0c0c;
		tk[i*8+61]  = ROR(tmp[6],30) & 0x30303030;
		tk[i*8+61] |= ROR(tmp[6],22) & 0x0c0c0c0c;
		tk[i*8+62]  = ROR(tmp[5],30) & 0x30303030;
		tk[i*8+62] |= ROR(tmp[5],22) & 0x0c0c0c0c;
		tk[i*8+63]  = ROR(tmp[4],30) & 0x30303030;
		tk[i*8+63] |= ROR(tmp[4],22) & 0x0c0c0c0c;
		if (i+8 < rounds) { 				//only if next loop iteration
			tk[i*8+64] = tmp[6] & 0xf0f0f0f0; 
			tk[i*8+65] = tmp[5] & 0xf0f0f0f0;
			tk[i*8+66] = tmp[0] & 0xf0f0f0f0;
			tk[i*8+67] = tmp[1] & 0xf0f0f0f0;
			tk[i*8+68] = tmp[3] & 0xf0f0f0f0;
			tk[i*8+69] = tmp[7] & 0xf0f0f0f0;
			tk[i*8+70] = tmp[4] & 0xf0f0f0f0;
			tk[i*8+71] = tmp[2] & 0xf0f0f0f0;
		}
	}
}

/****************************************************************************
* Precompute all the round tweakeys
****************************************************************************/
void precompute_tk(u32* rtk, const tweakey tk, const tweakey tk_bis,
				int rounds) {
	memset(rtk, 0x00, 32*rounds);
	if(rounds > SKINNY128_128_ROUNDS)
		precompute_lfsr_tk2(rtk, tk.tk2, tk_bis.tk2, rounds);
	if(rounds > SKINNY128_256_ROUNDS)
		precompute_lfsr_tk3(rtk, tk.tk3, tk_bis.tk3, rounds);
	permute_tk(rtk, tk.tk1, tk_bis.tk1, rounds);
	for(int i = 0; i < rounds; i++) {			//add all rconsts to TK
		for(int j = 0; j < 8; j++)
			rtk[i*8+j] ^= rconst_32_bs[i*8+j];
	}
}
