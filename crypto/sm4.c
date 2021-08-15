﻿/*
 * SM4 Encryption alogrithm (SMS4 algorithm)
 * GM/T 0002-2012 Chinese National Standard ref:http://www.oscca.gov.cn/ 
 * thanks to Xyssl
 * thnaks and refers to http://hi.baidu.com/numax/blog/item/80addfefddfb93e4cf1b3e61.html
 * author:goldboar
 * email:goldboar@163.com
 * 2012-4-20
 */

// Test vector 1
// plain: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
// key:   01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
// 	   round key and temp computing result:
// 	   rk[ 0] = f12186f9 X[ 0] = 27fad345
// 		   rk[ 1] = 41662b61 X[ 1] = a18b4cb2
// 		   rk[ 2] = 5a6ab19a X[ 2] = 11c1e22a
// 		   rk[ 3] = 7ba92077 X[ 3] = cc13e2ee
// 		   rk[ 4] = 367360f4 X[ 4] = f87c5bd5
// 		   rk[ 5] = 776a0c61 X[ 5] = 33220757
// 		   rk[ 6] = b6bb89b3 X[ 6] = 77f4c297
// 		   rk[ 7] = 24763151 X[ 7] = 7a96f2eb
// 		   rk[ 8] = a520307c X[ 8] = 27dac07f
// 		   rk[ 9] = b7584dbd X[ 9] = 42dd0f19
// 		   rk[10] = c30753ed X[10] = b8a5da02
// 		   rk[11] = 7ee55b57 X[11] = 907127fa
// 		   rk[12] = 6988608c X[12] = 8b952b83
// 		   rk[13] = 30d895b7 X[13] = d42b7c59
// 		   rk[14] = 44ba14af X[14] = 2ffc5831
// 		   rk[15] = 104495a1 X[15] = f69e6888
// 		   rk[16] = d120b428 X[16] = af2432c4
// 		   rk[17] = 73b55fa3 X[17] = ed1ec85e
// 		   rk[18] = cc874966 X[18] = 55a3ba22
// 		   rk[19] = 92244439 X[19] = 124b18aa
// 		   rk[20] = e89e641f X[20] = 6ae7725f
// 		   rk[21] = 98ca015a X[21] = f4cba1f9
// 		   rk[22] = c7159060 X[22] = 1dcdfa10
// 		   rk[23] = 99e1fd2e X[23] = 2ff60603
// 		   rk[24] = b79bd80c X[24] = eff24fdc
// 		   rk[25] = 1d2115b0 X[25] = 6fe46b75
// 		   rk[26] = 0e228aeb X[26] = 893450ad
// 		   rk[27] = f1780c81 X[27] = 7b938f4c
// 		   rk[28] = 428d3654 X[28] = 536e4246
// 		   rk[29] = 62293496 X[29] = 86b3e94f
// 		   rk[30] = 01cf72e5 X[30] = d206965e
// 		   rk[31] = 9124a012 X[31] = 681edf34
// cypher: 68 1e df 34 d2 06 96 5e 86 b3 e9 4f 53 6e 42 46
// 		
// test vector 2
// the same key and plain 1000000 times coumpting 
// plain:  01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
// key:    01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
// cypher: 59 52 98 c7 c6 fd 27 1f 04 02 f8 04 c3 3d 3f 66

#include <string.h>
#include <stdio.h>
#include <stddef.h>

#include "sm4.h"

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned int) (b)[(i)    ] << 24 )        \
        | ( (unsigned int) (b)[(i) + 1] << 16 )        \
        | ( (unsigned int) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned int) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/*
 *rotate shift left marco definition
 *
 */
#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define SWAP(a,b) { unsigned int t = a; a = b; b = t; t = 0; }

/*
 * Expanded SM4 S-boxes
 * Sbox table: 8bits input convert to 8 bits output*/
 
static const unsigned char SboxTable[16][16] = 
{
{0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
{0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
{0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
{0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
{0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
{0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
{0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
{0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
{0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
{0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
{0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
{0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
{0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
{0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
{0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
{0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
};

/* System parameter */
static const unsigned int FK[4] = {0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc};

/* fixed parameter */
static const unsigned int CK[32] =
{
0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};


/*
 * private function:
 * look up in SboxTable and get the related value.
 * args:    [in] inch: 0x00~0xFF (8 bits unsigned value).
 */
static unsigned char sm4Sbox(unsigned char inch)
{
    unsigned char *pTable = (unsigned char *)SboxTable;
    unsigned char retVal = (unsigned char)(pTable[inch]);
    return retVal;
}

/*
 * private F(Lt) function:
 * "T algorithm" == "L algorithm" + "t algorithm".
 * args:    [in] a: a is a 32 bits unsigned value;
 * return: c: c is calculated with line algorithm "L" and nonline algorithm "t"
 */
static unsigned int sm4Lt(unsigned int ka)
{
    unsigned int bb = 0;
    unsigned int c = 0;
    unsigned char a[4];
	unsigned char b[4];
    PUT_ULONG_BE(ka,a,0)
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
	GET_ULONG_BE(bb,b,0)
    c =bb^(ROTL(bb, 2))^(ROTL(bb, 10))^(ROTL(bb, 18))^(ROTL(bb, 24));
    return c;
}

/*
 * private F function:
 * Calculating and getting encryption/decryption contents.
 * args:    [in] x0: original contents;
 * args:    [in] x1: original contents;
 * args:    [in] x2: original contents;
 * args:    [in] x3: original contents;
 * args:    [in] rk: encryption/decryption key;
 * return the contents of encryption/decryption contents.
 */
static unsigned int sm4F(unsigned int x0, unsigned int x1, unsigned int x2, unsigned int x3, unsigned int rk)
{
    return (x0^sm4Lt(x1^x2^x3^rk));
}


/* private function:
 * Calculating round encryption key.
 * args:    [in] a: a is a 32 bits unsigned value;
 * return: sk[i]: i{0,1,2,3,...31}.
 */
static unsigned int sm4CalciRK(unsigned int ka)
{
    unsigned int bb = 0;
    unsigned int rk = 0;
    unsigned char a[4];
    unsigned char b[4];
    PUT_ULONG_BE(ka,a,0)
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
	GET_ULONG_BE(bb,b,0)
    rk = bb^(ROTL(bb, 13))^(ROTL(bb, 23));
    return rk;
}



/*
 * SM4 standard one round processing
 *
 */
#define uint32_t unsigned int
#define uint8_t unsigned char
#define GETU32(pc)  ( \
		((uint32_t)(pc)[0] << 24) ^ \
		((uint32_t)(pc)[1] << 16) ^ \
		((uint32_t)(pc)[2] <<  8) ^ \
		((uint32_t)(pc)[3]))

#define PUTU32(st, ct)  { \
		(ct)[0] = (uint8_t)((st) >> 24); \
		(ct)[1] = (uint8_t)((st) >> 16); \
		(ct)[2] = (uint8_t)((st) >>  8); \
		(ct)[3] = (uint8_t)(st); }


#define ROT(A,i) (((A) << i) | ((A) >> (32 - i)))
static const uint8_t SBOX[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};
#define L(B)	((B) ^ ROT((B), 2) ^ ROT((B),10) ^ ROT((B),18) ^ ROT((B), 24))
#define L_(B)	((B) ^ ROT((B),13) ^ ROT((B),23))
#define S(A)	((SBOX[((A) >> 24)       ] << 24) ^ \
		 (SBOX[((A) >> 16) & 0xff] << 16) ^ \
		 (SBOX[((A) >>  8) & 0xff] <<  8) ^ \
		 (SBOX[((A))       & 0xff]))
#define ROUND(X0,X1,X2,X3,X4,RK)	X4=(X1)^(X2)^(X3)^(RK); X4=S(X4); X4=(X0)^L(X4)
#define ROUND_(X0,X1,X2,X3,X4,CK,RK)	X4=(X1)^(X2)^(X3)^(CK); X4=S(X4); X4=(X0)^L_(X4); RK=X4
#define CK0	0x00070e15
#define CK1	0x1c232a31
#define CK2	0x383f464d
#define CK3	0x545b6269
#define CK4	0x70777e85
#define CK5	0x8c939aa1
#define CK6	0xa8afb6bd
#define CK7	0xc4cbd2d9 
#define CK8	0xe0e7eef5
#define CK9	0xfc030a11
#define CK10	0x181f262d
#define CK11	0x343b4249
#define CK12	0x50575e65
#define CK13	0x6c737a81
#define CK14	0x888f969d
#define CK15	0xa4abb2b9 
#define CK16	0xc0c7ced5
#define CK17	0xdce3eaf1
#define CK18	0xf8ff060d
#define CK19	0x141b2229
#define CK20	0x30373e45
#define CK21	0x4c535a61
#define CK22	0x686f767d
#define CK23	0x848b9299
#define CK24	0xa0a7aeb5
#define CK25	0xbcc3cad1
#define CK26	0xd8dfe6ed
#define CK27	0xf4fb0209
#define CK28	0x10171e25
#define CK29	0x2c333a41
#define CK30	0x484f565d
#define CK31	0x646b7279 

#define OS64
static void sm4_setkey(unsigned int SK[32], unsigned char key[16])
{
	unsigned int MK[4];
	unsigned int k[36];
	unsigned int i = 0;

	GET_ULONG_BE(MK[0], key, 0);
	GET_ULONG_BE(MK[1], key, 4);
	GET_ULONG_BE(MK[2], key, 8);
	GET_ULONG_BE(MK[3], key, 12);
	k[0] = MK[0] ^ FK[0];
	k[1] = MK[1] ^ FK[1];
	k[2] = MK[2] ^ FK[2];
	k[3] = MK[3] ^ FK[3];
	for (; i<32; i++)
	{
		k[i + 4] = k[i] ^ (sm4CalciRK(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]));
		SK[i] = k[i + 4];
	}
}

static void sm4_one_round( unsigned int sk[32],
                    unsigned char input[16],
                    unsigned char output[16] )
{
//32bit与64bit采用不同的逻辑来进行运算。64bit下的新算法比就算法快接近百分之20
//32bit下就算法性能优
#ifndef OS64
	unsigned int i = 0;
	unsigned int ulbuf[36];

	memset(ulbuf, 0, sizeof(ulbuf));
	GET_ULONG_BE(ulbuf[0], input, 0)
	GET_ULONG_BE(ulbuf[1], input, 4)
	GET_ULONG_BE(ulbuf[2], input, 8)
	GET_ULONG_BE(ulbuf[3], input, 12)

	while (i < 32)
	{
		ulbuf[i + 4] = sm4F(ulbuf[i], ulbuf[i + 1], ulbuf[i + 2], ulbuf[i + 3], sk[i]);
// #ifdef _DEBUG
//        	printf("rk(%02d) = 0x%08x,  X(%02d) = 0x%08x \n",i,sk[i], i, ulbuf[i+4] );
// #endif
		i++;
	}

	PUT_ULONG_BE(ulbuf[35], output, 0);
	PUT_ULONG_BE(ulbuf[34], output, 4);
	PUT_ULONG_BE(ulbuf[33], output, 8);
	PUT_ULONG_BE(ulbuf[32], output, 12);


#else
	const unsigned int *rk = sk;
	unsigned int X0, X1, X2, X3, X4;

	X0 = GETU32(input);
	X1 = GETU32(input + 4);
	X2 = GETU32(input + 8);
	X3 = GETU32(input + 12);

	ROUND(X0, X1, X2, X3, X4, rk[0]);
	ROUND(X1, X2, X3, X4, X0, rk[1]);
	ROUND(X2, X3, X4, X0, X1, rk[2]);
	ROUND(X3, X4, X0, X1, X2, rk[3]);
	ROUND(X4, X0, X1, X2, X3, rk[4]);
	ROUND(X0, X1, X2, X3, X4, rk[5]);
	ROUND(X1, X2, X3, X4, X0, rk[6]);
	ROUND(X2, X3, X4, X0, X1, rk[7]);
	ROUND(X3, X4, X0, X1, X2, rk[8]);
	ROUND(X4, X0, X1, X2, X3, rk[9]);
	ROUND(X0, X1, X2, X3, X4, rk[10]);
	ROUND(X1, X2, X3, X4, X0, rk[11]);
	ROUND(X2, X3, X4, X0, X1, rk[12]);
	ROUND(X3, X4, X0, X1, X2, rk[13]);
	ROUND(X4, X0, X1, X2, X3, rk[14]);
	ROUND(X0, X1, X2, X3, X4, rk[15]);
	ROUND(X1, X2, X3, X4, X0, rk[16]);
	ROUND(X2, X3, X4, X0, X1, rk[17]);
	ROUND(X3, X4, X0, X1, X2, rk[18]);
	ROUND(X4, X0, X1, X2, X3, rk[19]);
	ROUND(X0, X1, X2, X3, X4, rk[20]);
	ROUND(X1, X2, X3, X4, X0, rk[21]);
	ROUND(X2, X3, X4, X0, X1, rk[22]);
	ROUND(X3, X4, X0, X1, X2, rk[23]);
	ROUND(X4, X0, X1, X2, X3, rk[24]);
	ROUND(X0, X1, X2, X3, X4, rk[25]);
	ROUND(X1, X2, X3, X4, X0, rk[26]);
	ROUND(X2, X3, X4, X0, X1, rk[27]);
	ROUND(X3, X4, X0, X1, X2, rk[28]);
	ROUND(X4, X0, X1, X2, X3, rk[29]);
	ROUND(X0, X1, X2, X3, X4, rk[30]);
	ROUND(X1, X2, X3, X4, X0, rk[31]);

	PUTU32(X0, output);
	PUTU32(X4, output + 4);
	PUTU32(X3, output + 8);
	PUTU32(X2, output + 12)
#endif
}

/*
 * SM4 key schedule (128-bit, encryption)
 */
void sm4_setkey_enc( sm4_context *ctx, unsigned char key[16] )
{
    ctx->mode = SM4_ENCRYPT;
	sm4_setkey( ctx->sk, key );
}

/*
 * SM4 key schedule (128-bit, decryption)
 */
void sm4_setkey_dec( sm4_context *ctx, unsigned char key[16] )
{
    int i;
	ctx->mode = SM4_DECRYPT;
    sm4_setkey( ctx->sk, key );
    for( i = 0; i < 16; i ++ )
    {
        SWAP( ctx->sk[ i ], ctx->sk[ 31-i] );
    }

}


/*
 * SM4-ECB block encryption/decryption
 */

void sm4_crypt_ecb( sm4_context *ctx,
				   int mode,
				   int length,
				   unsigned char *input,
                   unsigned char *output)
{
	if(mode == SM4_ENCRYPT || mode == SM4_DECRYPT)
	{
		while (length > 0)
		{
			sm4_one_round(ctx->sk, input, output);
			input += SM4_BLOCK_SIZE;
			output += SM4_BLOCK_SIZE;
			length -= SM4_BLOCK_SIZE;
		}
	 }
}

/*
 * SM4-CBC buffer encryption/decryption
 */
void sm4_crypt_cbc( sm4_context *ctx,
                    int mode,
                    int length,
                    unsigned char iv[SM4_BLOCK_SIZE],
                    unsigned char *input,
                    unsigned char *output )
{
    int i;
    unsigned char temp[SM4_BLOCK_SIZE], iv_tmp[SM4_BLOCK_SIZE];

	memcpy(iv_tmp, iv, SM4_BLOCK_SIZE);

    if( mode == SM4_ENCRYPT )
    {
        while( length > 0 )
        {
            for( i = 0; i < SM4_BLOCK_SIZE; i++ )
                output[i] = (unsigned char)( input[i] ^ iv_tmp[i] );

            sm4_one_round( ctx->sk, output, output );
            memcpy( iv_tmp, output, SM4_BLOCK_SIZE);

            input  += SM4_BLOCK_SIZE;
            output += SM4_BLOCK_SIZE;
            length -= SM4_BLOCK_SIZE;
        }
    }
    else /* SM4_DECRYPT */
    {
        while( length > 0 )
        {
            memcpy( temp, input, SM4_BLOCK_SIZE );
            sm4_one_round( ctx->sk, input, output );

            for( i = 0; i < SM4_BLOCK_SIZE; i++ )
                output[i] = (unsigned char)( output[i] ^ iv_tmp[i] );

            memcpy(iv_tmp, temp, SM4_BLOCK_SIZE);

            input  += SM4_BLOCK_SIZE;
            output += SM4_BLOCK_SIZE;
            length -= SM4_BLOCK_SIZE;
        }
    }
}

void sm4_crypt_cbc_msg(int mode, int length, unsigned char key[SM4_BLOCK_SIZE], unsigned char iv[SM4_BLOCK_SIZE], unsigned char *input, unsigned char *output)
{
	sm4_context ctx;

	int i;
	unsigned char temp[SM4_BLOCK_SIZE], iv_tmp[SM4_BLOCK_SIZE];

	memcpy(iv_tmp, iv, SM4_BLOCK_SIZE);

	if (mode == SM4_ENCRYPT)
	{
		sm4_setkey_enc(&ctx, key);
		while (length > 0)
		{
			for (i = 0; i < SM4_BLOCK_SIZE; i++)
				output[i] = (unsigned char)(input[i] ^ iv_tmp[i]);

			sm4_one_round(ctx.sk, output, output);
			memcpy(iv_tmp, output, SM4_BLOCK_SIZE);

			input += SM4_BLOCK_SIZE;
			output += SM4_BLOCK_SIZE;
			length -= SM4_BLOCK_SIZE;
		}
	}
	else /* SM4_DECRYPT */
	{
		sm4_setkey_dec(&ctx, key);
		while (length > 0)
		{
			memcpy(temp, input, SM4_BLOCK_SIZE);
			sm4_one_round(ctx.sk, input, output);

			for (i = 0; i < SM4_BLOCK_SIZE; i++)
				output[i] = (unsigned char)(output[i] ^ iv_tmp[i]);

			memcpy(iv_tmp, temp, SM4_BLOCK_SIZE);

			input += SM4_BLOCK_SIZE;
			output += SM4_BLOCK_SIZE;
			length -= SM4_BLOCK_SIZE;
		}
	}
}

 void sm4_crypt_ofb(const sm4_context *ctx,
	size_t length,
	const unsigned char  iv[SM4_BLOCK_SIZE],
	const unsigned char  *input,
	unsigned char  *output)
{
	int i;
	unsigned char iv_tmp[SM4_BLOCK_SIZE];
	memcpy(iv_tmp, iv, SM4_BLOCK_SIZE);
	while (length > 0)
	{
		sm4_one_round((unsigned int *)(ctx->sk), iv_tmp, iv_tmp);
		
		for (i = 0; i < SM4_BLOCK_SIZE; i++)
		{
			output[i] = (unsigned char)(input[i] ^ iv_tmp[i]);
		}
		input += SM4_BLOCK_SIZE;
		output += SM4_BLOCK_SIZE;
		length -= SM4_BLOCK_SIZE;
	}
}

 
 void sm4_crypt_ofb_ex(const sm4_context *ctx, size_t length, const unsigned char iv[SM4_BLOCK_SIZE], const unsigned char *input, unsigned char *output)
 {
	 int iremainder = length % 16;
	 if (iremainder == 0)
	 {
		 sm4_crypt_ofb(ctx, length, iv, input, output);
	 }
	 else
	 {
		 int multi = length - iremainder;
		 int i;
		 unsigned char iv_tmp[SM4_BLOCK_SIZE];
		 memcpy(iv_tmp, iv, SM4_BLOCK_SIZE);
		 while (multi > 0)
		 {
			 sm4_one_round((unsigned int *)(ctx->sk), iv_tmp, iv_tmp);

			 for (i = 0; i < SM4_BLOCK_SIZE; i++)
			 {
				 output[i] = (unsigned char)(input[i] ^ iv_tmp[i]);
			 }
			 input += SM4_BLOCK_SIZE;
			 output += SM4_BLOCK_SIZE;
			 multi -= SM4_BLOCK_SIZE;
		 }
		 // 保证iv的更新
		 sm4_one_round((unsigned int *)(ctx->sk), iv_tmp, iv_tmp);
		 for (i = 0; i < iremainder; i++)
		 {
			 output[i] = (unsigned char)(input[i] ^ iv_tmp[i]);
		 }
	 }
 }

 void sm4_crypt_ofb_msg(int mode, int length, unsigned char key[SM4_BLOCK_SIZE], unsigned char iv[SM4_BLOCK_SIZE], unsigned char *input, unsigned char *output)
 {
	 sm4_context ctx;
	 sm4_setkey_enc(&ctx,key);
	 sm4_crypt_ofb_ex(&ctx, length, iv, input, output);
	 return;
 }

//  void sm4_crypt_ofb_setkey(sm4_context *ctx,
// 	size_t length,
// 	unsigned char *curiv,
// 	unsigned char *output,
// 	size_t cnt)
// {
// 	size_t i;
// 	sm4_one_round(ctx->sk, curiv, output);
// 	for (i = 1; i < cnt; ++i)
// 	{
// 		sm4_one_round(ctx->sk, output + (i - 1) * SM4_BLOCK_SIZE, output + i * SM4_BLOCK_SIZE);
// 	}
// 
// 	memcpy(curiv, output + (i - 1) * SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
// }
 /*
void sm4_crypt_ofb_getcur_iv(sm4_context *ctx, byte *curiv, size_t cnt)
{
	size_t i;
	for (i = 0; i < cnt; ++i)
	{
		sm4_one_round(ctx->sk, curiv, curiv);
	}
}
*/
