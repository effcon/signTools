/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#if !defined(NO_SM3)
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include "sm3.h"

#if defined(BIG_ENDIAN_ORDER) && !defined(FREESCALE_MMCAU)
    #define cpu_to_be32(v) (v)
#else
	#define cpu_to_be32(v) (((v)>>24) | (((v)>>8)&0xff00) | (((v)<<8)&0xff0000) | ((v)<<24))
#endif
SM3_DLL void wc_sm3_compress_ex(word32 digest[8], const byte block[SM3_BLOCK_SIZE]);

void sm3_starts(sm3_context *ctx)
{
	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;

	ctx->nblocks = 0;
	ctx->num = 0;
}

void sm3_update(sm3_context *ctx, const byte* data, size_t data_len)
{
	if (ctx->num) {
		unsigned int left = SM3_BLOCK_SIZE - ctx->num;
		if (data_len < left) {
			memcpy(ctx->block + ctx->num, data, data_len);
			ctx->num += data_len;
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			wc_sm3_compress_ex(ctx->digest, ctx->block);
			ctx->nblocks++;
			data += left;
			data_len -= left;
		}
	}
	while (data_len >= SM3_BLOCK_SIZE) {
		wc_sm3_compress_ex(ctx->digest, data);
		ctx->nblocks++;
		data += SM3_BLOCK_SIZE;
		data_len -= SM3_BLOCK_SIZE;
	}
	ctx->num = data_len;
	if (data_len) {
		memcpy(ctx->block, data, data_len);
	}
}

void sm3_finish(sm3_context *ctx, byte *digest)
{
	unsigned int i;
	word32 *pdigest = (word32 *)digest;
	word32 *count = (word32 *)(ctx->block + SM3_BLOCK_SIZE - 8);

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 9 <= SM3_BLOCK_SIZE) {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		wc_sm3_compress_ex(ctx->digest, ctx->block);
		memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}

	count[0] = cpu_to_be32((ctx->nblocks) >> 23);
	count[1] = cpu_to_be32((ctx->nblocks << 9) + (ctx->num << 3));

	wc_sm3_compress_ex(ctx->digest, ctx->block);
	for (i = 0; i < sizeof(ctx->digest)/sizeof(ctx->digest[0]); i++) {
		pdigest[i] = cpu_to_be32(ctx->digest[i]);
	}
}

#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n%32) 
#define ROTATELEFT(x,n) (SHL((x),n) | ((x) >> (32 - n%32)))

//#define ROTATELEFT(X,n)  (((X)<<(n)) | ((X)>>(32-(n))))

#define P0(x) ((x) ^  ROTATELEFT((x),9)  ^ ROTATELEFT((x),17))
#define P1(x) ((x) ^  ROTATELEFT((x),15) ^ ROTATELEFT((x),23))

#define FF0(x,y,z) ( (x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


void wc_sm3_compress_ex(word32 digest[8], const byte block[64])
{
	int j;
	word32 W[68], W1[64];
	const word32 *pblock = (const word32 *)block;

	word32 A = digest[0];
	word32 B = digest[1];
	word32 C = digest[2];
	word32 D = digest[3];
	word32 E = digest[4];
	word32 F = digest[5];
	word32 G = digest[6];
	word32 H = digest[7];
	word32 SS1,SS2,TT1,TT2,T[64];

	for (j = 0; j < 16; j++) {
		W[j] = cpu_to_be32(pblock[j]);
	}
	for (j = 16; j < 68; j++) {
		W[j] = P1( W[j-16] ^ W[j-9] ^ ROTATELEFT(W[j-3],15)) ^ ROTATELEFT(W[j - 13],7 ) ^ W[j-6];;
	}
	for( j = 0; j < 64; j++) {
		W1[j] = W[j] ^ W[j+4];
	}

	for(j =0; j < 16; j++) {

		T[j] = 0x79CC4519;
		SS1 = ROTATELEFT((ROTATELEFT(A,12) + E + ROTATELEFT(T[j],j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A,12);
		TT1 = FF0(A,B,C) + D + SS2 + W1[j];
		TT2 = GG0(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F,19);
		F = E;
		E = P0(TT2);
	}

	for(j =16; j < 64; j++) {

		T[j] = 0x7A879D8A;
		SS1 = ROTATELEFT((ROTATELEFT(A,12) + E + ROTATELEFT(T[j],j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A,12);
		TT1 = FF1(A,B,C) + D + SS2 + W1[j];
		TT2 = GG1(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F,19);
		F = E;
		E = P0(TT2);
	}

	digest[0] ^= A;
	digest[1] ^= B;
	digest[2] ^= C;
	digest[3] ^= D;
	digest[4] ^= E;
	digest[5] ^= F;
	digest[6] ^= G;
	digest[7] ^= H;
}

void sm3(const byte *msg, size_t msglen,byte dgst[SM3_DIGEST_LENGTH])
{
    sm3_context ctx;

    sm3_starts(&ctx);
    sm3_update(&ctx, msg, msglen);
    sm3_finish(&ctx, dgst);
}

int sm3_file(const char *path, unsigned char output[32] )
{

#if 0
    FILE *f;
    size_t n;
    sm3_context ctx;
    unsigned char buf[1024];

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( 1 );

    sm3_starts( &ctx );

    while( ( n = fread( buf, 1, sizeof( buf ), f ) ) > 0 )
        sm3_update( &ctx, buf,  n );

    sm3_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sm3_context ) );

    if( ferror( f ) != 0 )
    {
        fclose( f );
        return( 2 );
    }

    fclose( f );
#endif
	return( 0 );
}

/*
 * SM3 HMAC context setup
 */
void sm3_hmac_starts( sm3_context *ctx, unsigned char *key, size_t keylen )
{
    size_t i;
    unsigned char sum[32];

    if( keylen > 64 )
    {
        sm3( key, keylen, sum );
        keylen = 32;
        //keylen = ( is224 ) ? 28 : 32;
        key = sum;
    }

    memset( ctx->ipad, 0x36, 64 );
    memset( ctx->opad, 0x5C, 64 );

    for( i = 0; i < keylen; i++ )
    {
        ctx->ipad[i] = (unsigned char)( ctx->ipad[i] ^ key[i] );
        ctx->opad[i] = (unsigned char)( ctx->opad[i] ^ key[i] );
    }

    sm3_starts( ctx);
    sm3_update( ctx, ctx->ipad, 64 );

    memset( sum, 0, sizeof( sum ) );
}

/*
 * SM3 HMAC process buffer
 */
void sm3_hmac_update( sm3_context *ctx, unsigned char *input, size_t ilen )
{
    sm3_update( ctx, input, ilen );
}

/*
 * SM3 HMAC final digest
 */
void sm3_hmac_finish( sm3_context *ctx, unsigned char output[32] )
{
    size_t hlen;
    unsigned char tmpbuf[32];

    //is224 = ctx->is224;
    hlen =  32;

    sm3_finish( ctx, tmpbuf );
    sm3_starts( ctx );
    sm3_update( ctx, ctx->opad, 64 );
    sm3_update( ctx, tmpbuf, hlen );
    sm3_finish( ctx, output );

    memset( tmpbuf, 0, sizeof( tmpbuf ) );
}

/*
 * output = HMAC-SM#( hmac key, input buffer )
 */
void sm3_hmac( unsigned char *key, size_t keylen,
                unsigned char *input, size_t ilen,
                unsigned char output[32] )
{
    sm3_context ctx;

    sm3_hmac_starts( &ctx, key, keylen);
    sm3_hmac_update( &ctx, input, ilen );
    sm3_hmac_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sm3_context ) );
}

/*
void sm3kdf(unsigned char *ucKout, unsigned long lKlen, const unsigned char * cZin, unsigned long lZlen)
{
    unsigned long ct = 0x00000001;
    size_t i,j;
    unsigned char *hai;
    unsigned char *ha;

    j = lKlen>>5;
    if(lKlen&0x1f)
        j++;
    ha = (unsigned char *) malloc(32 * j * sizeof(unsigned char));
    hai = (unsigned char *) malloc((lZlen+4) * sizeof(unsigned char));

    for(i=1; i<=j; i++)
    {
        memcpy(&hai[0], cZin, lZlen);
        hai[lZlen+0] = (ct>>24)&0xff;
        hai[lZlen+1] = (ct>>16)&0xff;
        hai[lZlen+2] = (ct>>8)&0xff;
        hai[lZlen+3] = ct & 0xff;
        sm3(hai, lZlen+4, &ha[(i-1)*32]);
        ct++;
    }

    if(lKlen&0x1f)
    {
        i = lKlen - 32*floor((double)lKlen/32);
        memcpy(ucKout, ha, 32*(j-1)+i);
    }
    else
    {
        memcpy(ucKout, ha, lKlen);
    }


    free(ha);
    free(hai);
}
*/
static volatile int randomTime = 1;
int genrandom(unsigned char *rnd, unsigned int  rndlen)
{
	unsigned char tmp[256];
	unsigned char dgst[32];
	int cnt = rndlen/32;
	int i,j;

	if(randomTime == 1)
	{
		srand(time(NULL));
		randomTime = 0;
	}	
	if (cnt > 0)
	{
		for(j = 0; j < cnt; j++)
		{
			for(i = 0; i < 128; i++)
			{
				tmp[i] = (unsigned char)((rand() % 255) + 1);
			}

			sm3(tmp, 128, dgst);
			if (rndlen >= (j + 1) * 32)
			{
				memcpy(rnd + j * 32, dgst, 32);
			}
			else
			{
				memcpy(rnd + j * 32, dgst, rndlen%32);
			}
		}
	}
	else
	{
		for(i = 0; i < 128; i++)
		{
			tmp[i] = (unsigned char)((rand() % 255) + 1);
		}
		sm3(tmp, 128, dgst);
		memcpy(rnd, dgst, rndlen);
	}
	
	return 0;
}

#endif //if defined(HAVE_SM3)
