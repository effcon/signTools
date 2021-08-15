#ifndef CRYPT_SM3_H
#define CRYPT_SM3_H

//define dll file and lib
#define SM3_DLL_TYPE
//#define FLKWEBCRYPT_LIB_TYPE
#if defined(_WIN32) || defined(_WIN64)
#ifdef SM3_DLL_TYPE
#define SM3_DLL _declspec(dllexport)
#else
#define SM3_DLL _declspec(dllimport)
#endif
#else	
#define SM3_DLL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SM3_DIGEST_LENGTH	32
#define SM3_BLOCK_SIZE		64
#define SM3_CBLOCK			(SM3_BLOCK_SIZE)
#define SM3_HMAC_SIZE		(SM3_DIGEST_LENGTH)


#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include "base64.h"

typedef struct {
	word32 digest[8];
	int nblocks;
	byte block[64];
	int num;
    byte ipad[64];     /*!< HMAC: inner padding        */
    byte opad[64];     /*!< HMAC: outer padding        */
} sm3_context;

SM3_DLL void sm3_starts(sm3_context *ctx);
SM3_DLL void sm3_update(sm3_context *ctx, const byte* data, size_t data_len);
SM3_DLL void sm3_finish(sm3_context *ctx, byte digest[SM3_DIGEST_LENGTH]);
SM3_DLL void sm3(const byte *data, size_t datalen,byte digest[SM3_DIGEST_LENGTH]);

SM3_DLL int sm3_file(const char *path, byte output[32] );
SM3_DLL void sm3_hmac_starts( sm3_context *ctx, byte *key, size_t keylen);
SM3_DLL void sm3_hmac_update( sm3_context *ctx, byte *input, size_t ilen );
SM3_DLL void sm3_hmac_finish( sm3_context *ctx, byte output[32] );
SM3_DLL void sm3_hmac( byte *key, size_t keylen, byte *input, size_t ilen, byte output[32] );
SM3_DLL void sm3kdf(byte *ucKout, unsigned long lKlen, const byte * cZin, unsigned long lZlen);
SM3_DLL int genrandom(unsigned char *rnd, unsigned int  rndlen);

#ifdef __cplusplus
}
#endif

#endif
