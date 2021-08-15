/**
 * \file sm4.h
 */
#ifndef XYSSL_SM4_H
#define XYSSL_SM4_H


#ifndef SM4_BLOCK_SIZE
#define SM4_BLOCK_SIZE 16
#endif

#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0

/**
 * \brief          SM4 context structure
 */
typedef struct
{
    int mode;                   /*!<  encrypt/decrypt   */
    unsigned int sk[32];       /*!<  SM4 subkeys       */
}
sm4_context;


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SM4 key schedule (128-bit, encryption)
 *
 * \param ctx      SM4 context to be initialized
 * \param key      16-byte secret key
 */
void sm4_setkey_enc( sm4_context *ctx, unsigned char key[SM4_BLOCK_SIZE] );

/**
 * \brief          SM4 key schedule (128-bit, decryption)
 *
 * \param ctx      SM4 context to be initialized
 * \param key      16-byte secret key
 */
void sm4_setkey_dec( sm4_context *ctx, unsigned char key[SM4_BLOCK_SIZE] );

/**
 * \brief          SM4-ECB block encryption/decryption
 * \param ctx      SM4 context
 * \param mode     SM4_ENCRYPT or SM4_DECRYPT
 * \param length   length of the input data
 * \param input    input block
 * \param output   output block
 */
void sm4_crypt_ecb( sm4_context *ctx,
				     int mode,
					 int length,
                     unsigned char *input,
                     unsigned char *output);

// /** Just CTR OFB CFB support the no-padding
// * \brief          SM4-ECB block encryption/decryption
// * \param ctx      SM4 context
// * \param mode     SM4_ENCRYPT or SM4_DECRYPT
// * \param length   length of the input data
// * \param input    input block
// * \param output   output block
// */
// void sm4_crypt_ecb_ex(sm4_context *ctx,
// 	int mode,
// 	int length,
// 	unsigned char *input,
// 	unsigned char *output);

/**
 * \brief          SM4-CBC buffer encryption/decryption
 * \param ctx      SM4 context
 * \param mode     SM4_ENCRYPT or SM4_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 */
void sm4_crypt_cbc( sm4_context *ctx,
                     int mode,
                     int length,
                     unsigned char iv[SM4_BLOCK_SIZE],
                     unsigned char *input,
                     unsigned char *output );

/**
* \brief          SM4-CBC buffer encryption/decryption
* \param mode     SM4_ENCRYPT(1) or SM4_DECRYPT(0)
* \param length   length of the input data
* \param iv       initialization vector (updated after use)
* \param input    buffer holding the input data
* \param output   buffer holding the output data
* be careful the length of input need be multiples of 16 and the input length also be output length
*/
void sm4_crypt_cbc_msg(int mode,
	int length,
	unsigned char key[SM4_BLOCK_SIZE],
	unsigned char iv[SM4_BLOCK_SIZE],
	unsigned char *input,
	unsigned char *output);


void sm4_crypt_ofb(const sm4_context *ctx,
	size_t length,
	const unsigned char  iv[SM4_BLOCK_SIZE],
	const unsigned char  *input,
	unsigned char  *output);

/**
* \brief          SM4-OFB buffer encryption/decryption
* \param length   length of the input data
* \param iv       initialization vector 
* \param input    buffer holding the input data
* \param output   buffer holding the output data
* the expand implement
*/
void sm4_crypt_ofb_ex(const sm4_context *ctx,
	size_t length,
	const unsigned char  iv[SM4_BLOCK_SIZE],
	const unsigned char  *input,
	unsigned char  *output);

/**
* \brief          SM4-OFB buffer encryption/decryption
* \param length   unuseful,just give a look
* \param length   length of the input data
* \param iv       initialization vector
* \param input    buffer holding the input data
* \param output   buffer holding the output data
* the expand implement
*/
void sm4_crypt_ofb_msg(int mode,
	int length,
	unsigned char key[SM4_BLOCK_SIZE],
	unsigned char iv[SM4_BLOCK_SIZE],
	unsigned char *input,
	unsigned char *output);

// void sm4_crypt_ofb_setkey(unsigned char key[SM4_BLOCK_SIZE],
// 	size_t length,
// 	unsigned char *curiv,
// 	unsigned char *output,
// 	size_t cnt);
/*
void sm4_crypt_ofb_getcur_iv(sm4_context *ctx, byte *curiv, size_t cnt);
*/
#ifdef __cplusplus
}
#endif

#endif /* sm4.h */
