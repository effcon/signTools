#ifndef WOLF_CRYPT_SM2_H
#define WOLF_CRYPT_SM2_H

//define dll file and lib
#define SM2_DLL_TYPE
//#define FLKWEBCRYPT_LIB_TYPE
#if defined(_WIN32) || defined(_WIN64)
	#ifdef SM2_DLL_TYPE
		#define SM2_DLL _declspec(dllexport)
	#else
		#define SM2_DLL _declspec(dllimport)
	#endif
#else	
	#define SM2_DLL
#endif

#ifdef __cplusplus
extern "C" {
#endif


/**************************bn.h*******************/
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>
#include <string.h>

//#define SM2_DEBUG
	
/*SM2 ERROR Code*/
#define ERR_SUCCESS							0x0000
#define ERR_SM2_SIGN_FLAG					0x1001
#define ERR_SM2_SIGN_DATA					0x1002
#define ERR_SM2_VERIRFY						0x1003
#define ERR_SM2_KEY							0x1004
#define ERR_SM2_DECRYPT						0x1005
#define ERR_SM2_DER_LENGTH					0x1006
#define ERR_SM2_DER_DATA					0x1007

#define ECC_MAX_ENCRYPT_LENGTH				136
#define ECCref_MAX_BITS						512
#define ECCref_MAX_LEN						((ECCref_MAX_BITS+7) / 8)
#define ECCref_ALIGNED_LEN					(((ECCref_MAX_BITS+7) / 8) / 2)
#define ECC_SIGN_FLAG_HASH					0
#define ECC_SIGN_FLAG_ORIGINAL				1

#define FLK_BN_ULONG	unsigned int 
#define ECC_BITS		    256	                //ECC模长比特数 
#define FLK_SM2_CIPHER_MAX			136//sm2 max cipher len

#define ECC_BLOCK_LEN		((ECC_BITS+7)/8)	//ECC分组长度字节数 
#define ECC_BLOCK_LEN_DWORD	((ECC_BITS+31)/32)  //ECC分组长度双字数 

typedef struct ECCrefPublicKey_st
{
	unsigned int bits;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
}ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
	unsigned int bits;
    unsigned char D[ECCref_MAX_LEN];
}ECCrefPrivateKey;

typedef struct ECCCipher_st
{
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
	unsigned char M[32];
	unsigned int L;
    unsigned char C[ECC_MAX_ENCRYPT_LENGTH];
}ECCCipher;

typedef struct ECCrefPublicKey_st TCipher;

typedef struct ECCSignature_st 
{
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
}ECCSignature;

typedef struct ECCComponentSignature_st
{
    unsigned char r[ECC_BLOCK_LEN];
    unsigned char s2[ECC_BLOCK_LEN];
    unsigned char s3[ECC_BLOCK_LEN];
}ECCComponentSignature;

typedef struct FLK_bignum_st
{
	FLK_BN_ULONG d[ECC_BLOCK_LEN_DWORD+2];	/* 在某些函数调用时有溢出(BN_uadd_sm2_ex,BN_rshift_sm2_ex) */
	//FLK_BN_ULONG d[ECC_BLOCK_LEN];							//by wuwentai
} FLKBIGNUM;

/**************************ec_lcl.h**********************/
struct ec_point_st {
	FLKBIGNUM X;
	FLKBIGNUM Y;	
	FLKBIGNUM Z;	   /* Jacobian projective coordinates:
	* (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
	int Z_is_one; /* enable optimized point arithmetics for special case */
} /* EC_POINT */;

typedef struct ec_point_st EC_POINT;

SM2_DLL int SM2_Init_ECCParameter(void);
SM2_DLL int SM2_Init_ECCParameter_ex(const unsigned char *p_256,const unsigned char *a_256,const unsigned char *b_256,const unsigned char *Gx_256,const unsigned char *Gy_256,const unsigned char *Gn_256);
SM2_DLL int SM2_GenerateKeyPair(ECCrefPublicKey *pucPublicKey,ECCrefPrivateKey *pucPrivateKey);

SM2_DLL int SM2_Sign(int flag,const ECCrefPrivateKey *pucPrivateKey,const unsigned char *pucData,size_t uiDataLength,ECCSignature *pucSignature);
SM2_DLL int SM2_Verify(int flag,const ECCrefPublicKey *pucPublicKey,const unsigned char *pucDataInput,size_t uiInputLength,const ECCSignature *pucSignature);
SM2_DLL int SM2_Encrypt(const ECCrefPublicKey *pucPublicKey,const unsigned char *pucData,size_t uiDataLength,ECCCipher *pucEncData);
SM2_DLL int SM2_Decrypt(const ECCrefPrivateKey *pucPrivateKey,const ECCCipher *pucEncData, unsigned char *pucData,size_t *puiDataLength);
SM2_DLL int SM2_Test(void);
SM2_DLL int SM2_Test_data(void);

SM2_DLL void SM2_Sm3Hash(const unsigned char *data, size_t datalen,
                                    const unsigned char *userid, size_t useridlen,
                                    ECCrefPublicKey *pubkey,
                                    unsigned char *digest);
//获取杂凑哈希值
SM2_DLL void SM2_Sm3HashGall(const unsigned char *userid, size_t useridlen,
	ECCrefPublicKey *pubkey,
	unsigned char *digest);

//公钥Der编码
SM2_DLL int EncodePublicKey(const ECCrefPublicKey *pucPublicKey,unsigned char *pucData,size_t *uiDataLength);
//公钥Der解码
SM2_DLL int DecodePublicKey(ECCrefPublicKey *pucPublicKey,const unsigned char *pucData,size_t uiDataLength);
//加密数据Der编码
SM2_DLL int EncodeECCCipher(const ECCCipher *pucEncData,unsigned char *pucData,size_t *uiDataLength);
//加密数据Der解码
SM2_DLL int DecodeECCCipher(ECCCipher *pucEncData,const unsigned char *pucData,size_t uiDataLength);
//签名数据Der编码
SM2_DLL int EncodeECCSignature(const ECCSignature *pucSignature,unsigned char *pucData,size_t *uiDataLength);
//签名数据Der解码
SM2_DLL int DecodeECCSignature(ECCSignature *pucSignature,const unsigned char *pucData,size_t uiDataLength);

SM2_DLL int SM2_GenKeyComponent1(ECCrefPrivateKey *D1, ECCrefPublicKey *P1);
SM2_DLL int SM2_GenKeyComponent2(ECCrefPublicKey *P1, ECCrefPrivateKey *D2, ECCrefPublicKey *P);
//SM2_DLL int SM2_KeyComponent1Sign(int flag,const unsigned char *pucData,size_t uiDataLength,unsigned char *hash,unsigned char *K1,ECCSignature *Q1);
SM2_DLL int SM2_KeyComponent2Sign(const ECCrefPrivateKey *D2,unsigned char *hash,ECCSignature *Q1, ECCComponentSignature *D2SN);
SM2_DLL int SM2_KeyComponent3Sign(const ECCrefPrivateKey *P1,unsigned char *K1, ECCComponentSignature *D2SN, ECCSignature *Signature);
SM2_DLL int SM2_get_sm2keypair(ECCrefPrivateKey *D1, ECCrefPrivateKey *D2, ECCrefPrivateKey *PriD, ECCrefPublicKey *PubK);
SM2_DLL int SM2_KeyComponent1Dec(const ECCrefPrivateKey *D1, ECCCipher *cip, TCipher *T1);
SM2_DLL int SM2_KeyComponent2Dec(const ECCrefPrivateKey *D2, TCipher *T1, TCipher *T2);
SM2_DLL int SM2_KeyComponent3Dec(ECCCipher *cip, TCipher *T2Cip, unsigned char *pucData,size_t *puiDataLength);

SM2_DLL int SM2_KeyComponent1Sign(int flag,const unsigned char *pucData,size_t uiDataLength,const unsigned char *userid, size_t useridlen, ECCrefPublicKey *pubkey, unsigned char *hash,unsigned char *K1,ECCSignature *Q1);

//new add
/*
@param D2_KEY, 第二部分私钥分量值
@param D2_len, 私钥长度
@param input [hash + Q1]
@param input len  the length of input
@param sign 输出由第二部分私钥生成的签名
@param sign_len 签名的分配长度(需大于等于96)，若成功，则返回实际长度，目前默认为96B.
*/
SM2_DLL int SM2_KeyComponent2Sign_ex(const unsigned char* D2_key, int D2_len, const unsigned char* input, int input_len, unsigned char* sign, int *sign_len);
//#endif

#ifdef __cplusplus
}
#endif

#endif
