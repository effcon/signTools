#if !defined(NO_SM2)
#include <stdio.h>
#include <time.h>
#include "sm2.h"
#include "sm3.h"
#if defined(_WIN32) || defined(_WIN64)
#pragma comment(lib,"ws2_32.lib")
#include <WinSock.h>
#else
#include <arpa/inet.h>
#endif

#define FLK_BN_BITS		64
#define FLK_BN_BYTES	4
#define FLK_BN_BITS2	32
#define FLK_BN_BITS4	16
#define FLK_BN_BITS8	8

#define FLK_BN_MASK2	(0xffffffffL)
#define FLK_BN_MASK2l	(0xffff)
#define FLK_BN_MASK2h	(0xffff0000L)
#define FLK_BN_TBIT		(0x80000000L)
/**************************bn.h*******************/

/**************************ec_bn.h*******************/

#define FLK_BIGNUM_SIZE	sizeof(FLKBIGNUM)

//ECC芯片参数结构
typedef struct ECCParameter_st
{
    unsigned char p[ECC_BLOCK_LEN];		//模数p
	unsigned char a[ECC_BLOCK_LEN];		//参数a
	unsigned char b[ECC_BLOCK_LEN];		//参数b
	unsigned char Gx[ECC_BLOCK_LEN];	//G点的x坐标
	unsigned char Gy[ECC_BLOCK_LEN];	//G点的y坐标
	unsigned char Gn[ECC_BLOCK_LEN];	//G点的阶
} ECCParameter;

//ECC公钥结构
typedef struct 
{
	unsigned char Qx[ECC_BLOCK_LEN];		//Q点的x坐标
	unsigned char Qy[ECC_BLOCK_LEN];		//Q点的y坐标
} ECC_PUBLIC_KEY;

//ECC私钥结构
typedef struct 
{
	unsigned char Ka[ECC_BLOCK_LEN];		//私钥Ka
} ECC_PRIVATE_KEY;

//ECC签名值结构
typedef struct 
{
	unsigned char r[ECC_BLOCK_LEN];	
	unsigned char s[ECC_BLOCK_LEN];	
} ECC_SIGNATURE;

//ECC加密值结构
typedef struct 
{
	unsigned char C1[2*ECC_BLOCK_LEN];	
	//unsigned char C2[ECC_BLOCK_LEN];  //和明文等长，最大是	ECC_BLOCK_LEN
	unsigned int len;
   	unsigned char C2[ECC_MAX_ENCRYPT_LENGTH];
	unsigned char C3[ECC_BLOCK_LEN];
} ECC_ENCRYPTION;
/**************************ec_bn.h*******************/

/**************************bn_lcl.h**********************/
#define Lw(t)    (((FLK_BN_ULONG)(t))&FLK_BN_MASK2)
#define Hw(t)    (((FLK_BN_ULONG)((t)>>FLK_BN_BITS2))&FLK_BN_MASK2)

#define LBITS(a)	((a)&FLK_BN_MASK2l)
#define HBITS(a)	(((a)>>FLK_BN_BITS4)&FLK_BN_MASK2l)
#define	L2HBITS(a)	((FLK_BN_ULONG)((a)&FLK_BN_MASK2l)<<FLK_BN_BITS4)

#define LLBITS(a)	((a)&BN_MASKl)
#define LHBITS(a)	(((a)>>FLK_BN_BITS2)&BN_MASKl)
#define	LL2HBITS(a)	((BN_ULLONG)((a)&BN_MASKl)<<FLK_BN_BITS2)

#define mul64(l,h,bl,bh) \
	{ \
	FLK_BN_ULONG m,m1,lt,ht; \
	\
	lt=l; \
	ht=h; \
	m =(bh)*(lt); \
	lt=(bl)*(lt); \
	m1=(bl)*(ht); \
	ht =(bh)*(ht); \
	m=(m+m1)&FLK_BN_MASK2; if (m < m1) ht+=L2HBITS(1L); \
	ht+=HBITS(m); \
	m1=L2HBITS(m); \
	lt=(lt+m1)&FLK_BN_MASK2; if (lt < m1) ht++; \
	(l)=lt; \
	(h)=ht; \
	}

#define mul_add(r,a,bl,bh,c) { \
	FLK_BN_ULONG l,h; \
	\
	h= (a); \
	l=LBITS(h); \
	h=HBITS(h); \
	mul64(l,h,(bl),(bh)); \
	\
	/* non-multiply part */ \
	l=(l+(c))&FLK_BN_MASK2; if (l < (c)) h++; \
	(c)=(r); \
	l=(l+(c))&FLK_BN_MASK2; if (l < (c)) h++; \
	(c)=h&FLK_BN_MASK2; \
	(r)=l; \
	}

#define mul(r,a,bl,bh,c) { \
	FLK_BN_ULONG l,h; \
	\
	h= (a); \
	l=LBITS(h); \
	h=HBITS(h); \
	mul64(l,h,(bl),(bh)); \
	\
	/* non-multiply part */ \
	l+=(c); if ((l&FLK_BN_MASK2) < (c)) h++; \
	(c)=h&FLK_BN_MASK2; \
	(r)=l&FLK_BN_MASK2; \
	}
/**************************bn_lcl.h**********************/

/**************************bn_lib.h**********************/
int BN_is_zero_sm2_ex(FLK_BN_ULONG *a, FLK_BN_ULONG al);
int BN_is_one_sm2_ex(FLK_BN_ULONG *a, FLK_BN_ULONG al);
void bn_fix_top_sm2_ex(FLK_BN_ULONG *a, int *al);
int BN_num_bits_word_sm2_ex(FLK_BN_ULONG l);
int BN_num_bits_sm2_ex(FLK_BN_ULONG *a, int al);
int BN_ucmp_sm2_ex(FLK_BN_ULONG *a, int al, FLK_BN_ULONG *b, int bl);
/**************************bn_lib.h**********************/

/**************************bn_asm.h**********************/
FLK_BN_ULONG bn_mul_add_words_sm2_ex(FLK_BN_ULONG *rp, const FLK_BN_ULONG *ap, int num, FLK_BN_ULONG w);
FLK_BN_ULONG bn_mul_words_sm2_ex(FLK_BN_ULONG *rp, const FLK_BN_ULONG *ap, int num, FLK_BN_ULONG w);
FLK_BN_ULONG bn_div_words_sm2_ex(FLK_BN_ULONG h, FLK_BN_ULONG l, FLK_BN_ULONG d);
FLK_BN_ULONG bn_add_words_sm2_ex(FLK_BN_ULONG *r, const FLK_BN_ULONG *a, const FLK_BN_ULONG *b, int n);
FLK_BN_ULONG bn_sub_words_sm2_ex(FLK_BN_ULONG *r, const FLK_BN_ULONG *a, const FLK_BN_ULONG *b, int n);
/**************************bn_asm.h**********************/

/**************************bn_add.h**********************/
int BN_uadd_sm2_ex(FLK_BN_ULONG *r, int *rl, FLK_BN_ULONG *a, int al, FLK_BN_ULONG *b, int bl);
int BN_usub_sm2_ex(FLK_BN_ULONG *r, int *rl, FLK_BN_ULONG *a, int al, FLK_BN_ULONG *b, int bl);
/**************************bn_add.h**********************/

/**************************bn_div.h**********************/
void BN_div_sm2_ex(FLK_BN_ULONG *dv, int *dv_len, FLK_BN_ULONG *rm, int *rm_len, FLK_BN_ULONG *num, int num_len, FLK_BN_ULONG *divisor, int divisor_len);
/**************************bn_div.h**********************/

/**************************bn_gcd.h**********************/
void BN_mod_inverse_sm2_ex(FLK_BN_ULONG *in, int *in_len, FLK_BN_ULONG *a, int a_len, FLK_BN_ULONG *n, int n_len);
/**************************bn_gcd.h**********************/

/**************************bn_mod.h**********************/
void BN_mod_add_sm2_ex(FLK_BN_ULONG *r, FLK_BN_ULONG *a, FLK_BN_ULONG *b, FLK_BN_ULONG *m, FLK_BN_ULONG mLen);
void BN_mod_sub_sm2_ex(FLK_BN_ULONG *r, int *rl, FLK_BN_ULONG *a, FLK_BN_ULONG *b, FLK_BN_ULONG *m, FLK_BN_ULONG mLen);
void BN_mod_lshift1_sm2_ex(FLK_BN_ULONG *r, FLK_BN_ULONG *a, FLK_BN_ULONG *m, FLK_BN_ULONG mLen);
/**************************bn_mod.h**********************/

/**************************bn_mount.h**********************/
void BN_MONT_CTX_set_sm2_ex(FLK_BN_ULONG *Mod, int ModLen, FLK_BN_ULONG *n0, FLK_BN_ULONG *RR);
void BN_mod_mul_montgomery_sm2_ex(FLK_BN_ULONG *r, FLK_BN_ULONG *a, FLK_BN_ULONG *b, FLK_BN_ULONG *M, int M_Len, FLK_BN_ULONG n0);
void BN_mod_mul_montgomery_one_sm2_ex(FLK_BN_ULONG *r, FLK_BN_ULONG *a, FLK_BN_ULONG *M, int M_Len, FLK_BN_ULONG n0);
/**************************bn_mount.h**********************/

/**************************bn_mul.h**********************/
void BN_mul_nomal_sm2_ex(FLK_BN_ULONG *r, FLK_BN_ULONG *a, int na, FLK_BN_ULONG *b, int nb);
void BN_mul_sm2_ex(FLK_BN_ULONG *r, int *rl, FLK_BN_ULONG *a, int al, FLK_BN_ULONG *b, int bl);
/**************************bn_mul.h**********************/

/**************************bn_shift.h**********************/
void BN_rshift1_sm2_ex(FLKBIGNUM *r, int *r_top, FLKBIGNUM *a, int a_top);
int BN_lshift_sm2_ex(FLK_BN_ULONG *r, int *rl, FLK_BN_ULONG *a, int al, int n);
int BN_rshift_sm2_ex(FLK_BN_ULONG *r, int *rl, FLK_BN_ULONG *a, int al, int n);

int two_number_same_ex(FLK_BN_ULONG *a, int len, FLK_BN_ULONG *b);
/**************************bn_shift.h**********************/

#ifndef SM2_DEBUG
void myPrintBIGNUM(const char *p, FLKBIGNUM data);
void myPrintHex(const char *p, const unsigned char *data, int len);
void myprintPoint(const char *p,EC_POINT *point);

void myPrintBIGNUM(const char *p, FLKBIGNUM data)
{	
	return;
	unsigned int i;
	char *buf;

	buf = (char *)malloc(strlen(p) + sizeof(data)*2 + 1024);
	if(buf == NULL)
	{
		return ;
	}
	memset(buf, 0, strlen(p) + sizeof(data)*2 + 1024);

	sprintf(buf, "%s\n", p);
	for(i = 0; i < sizeof(data)/sizeof(FLK_BN_ULONG); i++)
	{
		sprintf(buf + strlen(buf), "%x ", data.d[i]);
	}
	sprintf(buf + strlen(buf), "\n");


	printf("%s\n", buf);
}
void myPrintHex(const char *p, const unsigned char *data, int len)
{
	return;
	int i;
	char *buf;

	buf = (char *)malloc(strlen(p) + len*2 + 1024);
	if(buf == NULL)
	{
		return ;
	}
	memset(buf, 0, strlen(p) + len*2 + 1024);

	sprintf(buf, "%s\n", p);
	for(i = 0; i < len; i++)
	{
		sprintf(buf + strlen(buf), "%02x", data[i]);
	}
	sprintf(buf + strlen(buf), "\n");

	printf("%s\n", buf);
}

void myprintPoint(const char *p,EC_POINT *point)
{
	return;
	printf("%s:\n", p);
	myPrintBIGNUM("point X", point->X);
	myPrintBIGNUM("point Y", point->Y);
	myPrintBIGNUM("point Z", point->Z);
}

#define PrintBIGNUM myPrintBIGNUM	
#define PrintHex myPrintHex
#define printPoint myprintPoint
#else
#define PrintBIGNUM
#define PrintHex
#define printPoint
#endif

struct ec_group_st {
	
	FLKBIGNUM field; 
	/* Field specification.
	* For curves over GF(p), this is the modulus. */
	
	FLK_BN_ULONG field_top;	/* Field length	*/ 
	
	FLKBIGNUM a,b; 
	/* Curve coefficients.
	* (Here the assumption is that BIGNUMs can be used
	* or abused for all kinds of fields, not just GF(p).)
	* For characteristic  > 3,  the curve is defined
	* by a Weierstrass equation of the form
	*     y^2 = x^3 + a*x + b.
	*/
	EC_POINT generator; /* Generator */
	FLKBIGNUM order;
	
	FLK_BN_ULONG order_top;	/* Order length	*/ 
	
	FLKBIGNUM RR;
	FLKBIGNUM Ni;     /* R*(1/R mod N) - N*Ni = 1
	* (Ni is only stored for bignum algorithm) */
	FLK_BN_ULONG n0;   /* least significant word of Ni */
	
	
	FLKBIGNUM field_data2; 
} /* EC_GROUP */;

typedef struct ec_group_st EC_GROUP;
/**************************ec_lcl.h**********************/

/**************************ec_general.h**********************/
void ECC_InitParameter_ex(ECCParameter *ECCPara,EC_GROUP *group);
void ECC_GenerateKeyPair_ex(EC_GROUP *group, ECC_PUBLIC_KEY *pECCPK, ECC_PRIVATE_KEY *pECCSK);
int POINT_is_on_curve_ex(ECCParameter *pECCPara, ECC_PUBLIC_KEY *pECCPoint);
/**************************ec_general.h**********************/


/**************************ecp_smpl.h**********************/
void ec_GFp_simple_point_get_affine_coordinates_GFp_ex(EC_GROUP *group, EC_POINT *point, FLKBIGNUM *x, FLKBIGNUM *y);
void ec_GFp_simple_add_sm2_ex(EC_GROUP *group, EC_POINT *r, EC_POINT *a, EC_POINT *b);
void ec_GFp_simple_dbl_sm2_ex(EC_GROUP *group, EC_POINT *r, EC_POINT *a);
int ec_GFp_simple_is_at_infinity_sm2_ex(EC_GROUP *group, EC_POINT *point);
/**************************ecp_smpl.h**********************/

/**************************ec_mult.h**********************/
signed char *compute_wNAF_ex(FLKBIGNUM *scalar, int w, int order_top, int *ret_len);
void EC_POINTs_mul_sm2_ex(EC_GROUP *group, EC_POINT *R, EC_POINT *P, FLKBIGNUM *k, EC_POINT *Q, FLKBIGNUM *l); 
/**************************ec_mult.h**********************/


/**************************kdf.h**********************/
void KDF_ALGRITRHM_ex(unsigned  char *Z_in,int z_input_len,int Klen,unsigned char *Z_out);
//void KDF_ALGRITRHM_ex(unsigned  char *Z_in,int z_input_len,int Klen,unsigned char *Z_out);
/**************************kdf.h**********************/

/**************************ECDSA.h**********************/
void ECDSA_Signature_ex(EC_GROUP *group, unsigned char *e, ECC_PRIVATE_KEY *pECCSK, ECC_SIGNATURE *pECCSign);
int ECDSA_Verification_ex(EC_GROUP *group, unsigned char *e, ECC_PUBLIC_KEY *pECCPK, ECC_SIGNATURE *pECCSign);
/**************************ECDSA.h**********************/

/**************************ECES.h**********************/
void ECES_Encryption_ex(EC_GROUP *group, const unsigned char *e, int e_len, ECC_PUBLIC_KEY *pECCPK,ECC_ENCRYPTION *pEncryption);
int  ECES_Decryption_ex(EC_GROUP *group,ECC_ENCRYPTION *pEncryption, int c2_len , ECC_PRIVATE_KEY *pECCSK, unsigned char *e);
/**************************ECES.h**********************/

/**************************algorithm_dll.h**********************/
void algrithm_ex(const unsigned char *ain, int len,int flag, unsigned char aout[32]);
/**************************algorithm_dll.h**********************/


int BN_is_bit_set_sm2_ex(FLKBIGNUM *a, int n);
signed char *compute_wNAF_openssl_ex(FLKBIGNUM *scalar, int w, int *ret_len);


void ECC_Public_To_WOLFSSLl_ex(ECC_PUBLIC_KEY *pk, ECCrefPublicKey *pucPublicKey);
void ECC_Public_From_WOLFSSL_ex(ECC_PUBLIC_KEY *pk, const ECCrefPublicKey *pucPublicKey);

void ECC_Private_To_WOLFSSL_ex(ECC_PRIVATE_KEY *pk, ECCrefPrivateKey *pucPrivateKey);
void ECC_Private_From_WOLFSSL_ex(ECC_PRIVATE_KEY *pk, const ECCrefPrivateKey *pucPrivateKey);

void ECC_ECCEncryption_To_WOLFSSL_ex(ECC_ENCRYPTION *pk, ECCCipher *pucEncData);
void ECC_ECCEncryption_From_WOLFSSL_ex(ECC_ENCRYPTION *pk, const ECCCipher *pucEncData);

void ECC_ECCSignature_To_WOLFSSL_ex(ECC_SIGNATURE *sd, ECCSignature *pucSignature);
void ECC_ECCSignature_From_WOLFSSL_ex(ECC_SIGNATURE *sd, const ECCSignature *pucSignature);

static unsigned int BytePrecision_ex(unsigned int value);
unsigned int DEREncodeSequence_ex(unsigned char *bt, const unsigned char *str, unsigned int strLen);
unsigned int DEREncodeInteger_ex(unsigned char *bt, const unsigned char *str, unsigned int strLen);
unsigned int DERLengthEncode_ex(unsigned char *bt, unsigned int length);
unsigned int DEREncodeString_ex(unsigned char *bt, const unsigned char *str, unsigned int strLen);

static EC_GROUP G_group;
static ECCParameter G_ECCPara;
static int g_sm2init = 0;

int BN_is_zero_sm2_ex(FLK_BN_ULONG *a, FLK_BN_ULONG al)
{
	FLK_BN_ULONG i;
	
	for(i = al-1; i > 0; i--)
		if( a[i] )
			return 0;
		return 1;
}

int BN_is_one_sm2_ex(FLK_BN_ULONG *a, FLK_BN_ULONG al)
{
	FLK_BN_ULONG i = 0;
	
	if( a[i++] != 1)
		return 0;
	for(; i < al-1; i++)
		if( a[i] )
			return 0;
		return 1;
}

void bn_fix_top_sm2_ex(FLK_BN_ULONG *a, int *al)
{
	if (*al > 0) 
	{ 
		for (; *al > 0; (*al)--) 
			if ( *(a+(*al)-1) ) break; 
	} 
}

int BN_num_bits_word_sm2_ex(FLK_BN_ULONG l)
{
	int i = FLK_BN_BITS2;
	
	while( !(l & (1 << (i-1))) )
		i--;
	
	return i;				
}


int BN_num_bits_sm2_ex(FLK_BN_ULONG *a, int al)
{
	FLK_BN_ULONG l;
	int i, dwords;
	
    dwords = al;
	bn_fix_top_sm2_ex(a, &dwords);
	
	if (dwords == 0) return(0);
	l = a[dwords-1];
	i = (dwords-1) * FLK_BN_BITS2;
	return(i + BN_num_bits_word_sm2_ex(l));
}

int BN_ucmp_sm2_ex(FLK_BN_ULONG *a, int al, FLK_BN_ULONG *b, int bl)
{
	int i;
	FLK_BN_ULONG t1, t2;
	
	i = al - bl;
	if (i != 0) return(i);
	for (i = al - 1; i >= 0; i--)
	{
		t1 = a[i];
		t2 = b[i];
		if (t1 != t2)
			return(t1 > t2 ? 1 : -1);
	}
	return(0);
}

FLK_BN_ULONG bn_mul_add_words_sm2_ex(FLK_BN_ULONG *rp, const FLK_BN_ULONG *ap, int num, FLK_BN_ULONG w)
{
	FLK_BN_ULONG c = 0;
	FLK_BN_ULONG bl, bh;

	if (num <= 0) return((FLK_BN_ULONG)0);

	bl = LBITS(w);
	bh = HBITS(w);

	for (;;)
	{
		mul_add(rp[0], ap[0], bl, bh, c);
		if (--num == 0) break;
		mul_add(rp[1], ap[1], bl, bh, c);
		if (--num == 0) break;
		mul_add(rp[2], ap[2], bl, bh, c);
		if (--num == 0) break;
		mul_add(rp[3], ap[3], bl, bh, c);
		if (--num == 0) break;
		ap+=4;
		rp+=4;
	}
	return(c);
} 

FLK_BN_ULONG bn_mul_words_sm2_ex(FLK_BN_ULONG *rp, const FLK_BN_ULONG *ap, int num, FLK_BN_ULONG w)
{
	FLK_BN_ULONG carry=0;
	FLK_BN_ULONG bl, bh;

	if (num <= 0) return((FLK_BN_ULONG)0);

	bl = LBITS(w);
	bh = HBITS(w);

	for (;;)
	{
		mul(rp[0], ap[0], bl, bh, carry);
		if (--num == 0) break;
		mul(rp[1], ap[1], bl, bh, carry);
		if (--num == 0) break;
		mul(rp[2], ap[2], bl, bh, carry);
		if (--num == 0) break;
		mul(rp[3], ap[3], bl, bh, carry);
		if (--num == 0) break;
		ap+=4;
		rp+=4;
	}

	return(carry);
} 

FLK_BN_ULONG bn_div_words_sm2_ex(FLK_BN_ULONG h, FLK_BN_ULONG l, FLK_BN_ULONG d)
{
	FLK_BN_ULONG dh, dl, q, ret = 0, th, tl, t;
	int i, count = 2;

	if (d == 0) return(FLK_BN_MASK2);

	i = BN_num_bits_word_sm2_ex(d);

	i = FLK_BN_BITS2 - i;
	if (h >= d) h -= d;

	if (i)
	{
		d <<= i;
		h = (h << i) | (l >> (FLK_BN_BITS2 - i));
		l <<= i;
	}
	dh = (d & FLK_BN_MASK2h) >> FLK_BN_BITS4;
	dl = (d & FLK_BN_MASK2l);
	for (;;)
	{
		if ((h >> FLK_BN_BITS4) == dh)
			q = FLK_BN_MASK2l;
		else
			q = h / dh;

		th = q * dh;
		tl = dl * q;
		for (;;)
		{
			t = h - th;
			if ((t & FLK_BN_MASK2h) ||
				((tl) <= (
					(t << FLK_BN_BITS4)|
					((l & FLK_BN_MASK2h) >> FLK_BN_BITS4))))
				break;
			q--;
			th -= dh;
			tl -= dl;
		}
		t = (tl >> FLK_BN_BITS4);
		tl = (tl << FLK_BN_BITS4) & FLK_BN_MASK2h;
		th += t;

		if (l < tl) th++;
		l -= tl;
		if (h < th)
		{
			h += d;
			q--;
		}
		h -= th;

		if (--count == 0) break;

		ret = q << FLK_BN_BITS4;
		h = ((h << FLK_BN_BITS4)|(l >> FLK_BN_BITS4)) & FLK_BN_MASK2;
		l = (l & FLK_BN_MASK2l) << FLK_BN_BITS4;
	}
	ret |= q;
	return(ret);
}

FLK_BN_ULONG bn_add_words_sm2_ex(FLK_BN_ULONG *r, const FLK_BN_ULONG *a, const FLK_BN_ULONG *b, int n)
{
	FLK_BN_ULONG c, l, t;

	if (n <= 0) return((FLK_BN_ULONG)0);

	c=0;
	for (;;)
	{
		t = a[0];
		t = (t + c) & FLK_BN_MASK2;
		c = (t < c);
		l = (t + b[0]) & FLK_BN_MASK2;
		c += (l < t);
		r[0] = l;
		if (--n <= 0) break;

		t = a[1];
		t = (t + c) & FLK_BN_MASK2;
		c =(t < c);
		l =(t + b[1]) & FLK_BN_MASK2;
		c += (l < t);
		r[1] = l;
		if (--n <= 0) break;

		t = a[2];
		t =(t + c) & FLK_BN_MASK2;
		c =(t < c);
		l =(t + b[2]) & FLK_BN_MASK2;
		c += (l < t);
		r[2] = l;
		if (--n <= 0) break;

		t = a[3];
		t =(t + c) & FLK_BN_MASK2;
		c =(t < c);
		l =(t + b[3]) & FLK_BN_MASK2;
		c += (l < t);
		r[3] = l;
		if (--n <= 0) break;

		a += 4;
		b += 4;
		r += 4;
	}

	return((FLK_BN_ULONG)c);
}

FLK_BN_ULONG bn_sub_words_sm2_ex(FLK_BN_ULONG *r, const FLK_BN_ULONG *a, const FLK_BN_ULONG *b, int n)
{
	FLK_BN_ULONG t1, t2;
	int c = 0;

	if (n <= 0) return((FLK_BN_ULONG)0);

	for (;;)
	{
		t1 = a[0]; t2 = b[0];
		r[0] = (t1 - t2 - c) & FLK_BN_MASK2;
		if (t1 != t2) c = (t1 < t2);
		if (--n <= 0) break;

		t1 = a[1]; t2 = b[1];
		r[1] = (t1 - t2 - c) & FLK_BN_MASK2;
		if (t1 != t2) c = (t1 < t2);
		if (--n <= 0) break;

		t1 = a[2]; t2 = b[2];
		r[2] = (t1 - t2 - c) & FLK_BN_MASK2;
		if (t1 != t2) c = (t1 < t2);
		if (--n <= 0) break;

		t1 = a[3]; t2 = b[3];
		r[3] = (t1 - t2 - c) & FLK_BN_MASK2;
		if (t1 != t2) c = (t1 < t2);
		if (--n <= 0) break;

		a += 4;
		b += 4;
		r += 4;
	}
	return(c);
}

int BN_uadd_sm2_ex(FLK_BN_ULONG *r, int *rl, FLK_BN_ULONG *a, int al, FLK_BN_ULONG *b, int bl)
{
	register int i;
	int max, min;
	FLK_BN_ULONG *ap, *bp, *rp, carry, t1;
	FLK_BN_ULONG *tmp;
	int tmp1;

	if (al < bl)
	{ 
		tmp = a; a = b; b = tmp; 
		tmp1 = al; al = bl; bl = tmp1; 
	}
	max = al;
	min = bl;

	*rl = max;

	ap = a;
	bp = b;
	rp = r;
	carry = 0;

	carry = bn_add_words_sm2_ex(rp, ap, bp, min);
	rp += min;
	ap += min;
	bp += min;
	i = min;

	if (carry)
	{
		while (i < max)
		{
			i++;
			t1 = *(ap++);
			if ((*(rp++) = (t1+1) & FLK_BN_MASK2) >= t1)
			{
				carry=0;
				break;
			}
		}
		if ((i >= max) && carry)
		{
			*(rp++) = 1;
			(*rl)++;
		}
	}
	if (rp != ap)
	{
		for (; i < max; i++)
			*(rp++) = *(ap++);
	}
	return(1);
}

int BN_usub_sm2_ex(FLK_BN_ULONG *r, int *rl, FLK_BN_ULONG *a, int al, FLK_BN_ULONG *b, int bl)
{
	int max, min;
	register FLK_BN_ULONG t1, t2, *ap, *bp, *rp;
	int i, carry;

	max = al;
	min = bl;

	ap = a;
	bp = b;
	rp = r;

	carry = 0;
	for (i = 0; i < min; i++)
	{
		t1= *(ap++);
		t2= *(bp++);
		if (carry)
		{
			carry = (t1 <= t2);
			t1 = (t1-t2-1) & FLK_BN_MASK2;
		}
		else
		{
			carry = (t1 < t2);
			t1 = (t1-t2) & FLK_BN_MASK2;
		}
		*(rp++) = t1 & FLK_BN_MASK2;
	}

	if (carry) /* subtracted */
	{
		while (i < max)
		{
			i++;
			t1 = *(ap++);
			t2 = (t1 - 1) & FLK_BN_MASK2;
			*(rp++) = t2;
			if (t1 > t2) break;
		}
	}

	if (rp != ap)
	{
		for (;;)
		{
			if (i++ >= max) break;
			rp[0]=ap[0];
			if (i++ >= max) break;
			rp[1]=ap[1];
			if (i++ >= max) break;
			rp[2]=ap[2];
			if (i++ >= max) break;
			rp[3]=ap[3];
			rp+=4;
			ap+=4;
		}
	}

	*rl=max;
	bn_fix_top_sm2_ex(r, rl);
	return(1);
}

void BN_div_sm2_ex(FLK_BN_ULONG *dv, int *dv_len, FLK_BN_ULONG *rm, int *rm_len, FLK_BN_ULONG *num, int num_len, FLK_BN_ULONG *divisor, int divisor_len)
{
	int norm_shift, i, j, loop;
	FLK_BN_ULONG snum[131], sdiv[66], tmp[67], dvv[129];
	int snum_len, sdiv_len, wnum_len, res_len, tmp_len;
	FLK_BN_ULONG *wnum;
	FLK_BN_ULONG *res;
	FLK_BN_ULONG *resp, *wnump;
	FLK_BN_ULONG d0, d1;
	int num_n, div_n;
	
	if (BN_ucmp_sm2_ex(num, num_len, divisor, divisor_len) < 0)
	{
		//被除数小于除数的情况
		if (rm_len)
		{
			//拷贝被除数到余数
			for(i = 0; i < num_len; i++)
				rm[i] = num[i];
			for(; i < divisor_len; i++)
				rm[i] = 0;
			//余数的长度为被除数的长度
			*rm_len = num_len;
		}
		if (dv_len)
			*dv_len = 0;
		return;
	}

	if(dv != NULL)
		res = dv;
	else
		res = dvv;	

	/* First we normalise the numbers */
	norm_shift = FLK_BN_BITS2 - ((BN_num_bits_sm2_ex(divisor,divisor_len))%FLK_BN_BITS2);
	//这里sdiv向后有一个字的溢出,sdiv在尾部要留出一个字
	BN_lshift_sm2_ex(sdiv, &sdiv_len, divisor, divisor_len, norm_shift);
	norm_shift += FLK_BN_BITS2;
	//这里snum向后有一个字的溢出,snum在尾部要留出一个字
	BN_lshift_sm2_ex(snum, &snum_len, num, num_len, norm_shift);
	div_n = sdiv_len;
	num_n = snum_len;
	//loop为商的字数,由于这里num_n最大为128+2=130,div_n最小为1,
	//所以dvv定义dvv[129]
	loop = num_n - div_n;

	/* Lets setup a 'window' into snum
	 * This is the part that corresponds to the current
	 * 'area' being divided */
	wnum = &snum[loop];
	wnum_len = div_n;

	/* Get the top 2 words of sdiv */
	d0 = sdiv[div_n-1];
	d1 = (div_n == 1)?0:sdiv[div_n-2];

	/* pointer to the 'top' of snum */
	wnump = &snum[num_n-1];

	/* Setup to 'res' */
	res_len = loop;
	resp = &res[loop-1];

	if (BN_ucmp_sm2_ex(wnum, wnum_len, sdiv, sdiv_len) >= 0)
	{
		//由于sdiv最高字>B/2,所以商只可能为1
		BN_usub_sm2_ex(wnum, &wnum_len, wnum, wnum_len, sdiv, sdiv_len);
		*resp = 1;
	}
	else
		res_len--;
	resp--;

	for (i = 0; i < loop - 1; i++)
	{
		FLK_BN_ULONG q, l0;
		FLK_BN_ULONG n0, n1, rem=0;

		n0 = wnump[0];
		n1 = wnump[-1];
		if (n0 == d0)
			q = FLK_BN_MASK2;
		else 			/* n0 < d0 */
		{
			FLK_BN_ULONG t2l, t2h, ql, qh;

			q = bn_div_words_sm2_ex(n0, n1, d0);
			rem = (n1 - q*d0) & FLK_BN_MASK2;

			t2l = LBITS(d1); t2h = HBITS(d1);
			ql = LBITS(q);  qh = HBITS(q);
			mul64(t2l, t2h, ql, qh); /* t2=(BN_ULLONG)d1*q; */

			//试商检验
			for (;;)
			{
				if ((t2h < rem) ||
					((t2h == rem) && (t2l <= wnump[-2])))
					break;
				q--;
				rem += d0;
				if (rem < d0) break; /* don't let rem overflow */
				if (t2l < d1) t2h--; t2l -= d1;
			}
		}

		//做进一步的试商检验

		//由于这里的乘法,tmp比sdiv多一字
		l0 = bn_mul_words_sm2_ex(tmp, sdiv, div_n, q);
		//看wnum和wnum_len的初值
		wnum--; wnum_len++;

		tmp[div_n] = l0;
		for (j = div_n + 1; j > 0; j--)
			if (tmp[j-1]) break;
		tmp_len = j;

		j=wnum_len;

		if (BN_ucmp_sm2_ex(wnum, wnum_len, tmp, tmp_len) >= 0)
		{
			BN_usub_sm2_ex(wnum, &wnum_len, wnum, wnum_len, tmp, tmp_len);

			snum_len = snum_len + wnum_len - j;
		}
		else
		{
			BN_usub_sm2_ex(wnum, &wnum_len, tmp, tmp_len, wnum, wnum_len);

			snum_len = snum_len + wnum_len - j;

			q--;
			j = wnum_len;
			BN_usub_sm2_ex(wnum, &wnum_len, sdiv, sdiv_len, wnum, wnum_len);
			snum_len = snum_len + wnum_len - j;
		}
		
		*(resp--) = q;
		wnump--;
	}
	if (rm)
		//norm_shift向后有一字的溢出,所以rm要多定义一个字
		BN_rshift_sm2_ex(rm, rm_len, snum, snum_len, norm_shift);

	if(dv_len != NULL)
		*dv_len = res_len;
	
	return;
}

//////////////////////////////////////////////
//											//
//	函数功能:								//
//		计算a对n的乘法逆					//
//	函数参数:								//
//		a:in								//
//		a_len:in,a的字长				    //
//		n:in								//
//		n_len:in,n的字长					//
//		in:out,a对n的乘法逆					//							
//		in_len:out,乘法逆的字长				//
//	函数返回:								//
//		无									//
//											//
//////////////////////////////////////////////

void BN_mod_inverse_sm2_ex(FLK_BN_ULONG *in, int *in_len, FLK_BN_ULONG *a, int a_len, FLK_BN_ULONG *n, int n_len)
{
	FLK_BN_ULONG *A, *B, *X, *Y, *M, *D, *T;
	FLK_BN_ULONG *R;
	int A_len, B_len, X_len, Y_len, M_len, D_len, T_len;
	int sign;
	int i;
	
	//根据测试,A,B,X,D,M,Y都分配最大64字节,
	//由于BN_mul,BN_uadd有1字溢出,所以A,B,X,D,M,Y加大了4字节
	
	A = (FLK_BN_ULONG *)malloc(80+4);	
	B = (FLK_BN_ULONG *)malloc(80+4);
	X = (FLK_BN_ULONG *)malloc(80+4);
	D = (FLK_BN_ULONG *)malloc(80+4);
	M = (FLK_BN_ULONG *)malloc(80+4);
	Y = (FLK_BN_ULONG *)malloc(80+4);
	
	R = in;
	
	X_len = 0;
	Y[0] = 1; Y_len = 1;
	for(i = 0; i < a_len; i++)
		A[i] = a[i];
	A_len = a_len;
	for(i = 0; i < n_len; i++)
		B[i] = n[i];
	B_len = n_len;
	
	sign = 1;
	
	while (B_len)
	{
		BN_div_sm2_ex(D, &D_len, M, &M_len, A, A_len, B, B_len); 
		T = A; T_len = A_len;
		A = B; A_len = B_len;
		B = M; B_len = M_len;
		
		BN_mul_sm2_ex(T, &T_len, D, D_len, X, X_len);
		BN_uadd_sm2_ex(T, &T_len, T, T_len, Y, Y_len);
		
		M = Y; M_len = Y_len;
		Y = X; Y_len = X_len;
		X = T; X_len = T_len;
		sign = -sign;
	}
	if (sign < 0)
		BN_usub_sm2_ex(Y, &Y_len, n, n_len, Y, Y_len);
	
	BN_div_sm2_ex(NULL, NULL, R, in_len, Y, Y_len, n, n_len);
	
	free(A);
	free(B);
	free(X);
	free(D);
	free(M);
	free(Y);
}

void BN_mod_add_sm2_ex(FLK_BN_ULONG *r, FLK_BN_ULONG *a, FLK_BN_ULONG *b, FLK_BN_ULONG *m, FLK_BN_ULONG mLen)
{
   int rl;

   BN_uadd_sm2_ex(r, &rl, a, mLen, b, mLen);
   if(BN_ucmp_sm2_ex(r, rl, m, mLen) >= 0)	//r >= m
   {
       BN_usub_sm2_ex(r, &rl, r, rl, m, mLen);
   }
}

void BN_mod_sub_sm2_ex(FLK_BN_ULONG *r, int *rl, FLK_BN_ULONG *a, FLK_BN_ULONG *b, FLK_BN_ULONG *m, FLK_BN_ULONG mLen)
{
    if(BN_ucmp_sm2_ex(a, mLen, b, mLen) >= 0)	//a >= b
    {
	    BN_usub_sm2_ex(r, rl, a, mLen, b, mLen);
	}
	else
	{
	    FLK_BN_ULONG t[ECC_BLOCK_LEN_DWORD+2];
	    int tl;	    
	    BN_usub_sm2_ex(t, &tl, m, mLen, b, mLen);
		BN_uadd_sm2_ex(r, rl, a, mLen, t, tl);	
	}
}

void BN_mod_lshift1_sm2_ex(FLK_BN_ULONG *r, FLK_BN_ULONG *a, FLK_BN_ULONG *m, FLK_BN_ULONG mLen)
{
	FLK_BN_ULONG t0, t1, t2;
	FLK_BN_ULONG c, carry;
	int i;
	
	if(a[mLen-1] & 0x80000000)	//大于模数
		goto BN_mod_lshift1a;
		
	for(i = mLen - 1; i > 0; i--)
	{
		t0 = (a[i] << 1) + (a[i-1] >> 31);
		if(t0 > m[i])	//大于模数
		{
	BN_mod_lshift1a:
				c = 0;
				carry = 0;
				for(i = 0; i < (int)mLen; i++)
				{
						t0 = a[i];
						t1 = (t0 << 1) + c;
						t2 = m[i];
						r[i] = t1 - t2 - carry;
						if (t1 != t2) carry = (t1 < t2);
						c = t0 >> 31;
				}
				return;
		}	   
		if(t0 < m[i])	//小于模数
		{
				c = 0;
				for(i = 0;i < (int)mLen; i++)
				{
						t0 = a[i];
						t1 = (t0 << 1) + c;
						r[i] = t1;
						c = t0 >> 31;
				}
				return;
		}
	}
	
	t0 = (a[i]<<1);
	if(t0 > m[i])	//大于模数
	{
			c = 0;
			carry = 0;
			for(i = 0; i < (int)mLen; i++)
			{
					t0 = a[i];
					t1 = (t0 << 1) + c;
					t2 = m[i];
					r[i] = t1 - t2 - carry;
					if (t1 != t2) carry = (t1 < t2);
					c = t0 >> 31;
			}
			return;
	}	   
	if(t0 < m[i])	//小于模数
	{
			c = 0;
			for(i = 0; i < (int)mLen; i++)
			{
					t0 = a[i];
					t1 = (t0<<1) + c;
					r[i] = t1;
					c = t0 >> 31;
			}
			return;
	}
	
	memset(r, 0, mLen);
}

#define UL unsigned int
#define ULL unsigned long long

//////////////////////////////////////////////
//											//
//	函数功能:								//
//		由模数计算出n0、RR					//
//	函数参数:								//
//		Mod:in,模数							//
//		ModLen:in,模长						//
//		n0:out								//							
//		RR:out								//
//	函数返回:								//
//		无									//
//											//
//////////////////////////////////////////////

unsigned int count1_ex, count2_ex;

void BN_MONT_CTX_set_sm2_ex(FLK_BN_ULONG *Mod, int ModLen, FLK_BN_ULONG *n0, FLK_BN_ULONG *RR)
{
	FLK_BN_ULONG R[2];
	FLK_BN_ULONG tmod;
	FLK_BN_ULONG Ri[2];
	FLK_BN_ULONG tmp[ECC_BLOCK_LEN_DWORD*2+1];	
	int Ri_len;
	int RR_len;
	int i;

	FLK_BN_ULONG XX[8];
	int X_len, X_Rlen;
	FLK_BN_ULONG X_RET[8];

	count1_ex = 0;
	count2_ex = 0;
	// Ri = R^-1 mod N
	
	R[0]=0;
	R[1]=1;
	tmod=Mod[0];
	
	BN_mod_inverse_sm2_ex(&Ri[1], &Ri_len, R, 2, &tmod, 1);	

	// R*Ri-1  

	Ri[0] = 0xffffffff;Ri[1] -= 1;

	// Ni = (R*Ri-1)/N
	
	if(Ri[1])
		BN_div_sm2_ex(Ri, &Ri_len, NULL, NULL, Ri, 2, &tmod, 1);
	else
		BN_div_sm2_ex(Ri, &Ri_len, NULL, NULL, Ri, 1, &tmod, 1);
		
	*n0 = Ri[0];

	//基2^26
	R[0]=0x04000000;
	XX[0]=0;XX[1]=0;
	tmod &= 0x03ffffff;
	BN_mod_inverse_sm2_ex(XX, &X_len, &tmod, 1, R, 1);
	BN_mod_sub_sm2_ex(X_RET, &X_Rlen, R, XX, R, 1);
	

		
	for(i = 0; i < ModLen*2; i++)
		tmp[i] = 0;
	tmp[i] = 1;
		
	BN_div_sm2_ex(NULL, NULL, RR, &RR_len, tmp, ModLen*2+1, Mod, ModLen);
}

void BN_mod_mul_montgomery_sm2_ex(FLK_BN_ULONG *r, FLK_BN_ULONG *a, FLK_BN_ULONG *b, FLK_BN_ULONG *M, int M_Len, FLK_BN_ULONG n0)
{
	int i, j, k;
	UL /*ht, */lt, /*ht1, lt1, */carry, bb, m, u;
	int rl;
	ULL tmp, /*tmp1, */carry1 = 0;
	ULL ab,nm;
    UL c[64*2+1], *cp;

	cp = c;

	memset(c, 0, sizeof(c));

	for(i = 0; i < M_Len; i++)
	{
		u = *cp;
		
		carry = 0;
		carry1 = 0;
		bb = b[i];

		tmp = (ULL)a[0] * (ULL)bb;
		lt = (UL)tmp;
		m = (UL)((ULL)(lt+u) * (ULL)n0);

		for(j = 0; j < M_Len; j++)
		{
			ab = (ULL)a[j] * (ULL)bb;
			nm = (ULL)m * (ULL)M[j];

			tmp = ab + nm;
			carry = (tmp<ab);
			tmp += (ULL)cp[j];
			carry += (tmp<cp[j]);
			tmp += carry1;
			carry += (tmp<carry1);

			cp[j] = (UL)tmp;
			carry1 = (((ULL)carry)<<32) + (tmp>>32);
		}

		carry = (UL)carry1;			
		carry1 >>= 32;

		cp[j] += carry;
		k = j+1;
	
		if(cp[j] < carry)
		{
			//cp[k] += 1;
			//cp[k] += (UL)carry1;
			cp[k] = 1 + (UL)carry1;
		}
		else
			//cp[k] += (UL)carry1;
			cp[k] = (UL)carry1;
	
		cp++;
	}

	//判断乘积位数是否超过模数位数

	if(!carry1)
	{
		for(i = 0; i < M_Len; i++)
			r[i] = c[M_Len + i];

		if(BN_ucmp_sm2_ex(r, M_Len, M, M_Len) >= 0)
		{
			BN_usub_sm2_ex(r, &rl, r, M_Len, M, M_Len);
		}
	}
	else
		BN_usub_sm2_ex(r, &rl, &c[M_Len], M_Len+1, M, M_Len);
}

void BN_mod_mul_montgomery_one_sm2_ex(FLK_BN_ULONG *r, FLK_BN_ULONG *a, FLK_BN_ULONG *M, int M_Len, FLK_BN_ULONG n0)
{
	int i, j, k;
	UL ht1, lt1, carry, m, u;
	int rl;
	ULL tmp, tmp1, carry1 = 0;
    UL c[ECC_BLOCK_LEN_DWORD*2+1], *cp;
    int first = 1;

	cp = c;

	memset(c, 0, sizeof(c));

	for(i = 0; i < M_Len; i++)
	{
		u = *cp;
		
		carry = 0;
		carry1 = 0;
		
		if(first)
			m = (UL)((ULL)(a[0]+u) * (ULL)n0);
		else
			m = (UL)(u * n0);

		for(j = 0; j < M_Len; j++)
		{
			
			//n0*M
			
			tmp1 = (ULL)m * (ULL)M[j];
			ht1 = (UL)(tmp1>>32);
			lt1 = (UL)tmp1;

			//ci=ci+ai*bi+n0*M+carry
			
			if(first)
				tmp = (ULL)a[j] + (ULL)lt1;
			else
				tmp = (ULL)lt1;
			tmp += (ULL)cp[j];
			tmp += (ULL)carry;
			cp[j] = (UL)tmp;
			
			carry1 += (ULL)ht1;
			tmp >>= 32;
			carry1 += tmp;
			carry = (UL)carry1;			
			carry1 >>= 32;
		}
		cp[j] += carry;
		k = j+1;
	
		if(cp[j] < carry)
		{
			cp[k] += 1;
			cp[k] += (UL)carry1;
		}
		else
			cp[k] += (UL)carry1;
	
		cp++;

		if(first)
			first = 0;
	}

	//判断乘积位数是否超过模数位数
	
	if(!carry1)
	{
		for(i = 0; i < M_Len; i++)
			r[i] = c[M_Len + i];

		if(BN_ucmp_sm2_ex(r, M_Len, M, M_Len) >= 0)
		{
			BN_usub_sm2_ex(r, &rl, r, M_Len, M, M_Len);
		}
	}
	else
		BN_usub_sm2_ex(r, &rl, &c[M_Len], M_Len+1, M, M_Len);
}

void BN_mul_nomal_sm2_ex(FLK_BN_ULONG *r, FLK_BN_ULONG *a, int na, FLK_BN_ULONG *b, int nb)
{
	FLK_BN_ULONG *rr;	
	if (na < nb)
	{
		int itmp;
		FLK_BN_ULONG *ltmp;
		
		itmp = na; na = nb; nb = itmp;
		ltmp = a; a = b; b = ltmp;
		
	}
	rr = &(r[na]);
	rr[0] = bn_mul_words_sm2_ex(r, a, na, b[0]);
	
	for (;;)
	{
		if (--nb <= 0) return;
		rr[1] = bn_mul_add_words_sm2_ex(&(r[1]), a, na, b[1]);
		if (--nb <= 0) return;
		rr[2] = bn_mul_add_words_sm2_ex(&(r[2]), a, na, b[2]);
		if (--nb <= 0) return;
		rr[3] = bn_mul_add_words_sm2_ex(&(r[3]), a, na, b[3]);
		if (--nb <= 0) return;
		rr[4] = bn_mul_add_words_sm2_ex(&(r[4]), a, na, b[4]);
		rr += 4;
		r += 4;
		b += 4;
	}
}

void BN_mul_sm2_ex(FLK_BN_ULONG *r, int *rl, FLK_BN_ULONG *a, int al, FLK_BN_ULONG *b, int bl)
{
	if ((al == 0) || (bl == 0))
	{
		*rl = 0;
		return;
	}
	
	*rl = al + bl;	
    BN_mul_nomal_sm2_ex(r, a, al, b, bl);
	
	bn_fix_top_sm2_ex(r, rl);			
}

void BN_rshift1_sm2_ex(FLKBIGNUM *r, int *r_top, FLKBIGNUM *a, int a_top)
{
	FLK_BN_ULONG *ap, *rp, t, c;
	int i;	
	if(a_top == 0)
	{
		memset(r,0,FLK_BIGNUM_SIZE);
		*r_top = 0;
		return ;
	}
	
	ap = a->d;
	rp = r->d;
	c = 0;
	for(i = a_top-1; i >= 0; i--)
	{
		t = ap[i];
		rp[i] = (t >> 1) | c;
		c = (t & 1) ? FLK_BN_TBIT : 0;
	}
	
	if(r->d[a_top-1])
		*r_top = a_top;
	else
		*r_top = a_top-1;
}

int BN_lshift_sm2_ex(FLK_BN_ULONG *r, int *rl, FLK_BN_ULONG *a, int al, int n)
{
	int i, nw, lb, rb;
	FLK_BN_ULONG l;
	
	nw = n/FLK_BN_BITS2;
	lb = n%FLK_BN_BITS2;
	rb = FLK_BN_BITS2 - lb;
	r[al+nw] = 0;
	if (lb == 0)
		for (i = al - 1; i >= 0; i--)
			r[nw+i] = a[i];
		else
			for (i = al - 1; i >= 0; i--)
			{
				l=a[i];
				r[nw+i+1] |= (l >> rb) & FLK_BN_MASK2;
				r[nw+i] = (l << lb) & FLK_BN_MASK2;
			}
			memset(r, 0, nw*sizeof(r[0]));
			/*	for (i=0; i<nw; i++)
			t[i]=0;*/
			*rl = al + nw + 1;
			bn_fix_top_sm2_ex(r, rl);
			return(1);
}

int BN_rshift_sm2_ex(FLK_BN_ULONG *r, int *rl, FLK_BN_ULONG *a, int al, int n)
{
	int i, j, nw, lb, rb;
	FLK_BN_ULONG *t, *f;
	FLK_BN_ULONG l, tmp;
	
	nw = n / FLK_BN_BITS2;
	rb = n % FLK_BN_BITS2;
	lb = FLK_BN_BITS2 - rb;
	if (nw > al || al == 0)
	{
		memset(r, 0, FLK_BIGNUM_SIZE);
		*rl = 0;
		return 0;
	}
	
	f = &a[nw];
	t = r;
	j = al - nw;
	*rl = j;
	
	if (rb == 0)
	{
		for (i = j + 1; i > 0; i--)
			*(t++) = *(f++);
	}
	else
	{
		l = *(f++);
		for (i = 1; i < j; i++)
		{
			tmp = (l >> rb) & FLK_BN_MASK2;
			l = *(f++);
			*(t++) = (tmp | (l << lb)) & FLK_BN_MASK2;
		}
		*(t++) = (l >> rb) & FLK_BN_MASK2;
	}
	*t = 0;
	bn_fix_top_sm2_ex(r, rl);
	return(1);
}


//  判断2个大数是否相等,0 相等，1 不等
int two_number_same_ex(FLK_BN_ULONG *a, int len, FLK_BN_ULONG *b)
{
	int i;
	int sum =0;
	int hh;
	for(i=0;i<len;i++)
	{
	if( a[i] == b[i]) hh=0;
	 else hh =1;
	 sum  = sum +hh;
	}

	if(sum ==0) return 0;
	else return  1;
}

void ec_GFp_simple_point_get_affine_coordinates_GFp_ex(EC_GROUP *group, EC_POINT *point, FLKBIGNUM *x, FLKBIGNUM *y)
{
	FLKBIGNUM X, Y, Z, Z_1, Z_2, Z_3;
	int x_top, y_top;
	int Z_1_top, Z_2_top, Z_3_top;
	FLK_BN_ULONG temp[ECC_BLOCK_LEN_DWORD*2];
	int temp_top;

	/* transform  (X, Y, Z)  into  (x, y) := (X/Z^2, Y/Z^3) */
    BN_mod_mul_montgomery_one_sm2_ex(X.d, point->X.d, group->field.d, group->field_top, group->n0);
    BN_mod_mul_montgomery_one_sm2_ex(Y.d, point->Y.d, group->field.d, group->field_top, group->n0);
    BN_mod_mul_montgomery_one_sm2_ex(Z.d, point->Z.d, group->field.d, group->field_top, group->n0);
	
	if(BN_is_one_sm2_ex(Z.d, group->field_top))
	{
		memcpy(x, &X, FLK_BIGNUM_SIZE);
		memcpy(y, &Y, FLK_BIGNUM_SIZE);
	}
	else
	{
		BN_mod_inverse_sm2_ex(Z_1.d, &Z_1_top, Z.d, group->field_top, group->field.d, group->field_top);	
		BN_mul_sm2_ex(temp, &temp_top, Z_1.d, Z_1_top, Z_1.d, Z_1_top);
		BN_div_sm2_ex(NULL, NULL, Z_2.d, &Z_2_top, temp, temp_top, group->field.d, group->field_top);
		BN_mul_sm2_ex(temp, &temp_top, X.d, group->field_top, Z_2.d, Z_2_top);
		BN_div_sm2_ex(NULL, NULL, x->d, &x_top, temp, temp_top, group->field.d, group->field_top);
		BN_mul_sm2_ex(temp, &temp_top, Z_2.d, Z_2_top, Z_1.d, Z_1_top);
		BN_div_sm2_ex(NULL, NULL, Z_3.d, &Z_3_top, temp, temp_top, group->field.d, group->field_top);
		BN_mul_sm2_ex(temp, &temp_top, Z_3.d, Z_3_top, Y.d, group->field_top);
		BN_div_sm2_ex(NULL, NULL,y->d, &y_top, temp, temp_top, group->field.d, group->field_top);
	}
}

void ec_GFp_simple_add_sm2_ex(EC_GROUP *group, EC_POINT *r, EC_POINT *a, EC_POINT *b)
{
	int top1, top2;
	FLKBIGNUM n0, n1, n2, n3, n4, n5, n6;
	
	if(a == b)
	{
		ec_GFp_simple_dbl_sm2_ex(group, r, a);
		return;
	}
	if(ec_GFp_simple_is_at_infinity_sm2_ex(group, a))
	{
		memcpy(r, b, sizeof(EC_POINT));
		return;
	}
	if(ec_GFp_simple_is_at_infinity_sm2_ex(group, b))
	{
		memcpy(r, a, sizeof(EC_POINT));
		return;
	}

	//if (a == b)
	//	return EC_POINT_dbl(group, r, a, ctx);
	//if (EC_POINT_is_at_infinity(group, a))
	//	return EC_POINT_copy(r, b);
	//if (EC_POINT_is_at_infinity(group, b))
	//	return EC_POINT_copy(r, a);

	/* n1, n2 */
	if (b->Z_is_one)
	{
		memcpy(&n1, &a->X, FLK_BIGNUM_SIZE);
		memcpy(&n2, &a->Y, FLK_BIGNUM_SIZE);
		/* n1 = X_a */
		/* n2 = Y_a */
	}
	else
	{
		BN_mod_mul_montgomery_sm2_ex(n0.d, b->Z.d, b->Z.d, group->field.d, group->field_top, group->n0);
		BN_mod_mul_montgomery_sm2_ex(n1.d, a->X.d, n0.d, group->field.d, group->field_top, group->n0);
		//field_sqr(group, n0, &b->Z, ctx)) goto end;
		//if (!field_mul(group, n1, &a->X, n0, ctx)) goto end;
		/* n1 = X_a * Z_b^2 */

		BN_mod_mul_montgomery_sm2_ex(n0.d, n0.d, b->Z.d, group->field.d, group->field_top, group->n0);
		BN_mod_mul_montgomery_sm2_ex(n2.d, a->Y.d, n0.d, group->field.d, group->field_top, group->n0);
		//if (!field_mul(group, n0, n0, &b->Z, ctx)) goto end;
		//if (!field_mul(group, n2, &a->Y, n0, ctx)) goto end;
		/* n2 = Y_a * Z_b^3 */
	}

	/* n3, n4 */
	if (a->Z_is_one)
	{
		memcpy(&n3, &b->X, FLK_BIGNUM_SIZE);
		memcpy(&n4, &b->Y, FLK_BIGNUM_SIZE);
		//if (!BN_copy(n3, &b->X)) goto end;
		//if (!BN_copy(n4, &b->Y)) goto end;
		/* n3 = X_b */
		/* n4 = Y_b */
	}
	else
	{
		BN_mod_mul_montgomery_sm2_ex(n0.d, a->Z.d, a->Z.d, group->field.d, group->field_top, group->n0);
		BN_mod_mul_montgomery_sm2_ex(n3.d, b->X.d, n0.d, group->field.d, group->field_top, group->n0);
		//if (!field_sqr(group, n0, &a->Z, ctx)) goto end;
		//if (!field_mul(group, n3, &b->X, n0, ctx)) goto end;
		/* n3 = X_b * Z_a^2 */

		BN_mod_mul_montgomery_sm2_ex(n0.d, n0.d, a->Z.d, group->field.d, group->field_top, group->n0);
		BN_mod_mul_montgomery_sm2_ex(n4.d, b->Y.d, n0.d, group->field.d, group->field_top, group->n0);
		//if (!field_mul(group, n0, n0, &a->Z, ctx)) goto end;
		//if (!field_mul(group, n4, &b->Y, n0, ctx)) goto end;
		/* n4 = Y_b * Z_a^3 */
	}

	/* n5, n6 */
    BN_mod_sub_sm2_ex(n5.d, &top1, n1.d, n3.d, group->field.d, group->field_top);
    BN_mod_sub_sm2_ex(n6.d, &top2, n2.d, n4.d, group->field.d, group->field_top);
	//if (!BN_mod_sub_quick(n5, n1, n3, p)) goto end;
	//if (!BN_mod_sub_quick(n6, n2, n4, p)) goto end;
	/* n5 = n1 - n3 */
	/* n6 = n2 - n4 */

	if(!top1)
	{
		if(!top2)
		{
			ec_GFp_simple_dbl_sm2_ex(group, r, a);
			return;
		}
		else
		{
			memset(&r->Z, 0, FLK_BIGNUM_SIZE);
			r->Z_is_one = 0;
			return;
		}
	}

	/* 'n7', 'n8' */
    BN_mod_add_sm2_ex(n1.d, n1.d, n3.d, group->field.d, group->field_top);
    BN_mod_add_sm2_ex(n2.d, n2.d, n4.d, group->field.d, group->field_top);
	//if (!BN_mod_add_quick(n1, n1, n3, p)) goto end;
	//if (!BN_mod_add_quick(n2, n2, n4, p)) goto end;
	/* 'n7' = n1 + n3 */
	/* 'n8' = n2 + n4 */

	/* Z_r */
	if (a->Z_is_one && b->Z_is_one)
	{
			memcpy(&r->Z, &n5, FLK_BIGNUM_SIZE);
		  //if (!BN_copy(&r->Z, n5)) goto end;
	}
	else
	{
		if (a->Z_is_one)
		{ 
			memcpy(&n0, &b->Z, FLK_BIGNUM_SIZE);
			//{ if (!BN_copy(n0, &b->Z)) goto end; }
		}
		else if (b->Z_is_one)
		{ 
			memcpy(&n0, &a->Z, FLK_BIGNUM_SIZE);
			//{ if (!BN_copy(n0, &a->Z)) goto end; }
		}
		else
		{ 
			BN_mod_mul_montgomery_sm2_ex(n0.d, a->Z.d, b->Z.d, group->field.d, group->field_top, group->n0);
			//if (!field_mul(group, n0, &a->Z, &b->Z, ctx)) goto end; 
		}
		BN_mod_mul_montgomery_sm2_ex(r->Z.d, n0.d, n5.d, group->field.d, group->field_top, group->n0);
		//if (!field_mul(group, &r->Z, n0, n5, ctx)) goto end;
	}
	r->Z_is_one = 0;
	/* Z_r = Z_a * Z_b * n5 */

	/* X_r */
	BN_mod_mul_montgomery_sm2_ex(n0.d, n6.d, n6.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2_ex(n4.d, n5.d, n5.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2_ex(n3.d, n1.d, n4.d, group->field.d, group->field_top, group->n0);
    BN_mod_sub_sm2_ex(r->X.d, &top1, n0.d, n3.d, group->field.d, group->field_top);
	//if (!field_sqr(group, n0, n6, ctx)) goto end;
	//if (!field_sqr(group, n4, n5, ctx)) goto end;
	//if (!field_mul(group, n3, n1, n4, ctx)) goto end;
	//if (!BN_mod_sub_quick(&r->X, n0, n3, p)) goto end;
	/* X_r = n6^2 - n5^2 * 'n7' */
	
	/* 'n9' */
	BN_mod_lshift1_sm2_ex(n0.d, r->X.d, group->field.d, group->field_top);
	BN_mod_sub_sm2_ex(n0.d, &top1, n3.d, n0.d, group->field.d, group->field_top);
	//if (!BN_mod_lshift1_quick(n0, &r->X, p)) goto end;
	//if (!BN_mod_sub_quick(n0, n3, n0, p)) goto end;
	/* n9 = n5^2 * 'n7' - 2 * X_r */

	/* Y_r */
	BN_mod_mul_montgomery_sm2_ex(n0.d, n0.d, n6.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2_ex(n5.d, n4.d, n5.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2_ex(n1.d, n2.d, n5.d, group->field.d, group->field_top, group->n0);
	BN_mod_sub_sm2_ex(n0.d, &top1, n0.d, n1.d, group->field.d, group->field_top);
	if(n0.d[0] & 1)
	{
		BN_uadd_sm2_ex(n0.d, &top1, n0.d, group->field_top, group->field.d, group->field_top);
		BN_rshift_sm2_ex(r->Y.d, &top1, n0.d, top1, 1);
	}
	else
		BN_rshift_sm2_ex(r->Y.d, &top1, n0.d, group->field_top, 1);
}

void ec_GFp_simple_dbl_sm2_ex(EC_GROUP *group, EC_POINT *r, EC_POINT *a)
{
	int top;
	FLKBIGNUM n0, n1, n2, n3;
	
	if(ec_GFp_simple_is_at_infinity_sm2_ex(group, a))
	{
		memset(&r->Z, 0, FLK_BIGNUM_SIZE);
		r->Z_is_one = 0;
		return;
	}

	//if (EC_POINT_is_at_infinity(group, a))
	//	{
	//	if (!BN_zero(&r->Z)) return 0;
	//	r->Z_is_one = 0;
	//	return 1;
	//	}
	
	/* n2 */
	BN_mod_mul_montgomery_sm2_ex(n3.d, a->Y.d, a->Y.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2_ex(n2.d, a->X.d, n3.d, group->field.d, group->field_top, group->n0);
	BN_mod_lshift1_sm2_ex(n2.d, n2.d, group->field.d, group->field_top);
	BN_mod_lshift1_sm2_ex(n2.d, n2.d, group->field.d, group->field_top);
	//if (!field_sqr(group, n3, &a->Y, ctx)) goto err;
	//if (!field_mul(group, n2, &a->X, n3, ctx)) goto err;
	//if (!BN_mod_lshift_quick(n2, n2, 2, p)) goto err;
	/* n2 = 4 * X_a * Y_a^2 */

	/* n3 */
	BN_mod_mul_montgomery_sm2_ex(n0.d, n3.d, n3.d, group->field.d, group->field_top, group->n0);
	BN_mod_lshift1_sm2_ex(n3.d, n0.d, group->field.d, group->field_top);
	BN_mod_lshift1_sm2_ex(n3.d, n3.d, group->field.d, group->field_top);
	BN_mod_lshift1_sm2_ex(n3.d, n3.d, group->field.d, group->field_top);
	//if (!field_sqr(group, n0, n3, ctx)) goto err;
	//if (!BN_mod_lshift_quick(n3, n0, 3, p)) goto err;
	/* n3 = 8 * Y_a^4 */


	/* n1 */
	if (a->Z_is_one)
	{
		BN_mod_mul_montgomery_sm2_ex(n0.d, a->X.d, a->X.d, group->field.d, group->field_top, group->n0);
		BN_mod_lshift1_sm2_ex(n1.d, n0.d, group->field.d, group->field_top);
		BN_mod_add_sm2_ex(n0.d, n0.d, n1.d, group->field.d, group->field_top);
		BN_mod_add_sm2_ex(n1.d, n0.d, group->a.d, group->field.d, group->field_top);

		//if (!field_sqr(group, n0, &a->X, ctx)) goto err;
		//if (!BN_mod_lshift1_quick(n1, n0, p)) goto err;
		//if (!BN_mod_add_quick(n0, n0, n1, p)) goto err;
		//if (!BN_mod_add_quick(n1, n0, &group->a, p)) goto err;
		/* n1 = 3 * X_a^2 + a_curve */
	}
	else
	{
		BN_mod_mul_montgomery_sm2_ex(n0.d, a->X.d, a->X.d, group->field.d, group->field_top, group->n0);
		BN_mod_lshift1_sm2_ex(n1.d, n0.d, group->field.d, group->field_top);
		BN_mod_add_sm2_ex(n0.d, n0.d, n1.d, group->field.d, group->field_top);
		BN_mod_mul_montgomery_sm2_ex(n1.d, a->Z.d, a->Z.d, group->field.d, group->field_top, group->n0);
		BN_mod_mul_montgomery_sm2_ex(n1.d, n1.d, n1.d, group->field.d, group->field_top, group->n0);
		BN_mod_mul_montgomery_sm2_ex(n1.d, n1.d, group->a.d, group->field.d, group->field_top, group->n0);
		BN_mod_add_sm2_ex(n1.d, n1.d, n0.d, group->field.d, group->field_top);
		
		//if (!field_sqr(group, n0, &a->X, ctx)) goto err;
		//if (!BN_mod_lshift1_quick(n1, n0, p)) goto err;
		//if (!BN_mod_add_quick(n0, n0, n1, p)) goto err;
		//if (!field_sqr(group, n1, &a->Z, ctx)) goto err;
		//if (!field_sqr(group, n1, n1, ctx)) goto err;
		//if (!field_mul(group, n1, n1, &group->a, ctx)) goto err;
		//if (!BN_mod_add_quick(n1, n1, n0, p)) goto err;
		/* n1 = 3 * X_a^2 + a_curve * Z_a^4 */
	}

	/* Z_r */
	if (a->Z_is_one)
	{
		memcpy(&n0, &a->Y, FLK_BIGNUM_SIZE);	
		//if (!BN_copy(n0, &a->Y)) goto err;
	}
	else
	{
		BN_mod_mul_montgomery_sm2_ex(n0.d, a->Y.d, a->Z.d, group->field.d, group->field_top, group->n0);
		//if (!field_mul(group, n0, &a->Y, &a->Z, ctx)) goto err;
	}
	BN_mod_lshift1_sm2_ex(r->Z.d, n0.d, group->field.d, group->field_top);
	//if (!BN_mod_lshift1_quick(&r->Z, n0, p)) goto err;
	r->Z_is_one = 0;
	/* Z_r = 2 * Y_a * Z_a */

	

	/* X_r */
	BN_mod_lshift1_sm2_ex(n0.d, n2.d, group->field.d, group->field_top);
	BN_mod_mul_montgomery_sm2_ex(r->X.d, n1.d, n1.d, group->field.d, group->field_top, group->n0);
    BN_mod_sub_sm2_ex(r->X.d, &top, r->X.d, n0.d, group->field.d, group->field_top);
	//if (!BN_mod_lshift1_quick(n0, n2, p)) goto err;
	//if (!field_sqr(group, &r->X, n1, ctx)) goto err;
	//if (!BN_mod_sub_quick(&r->X, &r->X, n0, p)) goto err;
	/* X_r = n1^2 - 2 * n2 */
	
	
	
	/* Y_r */
	BN_mod_sub_sm2_ex(n0.d, &top, n2.d, r->X.d, group->field.d, group->field_top);
	BN_mod_mul_montgomery_sm2_ex(n0.d, n1.d, n0.d, group->field.d, group->field_top, group->n0);
	BN_mod_sub_sm2_ex(r->Y.d, &top, n0.d, n3.d, group->field.d, group->field_top);

	//if (!BN_mod_sub_quick(n0, n2, &r->X, p)) goto err;
	//if (!field_mul(group, n0, n1, n0, ctx)) goto err;
	//if (!BN_mod_sub_quick(&r->Y, n0, n3, p)) goto err;
	/* Y_r = n1 * (n2 - X_r) - n3 */
}

int ec_GFp_simple_invert_sm2_ex(EC_GROUP *group, EC_POINT *point, EC_POINT *out)
{
	if (ec_GFp_simple_is_at_infinity_sm2_ex((EC_GROUP *)group, point) || BN_is_zero_sm2_ex(point->Y.d, group->field_top))
	{
		/* point is its own inverse */
		printf("ec_GFp_simple_invert_sm2_ex err!!!\n");
		return 1;
	}
	int rl;
	return BN_usub_sm2_ex(out->Y.d, &rl, group->field.d,  group->field_top, point->Y.d, group->field_top);
}

int ec_GFp_simple_is_at_infinity_sm2_ex(EC_GROUP *group, EC_POINT *point)
{
	return BN_is_zero_sm2_ex(point->Z.d, group->field_top);
}



/* Determine the width-(w+1) Non-Adjacent Form (wNAF) of 'scalar'.
 * This is an array  r[]  of values that are either zero or odd with an
 * absolute value less than  2^w  satisfying
 *     scalar = \sum_j r[j]*2^j
 * where at most one of any  w+1  consecutive digits is non-zero.
 */

int BN_is_bit_set_sm2_ex(FLKBIGNUM *a, int n)
{
	int i,j;
	int len;

	len=8;
	bn_fix_top_sm2_ex(a->d, &len);
	if (n < 0) return 0;
	i=n/FLK_BN_BITS2;
	j=n%FLK_BN_BITS2;
	if (len <= i) return 0;

	return (int)(((a->d[i])>>j)&((FLK_BN_ULONG)1));
}


/* Determine the modified width-(w+1) Non-Adjacent Form (wNAF) of 'scalar'.
 * This is an array  r[]  of values that are either zero or odd with an
 * absolute value less than  2^w  satisfying
 *     scalar = \sum_j r[j]*2^j
 * where at most one of any  w+1  consecutive digits is non-zero
 * with the exception that the most significant digit may be only
 * w-1 zeros away from that next non-zero digit.
 */
signed char *compute_wNAF_openssl_ex(FLKBIGNUM *scalar, int w, int *ret_len)
{
	int window_val;
	int ok = 0;
	signed char *r = NULL;
	int sign = 1;
	int bit, next_bit, mask;
	int len = 0, j;
	FLKBIGNUM c;


	bit = 1 << w; /* at most 128 */
	next_bit = bit << 1; /* at most 256 */
	mask = next_bit - 1; /* at most 255 */
	memcpy(&c, scalar, FLK_BIGNUM_SIZE);
	
	len = BN_num_bits_sm2_ex(c.d, 8);
	r = (signed char*)malloc(len + 1); /* modified wNAF may be one digit longer than binary representation
	                              * (*ret_len will be set to the actual length, i.e. at most
	                              * BN_num_bits_sm2_ex(scalar) + 1) */
	
	window_val = scalar->d[0] & mask;
	j = 0;
	while ((window_val != 0) || (j + w + 1 < len)) /* if j+w+1 >= len, window_val will not increase */
		{
		int digit = 0;
		/* 0 <= window_val <= 2^(w+1) */

		if (window_val & 1)
			{
			/* 0 < window_val < 2^(w+1) */

			if (window_val & bit)
				{
				digit = window_val - next_bit; /* -2^w < digit < 0 */

				if (j + w + 1 >= len)
					{
					/* special case for generating modified wNAFs:
					 * no new bits will be added into window_val,
					 * so using a positive digit here will decrease
					 * the total length of the representation */
					
					digit = window_val & (mask >> 1); /* 0 < digit < 2^w */
					}
				}
			else
				{
				digit = window_val; /* 0 < digit < 2^w */
				}
			
			if (digit <= -bit || digit >= bit || !(digit & 1))
				return NULL;

			window_val -= digit;

			/* now window_val is 0 or 2^(w+1) in standard wNAF generation;
			 * for modified window NAFs, it may also be 2^w
			 */
			if (window_val != 0 && window_val != next_bit && window_val != bit)
				return NULL;
			}

		r[j++] = sign * digit;
		window_val >>= 1;
		window_val += bit * BN_is_bit_set_sm2_ex(scalar, j + w);
		
		if (window_val > next_bit)
			return NULL;
		}


	if (j > len + 1)
		return NULL;
	len = j;
	ok = 1;

 //err:
	if (!ok)
		{
		free(r);
		r = NULL;
		}
	if (ok)
		*ret_len = len;
	return r;
}


signed char *compute_wNAF_ex(FLKBIGNUM *scalar, int w, int order_top, int *ret_len)
{
	int top;
	FLKBIGNUM c;
	signed char *r;
	int bit, next_bit, mask;
	FLK_BN_ULONG len = 0, j;
	
	bit = 1 << w; /* at most 128 */
	next_bit = bit << 1; /* at most 256 */
	mask = next_bit - 1; /* at most 255 */

	memcpy(&c, scalar, FLK_BIGNUM_SIZE);

	top = order_top;
	
	len = BN_num_bits_sm2_ex(c.d, top) + 1; /* wNAF may be one digit longer than binary representation */
	r = (signed char *)malloc(len);

	j = 0;
	while (top)
	{
		int u = 0, u1;

		if (c.d[0] & 1) 
		{
			u = c.d[0] & mask;
			if (u & bit)
			{
				u -= next_bit;
				/* u < 0 */
				//c.d[0] -= u;
				u1 = -u;
                BN_uadd_sm2_ex(c.d, &top, c.d, top, (FLK_BN_ULONG *)&u1, 1);
			}
			else
			{
				/* u > 0 */
				//c.d[0] -= u;
				u1 = u;
                BN_usub_sm2_ex(c.d, &top, c.d, top, (FLK_BN_ULONG *)&u1, 1);
			}
		}

		r[j++] = u;
				
		BN_rshift1_sm2_ex(&c, &top, &c, top);
	}

	*ret_len = j;

	return r;
}

#define EC_window_bits_for_scalar_size(b) \
		((b) >=  300 ? 4 : \
		 (b) >=   70 ? 3 : \
		 (b) >=   20 ? 2 : \
		  1)

/*	计算 R = kP 或 R = kP + lQ	*/

void EC_POINTs_mul_sm2_ex(EC_GROUP *group, EC_POINT *R, EC_POINT *P, FLKBIGNUM *k, EC_POINT *Q, FLKBIGNUM *l) 
{
	EC_POINT tmp;
	int num;
	int totalnum;
	int i, j;
	int kk;
	int r_is_inverted = 0;
	int r_is_at_infinity = 1;
	int top;
	int wsize[2]; /* individual window sizes */
	int wNAF_len[2];
	int max_len = 0;
	int num_val;
	signed char **wNAF; /* individual wNAFs */
	EC_POINT val_sub[2][16]; /* pointers to sub-arrays of 'val' */
	
	if(l == NULL)
	{
		totalnum = 1;
		num = 0;
	}
	else
	{
		totalnum = 2;
		num = 1;
	}
			
	wNAF = (signed char **)malloc((totalnum + 1) * sizeof wNAF[0]);

	/* num_val := total number of points to precompute */
	num_val = 0;
	for (i = 0; i < totalnum; i++)
	{
		int bits;

		bits = i < num ? BN_num_bits_sm2_ex(l->d,group->order_top) : BN_num_bits_sm2_ex(k->d,group->order_top);
		wsize[i] = EC_window_bits_for_scalar_size(bits);
		num_val += 1 << (wsize[i] - 1);
	}

	/* prepare precomputed values:
	 *    val_sub[i][0] :=     points[i]
	 *    val_sub[i][1] := 3 * points[i]
	 *    val_sub[i][2] := 5 * points[i]
	 *    ...
	 */
	for (i = 0; i < totalnum; i++)
	{
		if (i < num)
		{
			memcpy(&val_sub[i][0], Q, sizeof(EC_POINT));		
		}
		else
		{
			memcpy(&val_sub[i][0], P, sizeof(EC_POINT));		
		}

		if (wsize[i] > 1)
		{
		    ec_GFp_simple_dbl_sm2_ex(group, &tmp, &val_sub[i][0]);

			for (j = 1; j < (int)(1u << (wsize[i] - 1)); j++)
			{
				ec_GFp_simple_add_sm2_ex(group, &val_sub[i][j], &val_sub[i][j - 1], &tmp);
			}
		}
		wNAF[i + 1] = 0; 

		//by wuwentai modified bug
		wNAF[i] = compute_wNAF_openssl_ex((i < num ? l : k), wsize[i], &wNAF_len[i]);
		if (wNAF_len[i] > max_len)
			max_len = wNAF_len[i];
		}

	r_is_at_infinity = 1;

	for (kk = max_len - 1; kk >= 0; kk--)
	{
		if (!r_is_at_infinity)
		{
		  ec_GFp_simple_dbl_sm2_ex(group, R, R);
		}
		
		for (i = 0; i < totalnum; i++)
		{
			if (wNAF_len[i] > kk)
			{
				int digit = wNAF[i][kk];
				int is_neg;

				if (digit) 
				{
					is_neg = digit < 0;

					if (is_neg)
						digit = -digit;

					if (is_neg != r_is_inverted)
					{
						if (!r_is_at_infinity)
						{
							if(ec_GFp_simple_is_at_infinity_sm2_ex(group, R) || BN_is_zero_sm2_ex(R->Y.d, group->field_top))
							{
								;
							}
							else
							{
								BN_usub_sm2_ex(R->Y.d, &top, group->field.d, group->field_top, R->Y.d, group->field_top);
							}

						}
						r_is_inverted = !r_is_inverted;
					}

					/* digit > 0 */

					if (r_is_at_infinity)
					{
						memcpy(R, &val_sub[i][digit >> 1], sizeof(EC_POINT));
						r_is_at_infinity = 0;
					}
					else
					{
						ec_GFp_simple_add_sm2_ex(group, R, R, &val_sub[i][digit >> 1]);
					}
				}
			}
		}
	}

	if (r_is_inverted)
        BN_usub_sm2_ex(R->Y.d, &top, group->field.d, group->field_top, R->Y.d, group->field_top);

	if (wNAF != 0)
	{
		signed char **w;
		
		for (w = wNAF; *w != 0; w++)
			free(*w);
		
		free(wNAF);
	}
}

void ECC_InitParameter_ex(ECCParameter *pECCPara,EC_GROUP *group)
{
	int i;
	int dwords;
	unsigned char t[ECC_BLOCK_LEN];
	FLK_BN_ULONG tmp[ECC_BLOCK_LEN_DWORD];			
	memset(group,0,sizeof(EC_GROUP));
		
	//初始化p
	for(i = 0; i < ECC_BLOCK_LEN; i++)
		t[i] = pECCPara->p[ECC_BLOCK_LEN-1-i];
    memcpy(group->field.d, t, ECC_BLOCK_LEN);								
     	
	//初始化a

	for(i = 0; i < ECC_BLOCK_LEN; i++)
		t[i] = pECCPara->a[ECC_BLOCK_LEN-1-i];
    memcpy(group->a.d, t, ECC_BLOCK_LEN);								

	//初始化b

	for(i = 0; i < ECC_BLOCK_LEN; i++)
		t[i] = pECCPara->b[ECC_BLOCK_LEN-1-i];
    memcpy(group->b.d, t, ECC_BLOCK_LEN);								

	//初始化基点
	
	for(i = 0; i < ECC_BLOCK_LEN; i++)
		t[i] = pECCPara->Gx[ECC_BLOCK_LEN-1-i];
    memcpy(group->generator.X.d, t, ECC_BLOCK_LEN);								

	for(i = 0; i < ECC_BLOCK_LEN; i++)
		t[i] = pECCPara->Gy[ECC_BLOCK_LEN-1-i];
    memcpy(group->generator.Y.d, t, ECC_BLOCK_LEN);								

	//确定模长
	
    dwords = ECC_BLOCK_LEN_DWORD;
    bn_fix_top_sm2_ex(group->field.d,&dwords);
	
	group->field_top=dwords;

	//初始化阶

	for(i = 0; i < ECC_BLOCK_LEN; i++)
		t[i] = pECCPara->Gn[ECC_BLOCK_LEN-1-i];
    memcpy(group->order.d, t, ECC_BLOCK_LEN);								
	
	//确定阶长
	
    dwords = ECC_BLOCK_LEN_DWORD;
    bn_fix_top_sm2_ex(group->order.d, &dwords);
	
	group->order_top = dwords;

	BN_MONT_CTX_set_sm2_ex(group->field.d, group->field_top, &group->n0, group->RR.d);
		
	memset(tmp,0,sizeof(tmp));
	tmp[0]=1;		

	BN_mod_mul_montgomery_sm2_ex(group->field_data2.d, tmp, group->RR.d, group->field.d, group->field_top, group->n0);

	BN_mod_mul_montgomery_sm2_ex(group->a.d, group->a.d, group->RR.d, group->field.d, group->field_top, group->n0);

	BN_mod_mul_montgomery_sm2_ex(group->b.d, group->b.d, group->RR.d, group->field.d, group->field_top, group->n0);

	BN_mod_mul_montgomery_sm2_ex(group->generator.X.d, group->generator.X.d, group->RR.d, group->field.d, group->field_top, group->n0);

	BN_mod_mul_montgomery_sm2_ex(group->generator.Y.d, group->generator.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);

	memcpy(group->generator.Z.d, group->field_data2.d, FLK_BIGNUM_SIZE);
	
    group->generator.Z_is_one = 1;

	srand( (unsigned)time( NULL ) );
}

void ECC_GenerateKeyPair_ex(EC_GROUP *group, ECC_PUBLIC_KEY *pECCPK, ECC_PRIVATE_KEY *pECCSK)
{
	int i;
	FLKBIGNUM k;
	FLKBIGNUM x, y;
	EC_POINT R;
    unsigned char t[ECC_BLOCK_LEN];
	unsigned char Ka_256[ECC_BLOCK_LEN];

	memset(&k, 0, FLK_BIGNUM_SIZE);
	memset(&x, 0, FLK_BIGNUM_SIZE);
	memset(&y, 0, FLK_BIGNUM_SIZE);

	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		Ka_256[i] = (unsigned char)((rand() % 255) + 1);//SK,1<=SK<=n-1 
	}                    
	
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = Ka_256[31-i];
	}
	memcpy(k.d, t, ECC_BLOCK_LEN);

  	//1 <= k <= n-1
	while(k.d[ECC_BLOCK_LEN_DWORD-1] >= group->order.d[ECC_BLOCK_LEN_DWORD-1])
	{
		k.d[ECC_BLOCK_LEN_DWORD-1] >>= 1;
	}

 	//(x,y)=kG,计算公钥
 	EC_POINTs_mul_sm2_ex(group, &R, &group->generator, &k, NULL, NULL); 
    ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);

	//将小端模式转换到大端模式，并输出公私钥
  	memcpy(t, x.d, ECC_BLOCK_LEN);								
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		pECCPK->Qx[i] = t[ECC_BLOCK_LEN-1-i];
	}

  	memcpy(t, y.d, ECC_BLOCK_LEN);								
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		pECCPK->Qy[i] = t[ECC_BLOCK_LEN-1-i];
	}

	memcpy(pECCSK->Ka, Ka_256, ECC_BLOCK_LEN);
}
	
int POINT_is_on_curve_ex(ECCParameter *pECCPara, ECC_PUBLIC_KEY *pECCPoint)
{
	unsigned char t[ECC_BLOCK_LEN];
	FLKBIGNUM p, a, b;
	FLKBIGNUM X, Y;

    FLK_BN_ULONG temp1[ECC_BLOCK_LEN_DWORD*2+1];
    FLK_BN_ULONG temp2[ECC_BLOCK_LEN_DWORD*2+1];

	int p_top, a_top, b_top;
	int X_top, Y_top;
	int temp1_top, temp2_top;
    int i;
    int ret;

	//  初始化p
	for(i = 0; i < ECC_BLOCK_LEN; i++)
		t[i] = pECCPara->p[ECC_BLOCK_LEN-1-i];
    memcpy(p.d, t, ECC_BLOCK_LEN);								
    
	p_top = ECC_BLOCK_LEN_DWORD;
    bn_fix_top_sm2_ex(p.d, &p_top);
	//  初始化a

	for(i = 0; i < ECC_BLOCK_LEN; i++)
		t[i] = pECCPara->a[ECC_BLOCK_LEN-1-i];
    memcpy(a.d, t, ECC_BLOCK_LEN);								

    a_top = ECC_BLOCK_LEN_DWORD;
    bn_fix_top_sm2_ex(a.d, &a_top);

	//  初始化b

	for(i = 0; i < ECC_BLOCK_LEN; i++)
		t[i] = pECCPara->b[ECC_BLOCK_LEN-1-i];
    memcpy(b.d, t, ECC_BLOCK_LEN);								

    b_top = ECC_BLOCK_LEN_DWORD;
    bn_fix_top_sm2_ex(b.d, &b_top);

	//初始化待验证点
	
	for(i = 0; i < ECC_BLOCK_LEN; i++)
		t[i] = pECCPoint->Qx[ECC_BLOCK_LEN-1-i];
    memcpy(X.d, t, ECC_BLOCK_LEN);								

    X_top = ECC_BLOCK_LEN_DWORD;
    bn_fix_top_sm2_ex(X.d, &X_top);

	for(i = 0; i < ECC_BLOCK_LEN; i++)
		t[i] = pECCPoint->Qy[ECC_BLOCK_LEN-1-i];
    memcpy(Y.d, t, ECC_BLOCK_LEN);								

    Y_top = ECC_BLOCK_LEN_DWORD;
    bn_fix_top_sm2_ex(Y.d, &Y_top);

    //x ^ 3 + a * x + b mod p
    
    BN_mul_sm2_ex(temp1, &temp1_top, X.d, X_top, X.d, X_top);

    BN_div_sm2_ex(NULL, NULL, temp1, &temp1_top, temp1, temp1_top, p.d, p_top);

    BN_mul_sm2_ex(temp2, &temp2_top, temp1, temp1_top, X.d, X_top);
		
    BN_div_sm2_ex(NULL, NULL, temp1, &temp1_top, temp2, temp2_top, p.d, p_top);

    BN_mul_sm2_ex(temp2, &temp2_top, a.d, a_top, X.d, X_top);

    BN_div_sm2_ex(NULL, NULL, temp2, &temp2_top, temp2, temp2_top, p.d, p_top);

	BN_uadd_sm2_ex(temp1, &temp1_top, temp1, temp1_top, temp2, temp2_top);

    BN_div_sm2_ex(NULL, NULL, temp1, &temp1_top, temp1, temp1_top, p.d, p_top);

	BN_uadd_sm2_ex(temp1, &temp1_top, temp1, temp1_top, b.d, b_top);

    BN_div_sm2_ex(NULL, NULL, temp1, &temp1_top, temp1, temp1_top, p.d, p_top);

	//y ^ 2
	
    BN_mul_sm2_ex(temp2, &temp2_top, Y.d, Y_top, Y.d, Y_top);

    BN_div_sm2_ex(NULL, NULL, temp2, &temp2_top, temp2, temp2_top, p.d, p_top);

	ret = BN_ucmp_sm2_ex(temp1, temp1_top, temp2, temp2_top); 
	if( ret )
		return 0;  

	return 1;
}

// Z_in 共享数据，Z_out输出长度为klen的密钥，v_len是HASH输出的长度。 z_input_len是输入Z_IN的长度（unsigned char）
//v_len是SM3算法的输出，长度为256，192，160可选,本部分采用256长,最多协商256*2长度的密钥
//void KDF_ALGRITRHM_ex(unsigned  char *Z_in,int z_input_len,int Klen,int v_len,unsigned char *Z_out)
void KDF_ALGRITRHM_ex(unsigned  char *Z_in,int z_input_len,int Klen,unsigned char *Z_out)
{
	int 			j;
	int 			round_number;
	unsigned char  *aout_temp;
	unsigned char  *aout_hash;
	unsigned char	ct[4] = {0x0,0x0,0x0,0x1};

	aout_temp = (unsigned char *)malloc(z_input_len+4);
	if(NULL == aout_temp)
	{
		return ;
	}
	
	aout_hash = (unsigned char *)malloc(32);
	if(NULL == aout_hash)
	{
		free(aout_temp);
		return ;
	}

	if((Klen%32) == 0)
	{
		round_number = Klen / 32;
	}
	else
	{
		round_number = ((Klen - Klen % 32) / 32) + 1;
	}

	memcpy(aout_temp, Z_in, z_input_len);
	aout_temp[z_input_len] = ct[0];
	aout_temp[z_input_len+1] =ct[1];
	aout_temp[z_input_len+2] =ct[2];
	for(j = 0; j < round_number; j++)
	{
		aout_temp[z_input_len+3] = j + 1;
		algrithm_ex(aout_temp,z_input_len+4,0,aout_hash);

		if((j + 1) != round_number)
		{
			memcpy(Z_out + j * 32, aout_hash, 32);
		}
		else
		{
			if((Klen%32) == 0)
			{
				memcpy(Z_out + j * 32, aout_hash, 32);
			}
			else
			{
				memcpy(Z_out + j * 32, aout_hash, Klen % 32);
			}
		}
	}

	free(aout_temp);
	free(aout_hash);
}

void ECDSA_Signature_ex(EC_GROUP *group, unsigned char *e, ECC_PRIVATE_KEY *pECCSK, ECC_SIGNATURE *pECCSign)
{
	int i, top,top1;
	EC_POINT R;
	FLKBIGNUM k;
	FLKBIGNUM x, y;
    FLKBIGNUM  zwk_temp,r_add_k,number_1,number_1_add_da,k_sub_rda;
	unsigned char t[ECC_BLOCK_LEN];
	FLKBIGNUM tmp1, tmp2;
	FLK_BN_ULONG tmp3[ECC_BLOCK_LEN_DWORD*2+1],tmp4[ECC_BLOCK_LEN_DWORD*2+1];
	FLKBIGNUM Plain;
	FLKBIGNUM SK;
	FLKBIGNUM r, s;
	unsigned char rnd[ECC_BLOCK_LEN];// = {0xfd,0xd5,0x08,0x20,0xe3,0x17,0x06,0x84,0x54,0xc1,0xc0,0x41,0x99,0x08,0xb5,0x12,0xcd,0xb4,0xc6,0x96,0x9a,0x72,0x98,0x40,0xdf,0x0b,0x3b,0x21,0x26,0x4c,0x08,0xc0};

	genrandom(rnd, ECC_BLOCK_LEN);

	//初始化明文
	memset(&Plain, 0, FLK_BIGNUM_SIZE);
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = e[ECC_BLOCK_LEN-1-i];
	}
    memcpy(Plain.d, t, ECC_BLOCK_LEN);

	//初始化私钥
	memset(&SK, 0, FLK_BIGNUM_SIZE);
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = pECCSK->Ka[ECC_BLOCK_LEN-1-i];
	}

    memcpy(SK.d, t, ECC_BLOCK_LEN);

	again:				
	memset(&k, 0, FLK_BIGNUM_SIZE);
	memcpy(k.d, rnd, ECC_BLOCK_LEN);
	
	while(k.d[ECC_BLOCK_LEN_DWORD-1] >= group->order.d[ECC_BLOCK_LEN_DWORD-1])
	{
		k.d[ECC_BLOCK_LEN_DWORD-1] >>= 1;	
	}
 	
 	//(x1, y1) = kG
 	EC_POINTs_mul_sm2_ex(group, &R, &group->generator, &k, NULL, NULL); 
    ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);  
	// r =( e+x) mod n
	BN_mod_add_sm2_ex(zwk_temp.d, Plain.d, x.d, group->order.d, group->order_top);	
    BN_div_sm2_ex(NULL, NULL, r.d, &top, zwk_temp.d, group->order_top, group->order.d, group->order_top);		
	//
	if(top == 0)
	{
		goto again;	//r = 0  返回
	}
	// r+k=n   返回
	BN_mod_add_sm2_ex(r_add_k.d, r.d, k.d, group->order.d, group->order_top);	
    if(two_number_same_ex(r_add_k.d,ECC_BLOCK_LEN,group->order.d) ==0) 
    {
		goto again;
    }
	
	//  1+da
   	memset(number_1.d, 0, sizeof(FLKBIGNUM));
	number_1.d[0]=0x1;
	BN_mod_add_sm2_ex(number_1_add_da.d, number_1.d, SK.d, group->order.d, group->order_top);
       //  1+da 的逆
	BN_mod_inverse_sm2_ex(tmp2.d, &top, number_1_add_da.d, group->order_top, group->order.d, group->order_top);

	// r.da
	BN_mul_sm2_ex(tmp3, &top, SK.d, group->order_top, r.d, group->order_top);
	BN_div_sm2_ex(NULL, NULL, tmp1.d, &top, tmp3, top, group->order.d, group->order_top);

	//k-r.da

	BN_mod_sub_sm2_ex(k_sub_rda.d, &top1, k.d, tmp1.d, group->order.d, group->field_top);
	if(top1==0)
	{
		goto again;
	}
	
	BN_mul_sm2_ex(tmp4, &top, k_sub_rda.d, group->order_top, tmp2.d, group->order_top);
	BN_div_sm2_ex(NULL, NULL, s.d, &top, tmp4, top, group->order.d, group->order_top);
	if(top == 0)
	{
		goto again;	//s = 0
	}
	//将小端模式转换到大端模式，并输出
    memcpy(t, r.d, ECC_BLOCK_LEN);								
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		pECCSign->r[i] = t[ECC_BLOCK_LEN-1-i];
	}
    memcpy(t, s.d, ECC_BLOCK_LEN);								
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		pECCSign->s[i] = t[ECC_BLOCK_LEN-1-i];
	}
}

void ECDSA_Signature_Nornd_ex(EC_GROUP *group, unsigned char *e, unsigned char *rnd, ECC_PRIVATE_KEY *pECCSK, ECC_SIGNATURE *pECCSign)
{
	int i, top,top1;
	EC_POINT R;
	FLKBIGNUM k;
	FLKBIGNUM x, y;
    FLKBIGNUM  zwk_temp,r_add_k,number_1,number_1_add_da,k_sub_rda;
	unsigned char t[ECC_BLOCK_LEN];
	FLKBIGNUM tmp1, tmp2;
	FLK_BN_ULONG tmp3[ECC_BLOCK_LEN_DWORD*2+1],tmp4[ECC_BLOCK_LEN_DWORD*2+1];
	FLKBIGNUM Plain;
	FLKBIGNUM SK;
	FLKBIGNUM r, s;

	//初始化明文
	memset(&Plain, 0, FLK_BIGNUM_SIZE);
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = e[ECC_BLOCK_LEN-1-i];
	}
    memcpy(Plain.d, t, ECC_BLOCK_LEN);

	//初始化私钥
	memset(&SK, 0, FLK_BIGNUM_SIZE);
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = pECCSK->Ka[ECC_BLOCK_LEN-1-i];
	}

    memcpy(SK.d, t, ECC_BLOCK_LEN);

	again:				
	memset(&k, 0, FLK_BIGNUM_SIZE);
	memcpy(k.d, rnd, ECC_BLOCK_LEN);
	
	while(k.d[ECC_BLOCK_LEN_DWORD-1] >= group->order.d[ECC_BLOCK_LEN_DWORD-1])
	{
		k.d[ECC_BLOCK_LEN_DWORD-1] >>= 1;	
	}
 	
 	//(x1, y1) = kG
 	EC_POINTs_mul_sm2_ex(group, &R, &group->generator, &k, NULL, NULL); 
    ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);  
	// r =( e+x) mod n
	BN_mod_add_sm2_ex(zwk_temp.d, Plain.d, x.d, group->order.d, group->order_top);	
    BN_div_sm2_ex(NULL, NULL, r.d, &top, zwk_temp.d, group->order_top, group->order.d, group->order_top);		
	//
	if(top == 0)
	{
		goto again;	//r = 0  返回
	}
	// r+k=n   返回
	BN_mod_add_sm2_ex(r_add_k.d, r.d, k.d, group->order.d, group->order_top);	
    if(two_number_same_ex(r_add_k.d,ECC_BLOCK_LEN,group->order.d) ==0) 
    {
		goto again;
    }
	
	//  1+da
   	memset(number_1.d, 0, sizeof(FLKBIGNUM));
	number_1.d[0]=0x1;
	BN_mod_add_sm2_ex(number_1_add_da.d, number_1.d, SK.d, group->order.d, group->order_top);
       //  1+da 的逆
	BN_mod_inverse_sm2_ex(tmp2.d, &top, number_1_add_da.d, group->order_top, group->order.d, group->order_top);

	// r.da
	BN_mul_sm2_ex(tmp3, &top, SK.d, group->order_top, r.d, group->order_top);
	BN_div_sm2_ex(NULL, NULL, tmp1.d, &top, tmp3, top, group->order.d, group->order_top);

	//k-r.da

	BN_mod_sub_sm2_ex(k_sub_rda.d, &top1, k.d, tmp1.d, group->order.d, group->field_top);
	if(top1==0)
	{
		goto again;
	}
	
	BN_mul_sm2_ex(tmp4, &top, k_sub_rda.d, group->order_top, tmp2.d, group->order_top);
	BN_div_sm2_ex(NULL, NULL, s.d, &top, tmp4, top, group->order.d, group->order_top);
	if(top == 0)
	{
		goto again;	//s = 0
	}
	//将小端模式转换到大端模式，并输出
    memcpy(t, r.d, ECC_BLOCK_LEN);								
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		pECCSign->r[i] = t[ECC_BLOCK_LEN-1-i];
	}
    memcpy(t, s.d, ECC_BLOCK_LEN);								
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		pECCSign->s[i] = t[ECC_BLOCK_LEN-1-i];
	}
}
									
int ECDSA_Verification_ex(EC_GROUP *group, unsigned char *e, ECC_PUBLIC_KEY *pECCPK, ECC_SIGNATURE *pECCSign)
{
	int i;
	int ret;
	EC_POINT R, Q;
	FLKBIGNUM r, s;
	FLKBIGNUM x, y;
	unsigned char t[ECC_BLOCK_LEN];
	FLKBIGNUM Plain;
	FLKBIGNUM  zwkr_add_s,R_out;	
	//初始化明文

	memset(&Plain, 0, FLK_BIGNUM_SIZE);

	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = e[ECC_BLOCK_LEN-1-i];
	}
    memcpy(Plain.d, t, ECC_BLOCK_LEN);								
	
	//初始化公钥
	memset(&Q, 0, sizeof(EC_POINT));
	
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = pECCPK->Qx[ECC_BLOCK_LEN-1-i];
	}
    memcpy(Q.X.d, t, ECC_BLOCK_LEN);								

	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = pECCPK->Qy[ECC_BLOCK_LEN-1-i];
	}
    memcpy(Q.Y.d, t, ECC_BLOCK_LEN);								

	//初始化r
	memset(&r, 0, FLK_BIGNUM_SIZE);

	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = pECCSign->r[ECC_BLOCK_LEN-1-i];
	}
    memcpy(r.d, t, ECC_BLOCK_LEN);								

	
	ret = BN_ucmp_sm2_ex(r.d, ECC_BLOCK_LEN_DWORD, group->order.d, ECC_BLOCK_LEN_DWORD);
	if(ret >= 0)
	{
		return 0;			//验证未通过
	}

	//初始化s
	memset(&s, 0, FLK_BIGNUM_SIZE);

	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = pECCSign->s[ECC_BLOCK_LEN-1-i];
	}
    memcpy(s.d, t, ECC_BLOCK_LEN);
	//s>=n,报错
	
	ret = BN_ucmp_sm2_ex(s.d, ECC_BLOCK_LEN_DWORD, group->order.d, ECC_BLOCK_LEN_DWORD);
	if(ret >= 0)
	{
		return 0;			//验证未通过
	}

	BN_mod_mul_montgomery_sm2_ex(Q.X.d, Q.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2_ex(Q.Y.d, Q.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	memcpy(Q.Z.d, group->field_data2.d, group->field_top*FLK_BN_BYTES);
    Q.Z_is_one = 1;

	//r+s mod n
	BN_mod_add_sm2_ex(zwkr_add_s.d, r.d, s.d, group->order.d, group->order_top);

	//X = sG + tPa
 	EC_POINTs_mul_sm2_ex(group, &R, &group->generator, &s, &Q, &zwkr_add_s); 
    ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);
	//	(e+x1) mod n
	BN_mod_add_sm2_ex(R_out.d, Plain.d, x.d, group->order.d, group->order_top);
	
	if(BN_ucmp_sm2_ex(r.d, group->order_top, R_out.d, group->order_top))
	{
		return 0;			//验证未通过
	}

    return 1;				//验证通过
}

void ECES_Encryption_ex(EC_GROUP *group, const unsigned char *e, int e_len, ECC_PUBLIC_KEY *pECCPK,ECC_ENCRYPTION *pEncryption)
{
	int i;
	EC_POINT R, Q;
	FLKBIGNUM k;
	FLKBIGNUM x1, y1;
	FLKBIGNUM x2, y2;
	unsigned char t[ECC_BLOCK_LEN];

	// unsigned char rnd[ECC_BLOCK_LEN] = {0XEA, 0XC1, 0XBC, 0X21, 0X6D, 0X54, 0XB8, 0X0D, 
	// 									0X3C, 0XDB, 0XE4, 0XCE, 0XEF, 0X3C, 0XC1, 0XFA, 
	// 									0XD9, 0XC0, 0X2D, 0XCC, 0X16, 0X68, 0X0F, 0X3A, 
	// 									0XD5, 0X06, 0X86, 0X1A, 0X59, 0X27, 0X6E, 0X27};

	// unsigned char rnd[ECC_BLOCK_LEN] = {0X59, 0X27, 0X6E, 0X27, 0XD5, 0X06, 0X86, 0X1A, 
	// 								0X16, 0X68, 0X0F, 0X3A, 0XD9, 0XC0, 0X2D, 0XCC, 
	// 								0XEF, 0X3C, 0XC1, 0XFA, 0X3C, 0XDB, 0XE4, 0XCE, 
	// 								0X6D, 0X54, 0XB8, 0X0D, 0XEA, 0XC1, 0XBC, 0X21};

	// unsigned char rnd[ECC_BLOCK_LEN] = {0X27, 0X6E, 0X27, 0X59,  
	// 									0X1A, 0X86, 0X06, 0XD5,  
	// 									0X3A, 0X0F, 0X68, 0X16, 
	// 									0XCC, 0X2D, 0XC0, 0XD9, 
	// 									0XFA, 0XC1, 0X3C, 0XEF, 
	// 									0XCE, 0XE4, 0XDB, 0X3C, 
	// 									0X0D, 0XB8, 0X54, 0X6D, 
	// 									0X21, 0XBC, 0XC1, 0XEA};
#ifndef SM2_DEBUG
	unsigned char rnd[ECC_BLOCK_LEN] = {0};
#else
	unsigned char rnd[ECC_BLOCK_LEN] = {0X21, 0XBC, 0XC1, 0XEA,  
										0X0D, 0XB8, 0X54, 0X6D,  
										0XCE, 0XE4, 0XDB, 0X3C,  
										0XFA, 0XC1, 0X3C, 0XEF,
										0XCC, 0X2D, 0XC0, 0XD9, 
										0X3A, 0X0F, 0X68, 0X16,
										0X1A, 0X86, 0X06, 0XD5,
										0X27, 0X6E, 0X27, 0X59};
#endif
	// const char *data = {"2266f904f64d28e1684da7b7f0b0db4d5e50a3dc2966100f1d1fbab81cb7c741"};
	// for(i = 0; i < (int)strlen(data)/2; i++)
	// {
	// 	sscanf((char *)(data + strlen(data) - 2 - i * 2), "%02X", (unsigned int *)(rnd + i));
	// }
	// PrintHex("rnd:",rnd,32);

	unsigned char x1in[ECC_BLOCK_LEN],y1in[ECC_BLOCK_LEN];
	unsigned char x2in[ECC_BLOCK_LEN],y2in[ECC_BLOCK_LEN];
	unsigned char ain[64];

	//unsigned char  *kdf_out = new unsigned char[e_len];
    //unsigned char  *hash_in = new unsigned char[32+32+e_len];
    unsigned char  *kdf_out = (unsigned char *)malloc(e_len);
    unsigned char  *hash_in = (unsigned char *)malloc(32+32+e_len);


	unsigned char c1[64];
	unsigned char c3[32];
    unsigned char c2[ECC_MAX_ENCRYPT_LENGTH];
#ifndef SM2_DEBUG
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		rnd[i] = (unsigned char)((rand() % 255) + 1);
	}
#endif

	//初始化公钥 point Q
	memset(&Q, 0, sizeof(EC_POINT));
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = pECCPK->Qx[ECC_BLOCK_LEN-1-i];
	}
    memcpy(Q.X.d, t, ECC_BLOCK_LEN);

	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = pECCPK->Qy[ECC_BLOCK_LEN-1-i];
	}
    memcpy(Q.Y.d, t, ECC_BLOCK_LEN);

    //printPoint("pub key:", &Q);

	BN_mod_mul_montgomery_sm2_ex(Q.X.d, Q.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2_ex(Q.Y.d, Q.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	memcpy(Q.Z.d, group->field_data2.d, group->field_top*FLK_BN_BYTES);
    Q.Z_is_one = 1;



	again:
	memset(&k, 0, FLK_BIGNUM_SIZE);
	memcpy(k.d, rnd, ECC_BLOCK_LEN);

	while(k.d[ECC_BLOCK_LEN_DWORD-1] >= group->order.d[ECC_BLOCK_LEN_DWORD-1])
	{
		k.d[ECC_BLOCK_LEN_DWORD-1] >>= 1;
	}

	//PrintBIGNUM("k:",k);

 	//(x1,y1)=kG
 	EC_POINTs_mul_sm2_ex(group, &R, &group->generator, &k, NULL, NULL); 
    ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x1, &y1);

 	//(x2,y2)=kQ
	//  A3:  S= [k.h][h]Pb 默认余因子H=1
 	EC_POINTs_mul_sm2_ex(group, &R, &Q, &k, NULL, NULL); 
    ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x2, &y2);

	//判断x2是否为0
	memcpy(t, x1.d, ECC_BLOCK_LEN);
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		x1in[i] = t[ECC_BLOCK_LEN-1-i];
	}

	memcpy(t, y1.d, ECC_BLOCK_LEN);
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		y1in[i] = t[ECC_BLOCK_LEN-1-i];
	}

	//PrintHex("WOLFSSL c1 x1:", x1in, 32);
	//PrintHex("WOLFSSL c1 y1:", y1in, 32);

	//	c1[0] =0x04;
	for(i=0;i<32;i++)
	{
		c1[i] =x1in[i];
	}
	for(i=32;i<64;i++)
	{
		c1[i] =y1in[i-32];
	}


	for(i = 0; i < (int)group->field_top; i++)
	{
		if(x2.d[i])
		{
			goto ok;
		}
	}
	goto again;
	
	ok:
	//KDF的输入和X2,Y2的转化，是否要做x2,y2的数据颠倒。？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？
	// 本处做数据的颠倒
	memcpy(t, x2.d, ECC_BLOCK_LEN);
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		x2in[i] = t[ECC_BLOCK_LEN-1-i];
	}
	memcpy(t, y2.d, ECC_BLOCK_LEN);	
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		y2in[i] = t[ECC_BLOCK_LEN-1-i];
	}

	//PrintHex("WOLFSSL x2:", x2in, 32);
	//PrintHex("WOLFSSL y2:", y2in, 32);

	for(i=0;i<32;i++)
	{
    	ain[i] = x2in[i];	
	}

	for(i=0;i<32;i++)
	{
    	ain[32+i] = y2in[i];
	}

	// Z_in 共享数据，Z_out输出长度为klen的密钥，v_len是HASH输出的长度。 z_input_len是输入Z_IN的长度（unsigned char）
	//v_len是SM3算法的输出，长度为256，192，160可选,本部分采用256长,最多协商256*2长度的密钥
	KDF_ALGRITRHM_ex(ain,64,e_len,kdf_out);

	PrintHex("WOLFSSL t:", kdf_out, e_len);
	PrintHex("WOLFSSL e:", e, e_len);
	//printf("e:%s\n", e);

  	for(i=0;i<e_len;i++)
  	{
	  c2[i] = e[i] ^ kdf_out[i];
  	}


  	PrintHex("WOLFSSL C2:", c2, e_len);


	for(i=0;i<32;i++)
	{
		hash_in[i] =ain[i];
	}

	for(i=32;i<32+e_len;i++)
	{
		hash_in[i] =e[i-32];
	}

	for(i=32+e_len;i<32+e_len+32;i++)
	{
		hash_in[i] =ain[i-e_len];
	}

	algrithm_ex( hash_in,32+32+e_len,0,c3);


	PrintHex("WOLFSSL C3:", c3, 32);


	for(i = 0; i < 2*ECC_BLOCK_LEN; i++)
	{
		pEncryption->C1[i] = c1[i];	
	}
	
	for(i = 0; i < e_len; i++)
	{
		pEncryption->C2[i] = c2[i];
	}
			
	
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		pEncryption->C3[i] = c3[i];
	}

	pEncryption->len = e_len;

	free(kdf_out);
	free(hash_in);
}

int  ECES_Decryption_ex(EC_GROUP *group,ECC_ENCRYPTION *pEncryption, int c2_len , ECC_PRIVATE_KEY *pECCSK, unsigned char *e)
{
	int i;
	int char_equal = 0;// B5 判断u和C3是否相等
	EC_POINT R,Q;
	FLKBIGNUM x,  y;
	unsigned char t[ECC_BLOCK_LEN];
	FLKBIGNUM SK;

	unsigned char  *c2_kdf = (unsigned char *)malloc(pEncryption->len);
	unsigned char  *t_xor_m = (unsigned char *)malloc(pEncryption->len);
	unsigned char x2_y2[64];
	unsigned char x2in[ECC_BLOCK_LEN],y2in[ECC_BLOCK_LEN];
	unsigned char  *hash_in = (unsigned char *)malloc(32+32+pEncryption->len);
	unsigned char u[32];//B5

	//FLK_BN_ULONG  sum_t=0;//判断t是否全0，  B3

	//  初始化C1,判断该点是否在曲线上
	// 该在外围做判断
	unsigned char c1[64];
    unsigned char c2[ECC_MAX_ENCRYPT_LENGTH];
	unsigned char c3[32];
	c2_len = pEncryption->len;
	
	memset(&Q, 0, sizeof(EC_POINT));

	
	memcpy(c1, pEncryption->C1, 2*ECC_BLOCK_LEN);
	memcpy(c3, pEncryption->C3, ECC_BLOCK_LEN);
	memset(c2, 0, sizeof(c2));
	memcpy(c2, pEncryption->C2, c2_len);

	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{	
		t[i] = c1[31-i];
	}
	memcpy(Q.X.d, t, ECC_BLOCK_LEN);	

	for(i = 0; i < ECC_BLOCK_LEN; i++)
    {
         t[i] =  c1[63-i];
	}
	memcpy(Q.Y.d, t, ECC_BLOCK_LEN);
	
	//初始化私钥
	memset(&SK, 0, FLK_BIGNUM_SIZE);
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = pECCSK->Ka[ECC_BLOCK_LEN-1-i];  
	}
    memcpy(SK.d, t, ECC_BLOCK_LEN);

    PrintBIGNUM("before c1 Q.X.d", Q.X);
	BN_mod_mul_montgomery_sm2_ex(Q.X.d, Q.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	PrintBIGNUM("after c1 Q.X.d", Q.X);

	PrintBIGNUM("before c1 Q.Y.d", Q.Y);
    BN_mod_mul_montgomery_sm2_ex(Q.Y.d, Q.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	PrintBIGNUM("after c1 Q.Y.d", Q.Y);

	memcpy(Q.Z.d, group->field_data2.d, group->field_top*FLK_BN_BYTES);
	PrintBIGNUM("c1 Q.Z.d", Q.Z);
    Q.Z_is_one=1;

	printPoint("before R:", &R);
	printPoint("before Q:", &Q);
    
	PrintBIGNUM("before priv key:", SK);
 	//(x1,y1)=dQ
 	EC_POINTs_mul_sm2_ex(group, &R, &Q, &SK, NULL,NULL); 

	printPoint("after R:", &R);
    printPoint("after Q:", &Q);
    
    PrintBIGNUM("after priv key:", SK);


    printPoint("before R:", &R);
    PrintBIGNUM("before x:", x);
    PrintBIGNUM("before y:", y);
    ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);
    printPoint("after R:", &R);
    PrintBIGNUM("after x:", x);
    PrintBIGNUM("after y:", y);

 	if(BN_is_zero_sm2_ex(x.d, ECC_BLOCK_LEN)||BN_is_zero_sm2_ex(y.d, ECC_BLOCK_LEN))
 	{
 		return -1; // 无穷远点
 	}
	else
	{
		// B2
		//KDF的输入和X2,Y2的转化，是否要做x2,y2的数据颠倒。？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？
		// 本处做数据的颠倒
		memcpy(t, x.d, ECC_BLOCK_LEN);
		for(i = 0; i < ECC_BLOCK_LEN; i++)
		{
			x2in[i] = t[ECC_BLOCK_LEN-1-i];
		}
		memcpy(t, y.d, ECC_BLOCK_LEN);
		for(i = 0; i < ECC_BLOCK_LEN; i++)
		{
			y2in[i] = t[ECC_BLOCK_LEN-1-i];
		}
		
		memcpy(x2_y2, x2in, 32);
		memcpy(x2_y2 + 32, y2in, 32);

		//PrintHex("x2_y2",x2_y2,64);

		//B3 kdf
		KDF_ALGRITRHM_ex(x2_y2,64,c2_len,c2_kdf);
		//PrintHex("dec KDF_ALGRITRHM_ex:", c2_kdf, 32);
		/*for(i=0;i<c2_len;i++)
		{
			sum_t = sum_t + c2_kdf[i];
		}
		if(sum_t == 0)
		{
			printf("c2_len = %d\n", c2_len);
			for(i = 0; i < c2_len; i++)
			{
				printf("%d", c2_kdf[i]);
			}
			return -2;
		}*/
		//else
		//{
			for(i=0;i<c2_len;i++)  // B4
			{ 
				t_xor_m[i] = c2[i] ^ c2_kdf[i];
				e[i] = c2[i] ^ c2_kdf[i];
			}

		//PrintHex("dec:", e, c2_len);

		//B5
		for(i=0;i<32;i++)
		{
			hash_in[i] =x2in[i];
		}

		for(i=32;i<32+c2_len;i++)
		{
			hash_in[i] =t_xor_m[i-32];
		}

			for(i=32+c2_len;i<32+c2_len+32;i++)
			{
				hash_in[i] =y2in[i-32-c2_len];
			}

			algrithm_ex( hash_in,32+32+c2_len,0,u);
			for(i=0;i<32;i++)
			{  
				char_equal = char_equal+(unsigned int)(u[i] -c3[i]);
			}

			if(char_equal!=0) 
			{
				return 0;
			}
		//}
	}

	free(c2_kdf);
	free(t_xor_m);
	free(hash_in);

	return 1;
}

void algrithm_ex(const unsigned char *ain, int len,int flag, unsigned char aout[32])
{
	if(flag != 0)
	{
		return ;
	}
    return sm3(ain, len,aout);
}

void ECC_Public_To_WOLFSSL_ex(ECC_PUBLIC_KEY *pk, ECCrefPublicKey *pucPublicKey)
{
    memset(pucPublicKey, 0, sizeof(ECCrefPublicKey));

	pucPublicKey->bits = 256;
    memcpy(pucPublicKey->x + ECCref_ALIGNED_LEN, pk->Qx, ECC_BLOCK_LEN);
    memcpy(pucPublicKey->y + ECCref_ALIGNED_LEN, pk->Qy, ECC_BLOCK_LEN);
}

void ECC_Public_From_WOLFSSL_ex(ECC_PUBLIC_KEY *pk, const ECCrefPublicKey *pucPublicKey)
{
	memset(pk, 0, sizeof(ECC_PUBLIC_KEY));

    memcpy(pk->Qx, pucPublicKey->x + ECCref_ALIGNED_LEN, ECC_BLOCK_LEN);
    memcpy(pk->Qy, pucPublicKey->y + ECCref_ALIGNED_LEN, ECC_BLOCK_LEN);
}

void ECC_Private_To_WOLFSSL_ex(ECC_PRIVATE_KEY *pk, ECCrefPrivateKey *pucPrivateKey)
{
    memset(pucPrivateKey, 0, sizeof(ECCrefPrivateKey));

	pucPrivateKey->bits = 256;
    memcpy(pucPrivateKey->D + ECCref_ALIGNED_LEN, pk->Ka, ECC_BLOCK_LEN);
}
void ECC_Private_From_WOLFSSL_ex(ECC_PRIVATE_KEY *pk, const ECCrefPrivateKey *pucPrivateKey)
{
	memset(pk, 0, sizeof(ECC_PRIVATE_KEY));

    memcpy(pk->Ka, pucPrivateKey->D + ECCref_ALIGNED_LEN, ECC_BLOCK_LEN);
}

void ECC_ECCEncryption_To_WOLFSSL_ex(ECC_ENCRYPTION *pk, ECCCipher *pucEncData)
{
    memset(pucEncData, 0, sizeof(ECCCipher));

    memcpy(pucEncData->x + ECCref_ALIGNED_LEN, pk->C1, ECC_BLOCK_LEN);
    memcpy(pucEncData->y + ECCref_ALIGNED_LEN, pk->C1 + ECC_BLOCK_LEN, ECC_BLOCK_LEN);
	memcpy(pucEncData->M, pk->C3, ECC_BLOCK_LEN);
	pucEncData->L = pk->len;
	memcpy(pucEncData->C, pk->C2, pk->len);
}
void ECC_ECCEncryption_From_WOLFSSL_ex(ECC_ENCRYPTION *pk, const ECCCipher *pucEncData)
{
	memset(pk, 0, sizeof(ECC_ENCRYPTION));

    memcpy(pk->C1, pucEncData->x + ECCref_ALIGNED_LEN, ECC_BLOCK_LEN);
    memcpy(pk->C1 + ECC_BLOCK_LEN, pucEncData->y + ECCref_ALIGNED_LEN, ECC_BLOCK_LEN);
	memcpy(pk->C3, pucEncData->M, ECC_BLOCK_LEN);
	pk->len = pucEncData->L;
	memcpy(pk->C2, pucEncData->C, pk->len);
}

void ECC_ECCSignature_To_WOLFSSL_ex(ECC_SIGNATURE *sd, ECCSignature *pucSignature)
{
    memset(pucSignature, 0, sizeof(ECCSignature));

    memcpy(pucSignature->r + ECCref_ALIGNED_LEN, sd->r, ECC_BLOCK_LEN);
    memcpy(pucSignature->s + ECCref_ALIGNED_LEN, sd->s, ECC_BLOCK_LEN);
}
void ECC_ECCSignature_From_WOLFSSL_ex(ECC_SIGNATURE *sd, const ECCSignature *pucSignature)
{
	memset(sd, 0, sizeof(ECC_SIGNATURE));

    memcpy(sd->r, pucSignature->r + ECCref_ALIGNED_LEN, ECC_BLOCK_LEN);
    memcpy(sd->s, pucSignature->s + ECCref_ALIGNED_LEN, ECC_BLOCK_LEN);
}

int SM2_Init_ECCParameter(void)
{
	if (g_sm2init == 1)
	{
		return ERR_SUCCESS;
	}
	
	unsigned char p_256[ECC_BLOCK_LEN]={0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
										0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

	unsigned char a_256[ECC_BLOCK_LEN]={0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
										0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC};

	unsigned char b_256[ECC_BLOCK_LEN]={0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,
										0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,
										0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,
										0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93};

	unsigned char Gx_256[ECC_BLOCK_LEN]={0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,
										0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,
										0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,
										0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7};

	unsigned char Gy_256[ECC_BLOCK_LEN]={0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,
										0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,
										0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,
										0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0};

	unsigned char Gn_256[ECC_BLOCK_LEN]={0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
										0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
										0x72,0x03,0xDF,0x6B,0x21,0xC6,0x05,0x2B,
										0x53,0xBB,0xF4,0x09,0x39,0xD5,0x41,0x23};

    //G_group
	
    memcpy(&G_ECCPara.p, p_256, ECC_BLOCK_LEN);
    memcpy(&G_ECCPara.a, a_256, ECC_BLOCK_LEN);
    memcpy(&G_ECCPara.b, b_256, ECC_BLOCK_LEN);
    memcpy(&G_ECCPara.Gx, Gx_256, ECC_BLOCK_LEN);
    memcpy(&G_ECCPara.Gy, Gy_256, ECC_BLOCK_LEN);
    memcpy(&G_ECCPara.Gn, Gn_256, ECC_BLOCK_LEN);

    ECC_InitParameter_ex(&G_ECCPara, &G_group);

    g_sm2init = 1;
	
    return ERR_SUCCESS;
}

int SM2_Init_ECCParameter_ex(const unsigned char *p_256,const unsigned char *a_256,const unsigned char *b_256,const unsigned char *Gx_256,const unsigned char *Gy_256,const unsigned char *Gn_256)
{
    memcpy(&G_ECCPara.p, p_256, ECC_BLOCK_LEN);
    memcpy(&G_ECCPara.a, a_256, ECC_BLOCK_LEN);
    memcpy(&G_ECCPara.b, b_256, ECC_BLOCK_LEN);
    memcpy(&G_ECCPara.Gx, Gx_256, ECC_BLOCK_LEN);
    memcpy(&G_ECCPara.Gy, Gy_256, ECC_BLOCK_LEN);
    memcpy(&G_ECCPara.Gn, Gn_256, ECC_BLOCK_LEN);

    ECC_InitParameter_ex(&G_ECCPara, &G_group);

    return ERR_SUCCESS;
}

#if 0

int ECC_do_key(FLKBIGNUM *X, FLKBIGNUM *Y, ECCrefPrivateKey *D2, ECCrefPublicKey *PubK)
{
	ECC_PRIVATE_KEY 		stECCSK1;
	ECC_PRIVATE_KEY 		stECCSK2;
	ECC_PRIVATE_KEY 		stECCD;
	ECC_PUBLIC_KEY 			stECCPK;

	int i;
	EC_POINT R;
	FLKBIGNUM k;
	FLKBIGNUM x, y;
	FLKBIGNUM DD;
	FLKBIGNUM tmp;
	FLKBIGNUM Plain;
	unsigned char t[ECC_BLOCK_LEN];
	unsigned char rnd[ECC_BLOCK_LEN];// = {0xfd,0xd5,0x08,0x20,0xe3,0x17,0x06,0x84,0x54,0xc1,0xc0,0x41,0x99,0x08,0xb5,0x12,0xcd,0xb4,0xc6,0x96,0x9a,0x72,0x98,0x40,0xdf,0x0b,0x3b,0x21,0x26,0x4c,0x08,0xc0};
	EC_GROUP *group = &G_group;
	int top;


	FLKBIGNUM SK1, SK2, tmp1, tmp2, XYtmp, XY, XYsub1, n;
	int temp1_top, temp2_top, XYtmp_top, XY_top, XYsub1_top;
	//初始化私钥
	memset(&SK1, 0, sizeof(FLKBIGNUM));
	memset(&SK2, 0, sizeof(FLKBIGNUM));
	memset(&tmp1, 0, sizeof(FLKBIGNUM));
	memset(&tmp2, 0, sizeof(FLKBIGNUM));
	memset(&XYsub1, 0, sizeof(FLKBIGNUM));
	memset(&x, 0, sizeof(FLKBIGNUM));
	memset(&y, 0, sizeof(FLKBIGNUM));
	memset(&DD, 0, sizeof(FLKBIGNUM));
	memset(&tmp, 0, sizeof(FLKBIGNUM));

	// 计算X 的逆
	BN_mod_inverse_sm2_ex(tmp1.d, &temp1_top, X->d, group->order_top, group->order.d, group->order_top);
	// 计算Y 的逆
	BN_mod_inverse_sm2_ex(tmp2.d, &temp2_top, Y->d, group->order_top, group->order.d, group->order_top);

	BN_mul_sm2_ex(XYtmp.d, &XYtmp_top, tmp1.d, temp1_top, tmp2.d, temp2_top);
	BN_div_sm2_ex(NULL, NULL, XY.d, &XY_top, XYtmp.d, group->order_top, group->order.d, group->order_top);
	if (XY_top == 0)
	{
		return -1;
	}

	memset(&n, 0, sizeof(FLKBIGNUM));
	n.d[0] = 1;
	BN_mod_sub_sm2_ex(XYsub1.d, &XYsub1_top, XY.d, n.d, group->field.d, group->field_top);
	if (XYsub1_top == 0)
	{
		return -1;
	}
	memcpy(DD.d, XYsub1.d, ECC_BLOCK_LEN);
	//for(i = 0; i < ECC_BLOCK_LEN; i++)
	//{
	//	t[i] = 1;
	//}
	//memcpy(tmp.d, t, ECC_BLOCK_LEN);

	//BN_mod_add_sm2_ex(DD.d, tmp.d, XYsub1.d, group->order.d, group->order_top);

	memcpy(t, DD.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCD.Ka[i] = t[i];//MARK
	}
#ifndef SM2_DEBUG
	PrintHex("ECC_do_key stECCD.Ka:", stECCD.Ka, ECC_BLOCK_LEN);
#endif
	ECC_Private_To_WOLFSSL_ex(&stECCD, D2);

	memset(&R, 0, sizeof(EC_POINT));
	EC_POINTs_mul_sm2_ex(group, &R, &group->generator, &XYsub1, NULL, NULL);
	ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);


	//将小端模式转换到大端模式，并输出公私钥
	memcpy(t, x.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCPK.Qx[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(t, y.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCPK.Qy[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	ECC_Public_To_WOLFSSL_ex(&stECCPK, PubK);
	return 0;

}

int SM2_Split_GenKeyComponent1(EC_GROUP *group, ECCrefPrivateKey *D1, ECCrefPublicKey *P1)
{
	int i;
	FLKBIGNUM k;
	unsigned char t[ECC_BLOCK_LEN];
	unsigned char Ka_256[ECC_BLOCK_LEN];
	FLKBIGNUM x, y;

	memset(&k, 0, FLK_BIGNUM_SIZE);
	ECC_PRIVATE_KEY 		stECCSK;
	ECC_PUBLIC_KEY 			stECCPK;
	EC_POINT 				R;

	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		Ka_256[i] = (unsigned char)((rand() % 255) + 1);//SK,1<=SK<=n-1
	}

	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = Ka_256[31 - i];
	}
	memcpy(k.d, t, ECC_BLOCK_LEN);

	//1 <= k <= n-1
	while (k.d[ECC_BLOCK_LEN_DWORD - 1] >= group->order.d[ECC_BLOCK_LEN_DWORD - 1])
	{
		k.d[ECC_BLOCK_LEN_DWORD - 1] >>= 1;
	}

	//将小端模式转换到大端模式，并输出私钥分量D
	memcpy(t, k.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCSK.Ka[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	FLKBIGNUM tmp;
	int len;
	// 计算D1 的逆
	BN_mod_inverse_sm2_ex(tmp.d, &len, k.d, group->order_top, group->order.d, group->order_top);
	//计算P1(x1, y1) = D1-1[*]G
	memset(&R, 0x00, sizeof(EC_POINT));
	EC_POINTs_mul_sm2_ex(group, &R, &group->generator, &tmp, NULL, NULL);
	ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);

	BN_mod_add_sm2_ex(x.d, y.d, k.d, group->order.d, group->order_top);

	//将小端模式转换到大端模式，并输出公私钥
	memcpy(t, x.d, ECC_BLOCK_LEN);	/////////TBD
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCPK.Qx[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(t, y.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCPK.Qy[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	ECC_Private_To_WOLFSSL_ex(&stECCSK, D1);
	ECC_Public_To_WOLFSSL_ex(&stECCPK, P1);
#ifndef SM2_DEBUG
	//PrintHex("SM2_Split_GenKeyComponent1 D1->D:", D1->D, ECCref_MAX_LEN);
	//PrintHex("SM2_Split_GenKeyComponent1 P1->x:", P1->x,ECCref_MAX_LEN);
	//PrintHex("SM2_Split_GenKeyComponent1 P1->y:", P1->y,ECCref_MAX_LEN);
#endif
	return 0;
}


int SM2_Split_GenKeyComponent2(EC_GROUP *group, ECCrefPublicKey *P1, ECCrefPrivateKey *D2, ECCrefPublicKey *P)
{
	int i;
	FLKBIGNUM k;
	unsigned char t[ECC_BLOCK_LEN];
	unsigned char Ka_256[ECC_BLOCK_LEN];
	FLKBIGNUM x, y, DX;

	memset(&k, 0, FLK_BIGNUM_SIZE);
	ECC_PRIVATE_KEY 		stECCSK;
	ECC_PUBLIC_KEY 			stECCPK;

	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		Ka_256[i] = (unsigned char)((rand() % 255) + 1);//SK,1<=SK<=n-1
	}

	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = Ka_256[31 - i];
	}
	memcpy(k.d, t, ECC_BLOCK_LEN);

	//1 <= k <= n-1
	while (k.d[ECC_BLOCK_LEN_DWORD - 1] >= group->order.d[ECC_BLOCK_LEN_DWORD - 1])
	{
		k.d[ECC_BLOCK_LEN_DWORD - 1] >>= 1;
	}

	//将小端模式转换到大端模式，并输出私钥分量D2
	memcpy(t, k.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCSK.Ka[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	FLKBIGNUM tmp;
	int len, DX_top;
	EC_POINT R, Q, S, UG;
	memset(&R, 0, sizeof(EC_POINT));
	memset(&Q, 0, sizeof(EC_POINT));
	memset(&S, 0, sizeof(EC_POINT));
	memset(&UG, 0, sizeof(EC_POINT));

	// 计算D2 的逆
	BN_mod_inverse_sm2_ex(tmp.d, &len, k.d, group->order_top, group->order.d, group->order_top);
	//计算P(x1, y1) = D2-1[*]P1[-]G
	//初始化公钥 point Q
	ECC_Public_From_WOLFSSL_ex(&stECCPK, P1);
	memset(&Q, 0, sizeof(EC_POINT));
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCPK.Qx[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(Q.X.d, t, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCPK.Qy[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(Q.Y.d, t, ECC_BLOCK_LEN);

	/////////TBD
	BN_mod_sub_sm2_ex(DX.d, &DX_top, Q.X.d, Q.Y.d, group->order.d, group->field_top);
	if (DX_top == 0)
	{
		return -1;
	}

	BN_mod_mul_montgomery_sm2_ex(Q.X.d, Q.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2_ex(Q.Y.d, Q.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	memcpy(Q.Z.d, group->field_data2.d, group->field_top*FLK_BN_BYTES);
	Q.Z_is_one = 1;

	EC_POINTs_mul_sm2_ex(group, &R, &Q, &tmp, NULL, NULL);

	memcpy(&UG, &(group->generator), sizeof(EC_POINT));
	ec_GFp_simple_invert_sm2_ex(group, &(group->generator), &UG);

	ec_GFp_simple_add_sm2_ex(group, &S, &R, &UG);

	printPoint("pub key:", &S);

	ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &S, &x, &y);

	//将小端模式转换到大端模式，并输出公钥
	memcpy(t, x.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCPK.Qx[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(t, y.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCPK.Qy[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	ECC_do_key(&DX, &k, D2, P);
#ifndef SM2_DEBUG
	//PrintHex("SM2_Split_GenKeyComponent2 P1->x:", P1->x,ECCref_MAX_LEN);
	//PrintHex("SM2_Split_GenKeyComponent2 P1->y:", P1->y,ECCref_MAX_LEN);
	//PrintHex("SM2_Split_GenKeyComponent2 D2->D:", D2->D, ECCref_MAX_LEN);
	//PrintHex("SM2_Split_GenKeyComponent2 P->x:", P->x,ECCref_MAX_LEN);
	//PrintHex("SM2_Split_GenKeyComponent2 P->y:", P->y,ECCref_MAX_LEN);
#endif
	return 0;
}



int SM2_GenKeyComponent1(ECCrefPrivateKey *D1, ECCrefPublicKey *P1)
{
	return SM2_Split_GenKeyComponent1(&G_group, D1, P1);
}


int SM2_GenKeyComponent2(ECCrefPublicKey *P1, ECCrefPrivateKey *D2, ECCrefPublicKey *P)
{
	return  SM2_Split_GenKeyComponent2(&G_group, P1, D2, P);
}


int SM2_KeyComponent1Sign(int flag, const unsigned char *pucData, size_t uiDataLength, unsigned char *hash, unsigned char *K1, ECCSignature *Q1)
{
	ECC_SIGNATURE 			stECCSign;

	if (flag == ECC_SIGN_FLAG_ORIGINAL)
	{
		if (uiDataLength != SM3_DIGEST_LENGTH)
		{
			return ERR_SM2_SIGN_DATA;
		}
		memcpy(hash, pucData, uiDataLength);
	}
	else if (flag == ECC_SIGN_FLAG_HASH)
	{
		algrithm_ex(pucData, uiDataLength, 0, hash);
	}
	else
	{
		return ERR_SM2_SIGN_FLAG;
	}

	int i;
	EC_POINT R;
	FLKBIGNUM k;
	FLKBIGNUM x, y;
	unsigned char t[ECC_BLOCK_LEN];
	FLKBIGNUM Plain;
	unsigned char rnd[ECC_BLOCK_LEN];// = {0xfd,0xd5,0x08,0x20,0xe3,0x17,0x06,0x84,0x54,0xc1,0xc0,0x41,0x99,0x08,0xb5,0x12,0xcd,0xb4,0xc6,0x96,0x9a,0x72,0x98,0x40,0xdf,0x0b,0x3b,0x21,0x26,0x4c,0x08,0xc0};
	EC_GROUP *group = &G_group;

	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		rnd[i] = (unsigned char)((rand() % 255) + 1);
	}
	//初始化明文
	memset(&Plain, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = hash[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(Plain.d, t, ECC_BLOCK_LEN);

again:
	memset(&k, 0, FLK_BIGNUM_SIZE);
	memcpy(k.d, rnd, ECC_BLOCK_LEN);

	while (k.d[ECC_BLOCK_LEN_DWORD - 1] >= group->order.d[ECC_BLOCK_LEN_DWORD - 1])
	{
		k.d[ECC_BLOCK_LEN_DWORD - 1] >>= 1;
	}

	//(x1, y1) = kG
	EC_POINTs_mul_sm2_ex(group, &R, &group->generator, &k, NULL, NULL);
	ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);

	//将小端模式转换到大端模式，并输出公私钥
	memcpy(t, x.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCSign.s[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(t, y.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCSign.r[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	ECC_ECCSignature_To_WOLFSSL_ex(&stECCSign, Q1);

	//将小端模式转换到大端模式，并输出K1
	memcpy(t, k.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		K1[i] = t[ECC_BLOCK_LEN - 1 - i];
	}
#ifndef SM2_DEBUG
	//PrintHex("SM2_KeyComponent1Sign K1:", K1, ECC_BLOCK_LEN);
	//PrintHex("SM2_KeyComponent1Sign hash:", hash,ECC_BLOCK_LEN);
	//PrintHex("SM2_KeyComponent1Sign Q1->r:", Q1->r, ECCref_MAX_LEN);
	//PrintHex("SM2_KeyComponent1Sign Q1->s:", Q1->s,ECCref_MAX_LEN);
#endif
	return 0;
}


int SM2_KeyComponent2Sign(const ECCrefPrivateKey *D2, unsigned char *hash, ECCSignature *Q1, ECCComponentSignature *D2SN)
{
	ECC_PRIVATE_KEY 		stECCSK;
	ECC_SIGNATURE 			stECCSign;
	FLKBIGNUM k2, k3, SK;
	FLKBIGNUM  S2;
	EC_GROUP *group = &G_group;
	unsigned char t[ECC_BLOCK_LEN];
	int i;

	ECC_Private_From_WOLFSSL_ex(&stECCSK, D2);
	//ECC_ECCSignature_From_WOLFSSL_ex(&stECCSign, Q1);

	//初始化私钥
	memset(&SK, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCSK.Ka[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(SK.d, t, ECC_BLOCK_LEN);

#if 0
	EC_POINT R3, Q2, R;
	FLKBIGNUM x, y;
	FLKBIGNUM Plain;
	unsigned char rnd[ECC_BLOCK_LEN];// = {0xfd,0xd5,0x08,0x20,0xe3,0x17,0x06,0x84,0x54,0xc1,0xc0,0x41,0x99,0x08,0xb5,0x12,0xcd,0xb4,0xc6,0x96,0x9a,0x72,0x98,0x40,0xdf,0x0b,0x3b,0x21,0x26,0x4c,0x08,0xc0};


									 //(x1, y1) = k2G
									 //初始化明文
	memset(&Plain, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = hash[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(Plain.d, t, ECC_BLOCK_LEN);

	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		rnd[i] = (unsigned char)((rand() % 255) + 1);
	}

	memset(&k2, 0, FLK_BIGNUM_SIZE);
	memcpy(k2.d, rnd, ECC_BLOCK_LEN);

	while (k2.d[ECC_BLOCK_LEN_DWORD - 1] >= group->order.d[ECC_BLOCK_LEN_DWORD - 1])
	{
		k2.d[ECC_BLOCK_LEN_DWORD - 1] >>= 1;
	}

	EC_POINTs_mul_sm2_ex(group, &Q2, &group->generator, &k2, NULL, NULL);

again:
	//(x2, y2) = k3Q1+Q2
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		rnd[i] = (unsigned char)((rand() % 255) + 1);
	}

	memset(&k3, 0, FLK_BIGNUM_SIZE);
	memcpy(k3.d, rnd, ECC_BLOCK_LEN);

	while (k3.d[ECC_BLOCK_LEN_DWORD - 1] >= group->order.d[ECC_BLOCK_LEN_DWORD - 1])
	{
		k3.d[ECC_BLOCK_LEN_DWORD - 1] >>= 1;
	}

	EC_POINT q1;
	memset(&q1, 0, sizeof(EC_POINT));
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCSign.r[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(q1.X.d, t, ECC_BLOCK_LEN);

	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCSign.s[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(q1.Y.d, t, ECC_BLOCK_LEN);

	BN_mod_mul_montgomery_sm2_ex(q1.X.d, q1.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2_ex(q1.Y.d, q1.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	memcpy(q1.Z.d, group->field_data2.d, group->field_top*FLK_BN_BYTES);
	q1.Z_is_one = 1;

	EC_POINTs_mul_sm2_ex(group, &R3, &q1, &k3, NULL, NULL);

	ec_GFp_simple_add_sm2_ex(group, &R, &R3, &Q2);

	ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);

	// r =( e+x) mod n
	FLKBIGNUM  zwk_temp;
	FLKBIGNUM r;
	int top;
	BN_mod_add_sm2_ex(zwk_temp.d, Plain.d, x.d, group->order.d, group->order_top);
	BN_div_sm2_ex(NULL, NULL, r.d, &top, zwk_temp.d, group->order_top, group->order.d, group->order_top);
	if (top == 0)
	{
		goto again;	//r = 0  返回
	}

	// S2 = D2*k3mod n
	int temp_top, S2l;

	int skl = ECC_BLOCK_LEN_DWORD;
	bn_fix_top_sm2_ex(SK.d, &skl);

	int k3l = ECC_BLOCK_LEN_DWORD;
	bn_fix_top_sm2_ex(k3.d, &k3l);

	BN_mul_sm2_ex(temp.d, &temp_top, SK.d, skl, k3.d, k3l);
	BN_div_sm2_ex(NULL, NULL, S2.d, &S2l, temp.d, temp_top, group->field.d, group->field_top);

	// S3 = D2*(r+k2)
	FLKBIGNUM  r_add_k2, S3;
	int S3l;
	BN_mod_add_sm2_ex(r_add_k2.d, r.d, k2.d, group->order.d, group->order_top);

	int r_add_k2l = ECC_BLOCK_LEN_DWORD;
	bn_fix_top_sm2_ex(r_add_k2.d, &r_add_k2l);

	BN_mul_sm2_ex(temp.d, &temp_top, SK.d, skl, r_add_k2.d, r_add_k2l);
	BN_div_sm2_ex(NULL, NULL, S3.d, &S3l, temp.d, temp_top, group->field.d, group->field_top);

	//将小端模式转换到大端模式，并输出公私钥
	memcpy(t, r.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		D2SN->r[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	//FLKBIGNUM tmp;
	//int D2l;
	//memset(&tmp, 0, sizeof(FLKBIGNUM));
	//for(i = 0; i < ECC_BLOCK_LEN; i++)
	//{
	//	t[i] = 1;
	//}
	//memcpy(tmp.d, t, ECC_BLOCK_LEN);

	//BN_mod_sub_sm2_ex(SK.d, &D2l, SK.d, tmp.d, group->field.d, group->field_top);
	//if (D2l == 0)
	//{
	//	return -1;
	//}

#endif
	memcpy(t, SK.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCSK.Ka[i] = t[i];	//MARK
	}



	ECC_SIGNATURE ECCSign;
	ECDSA_Signature_ex(group, hash, (ECC_PRIVATE_KEY *)&stECCSK, &ECCSign);
	FLKBIGNUM r2, s3;
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = ECCSign.r[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(r2.d, t, ECC_BLOCK_LEN);

	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = ECCSign.s[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(s3.d, t, ECC_BLOCK_LEN);

	FLKBIGNUM tmp1, RR2, SS3;
	memset(&tmp1, 0, sizeof(FLKBIGNUM));
	memset(&RR2, 0, sizeof(FLKBIGNUM));
	memset(&SS3, 0, sizeof(FLKBIGNUM));

	//for(i = 0; i < ECC_BLOCK_LEN; i++)
	//{
	//	t[i] = 1;
	//}
	//memcpy(tmp1.d, t, ECC_BLOCK_LEN);

	//BN_mod_add_sm2_ex(RR2.d, r2.d, tmp1.d, group->order.d, group->order_top);
	//BN_mod_add_sm2_ex(SS3.d, s3.d, tmp1.d, group->order.d, group->order_top);
	memcpy(RR2.d, r2.d, ECC_BLOCK_LEN);
	memcpy(SS3.d, s3.d, ECC_BLOCK_LEN);

	memcpy(t, RR2.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		D2SN->r[i] = t[i];//MARK
	}
	memcpy(t, S2.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		D2SN->s2[i] = t[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(t, SS3.d, ECC_BLOCK_LEN);

	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		D2SN->s3[i] = t[i];//MARK
	}
#ifndef SM2_DEBUG
	//PrintHex("SM2_KeyComponent2Sign D2->D:", D2->D, ECCref_MAX_LEN);
	//PrintHex("SM2_KeyComponent2Sign Q1->r:", Q1->r, ECCref_MAX_LEN);
	//PrintHex("SM2_KeyComponent2Sign Q1->s:", Q1->s, ECCref_MAX_LEN);
	//PrintHex("SM2_KeyComponent2Sign hash:", hash,ECC_BLOCK_LEN);
	//PrintHex("SM2_KeyComponent2Sign stECCSK.Ka:", stECCSK.Ka, ECC_BLOCK_LEN);
	//PrintHex("SM2_KeyComponent2Sign D2SN->r:", D2SN->r, ECC_BLOCK_LEN);
	//PrintHex("SM2_KeyComponent2Sign D2SN->s2:", D2SN->s2,ECC_BLOCK_LEN);
	//PrintHex("SM2_KeyComponent2Sign D2SN->s3:", D2SN->s3,ECC_BLOCK_LEN);
#endif
	return 0;
}


SM2_DLL int SM2_KeyComponent2Sign_ex(const unsigned char* D2_key, int D2_len, const unsigned char* input, int input_len, unsigned char* sign, int *sign_len)
{
	// D2私钥分量
	ECCrefPrivateKey D2;
	D2.bits = D2_len * 8;
	if (D2_len != ECCref_MAX_LEN)
	{
		return -1;
	}
	memcpy(D2.D, D2_key, ECCref_MAX_LEN);
	// Q1 and hash
	unsigned char hash[ECC_BLOCK_LEN] = { 0 };
	ECCSignature Q1;
	if (input_len < ECC_BLOCK_LEN + sizeof(ECCSignature) || *sign_len < 96)
	{
		return -2;
	}
	memcpy(hash, input, ECC_BLOCK_LEN);
	memcpy(&Q1, input + ECC_BLOCK_LEN, sizeof(ECCSignature));

	ECCComponentSignature D2SN;
	SM2_KeyComponent2Sign(&D2, hash, &Q1, &D2SN);
	memcpy(sign, &D2SN, sizeof(ECCComponentSignature));
	*sign_len = sizeof(ECCComponentSignature);
	return 0;
}

int SM2_KeyComponent3Sign(const ECCrefPrivateKey *P1, unsigned char *K1, ECCComponentSignature *D2SN, ECCSignature *Signature)
{
	ECC_SIGNATURE 			stECCSign;
	ECC_PRIVATE_KEY 		stECCSK;
	int i;
	unsigned char t[ECC_BLOCK_LEN];
	FLKBIGNUM SK, k1, temp, r, RR, SS, S2, S3;
#if 0
	EC_POINT R;
	FLKBIGNUM k;
	FLKBIGNUM x, y;
	FLKBIGNUM Plain;
	unsigned char rnd[ECC_BLOCK_LEN];// = {0xfd,0xd5,0x08,0x20,0xe3,0x17,0x06,0x84,0x54,0xc1,0xc0,0x41,0x99,0x08,0xb5,0x12,0xcd,0xb4,0xc6,0x96,0x9a,0x72,0x98,0x40,0xdf,0x0b,0x3b,0x21,0x26,0x4c,0x08,0xc0};
	EC_GROUP *group = &G_group;
	int top;


	ECC_Private_From_WOLFSSL_ex(&stECCSK, P1);
	int temp_top;
	memset(&temp, 0, FLK_BIGNUM_SIZE);
	memset(&r, 0, FLK_BIGNUM_SIZE);
	memset(&RR, 0, FLK_BIGNUM_SIZE);
	memset(&SS, 0, FLK_BIGNUM_SIZE);
	memset(&S2, 0, FLK_BIGNUM_SIZE);
	memset(&S3, 0, FLK_BIGNUM_SIZE);
	//初始化私钥
	memset(&SK, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCSK.Ka[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(SK.d, t, ECC_BLOCK_LEN);

	// s =(D1*k1)*s2+D1*s3-r mod n
	memset(&k1, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = K1[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(k1.d, t, ECC_BLOCK_LEN);

	int skl = ECC_BLOCK_LEN_DWORD;
	bn_fix_top_sm2_ex(SK.d, &skl);
	int k1l = ECC_BLOCK_LEN_DWORD;
	bn_fix_top_sm2_ex(k1.d, &k1l);

	memset(&temp, 0, FLK_BIGNUM_SIZE);
	BN_mul_sm2_ex(temp.d, &temp_top, SK.d, skl, k1.d, k1l);

	//FLKBIGNUM D1MULK1;
	//int D1MULK1_top;
	//BN_div_sm2_ex(NULL, NULL, D1MULK1.d, &D1MULK1_top, temp.d, group->order_top, group->order.d, group->order_top);
	//if (D1MULK1_top == 0)
	//{
	//	return -2;
	//}
#endif

	memset(&r, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = D2SN->r[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(r.d, t, ECC_BLOCK_LEN);

	memset(&S2, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = D2SN->s2[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(S2.d, t, ECC_BLOCK_LEN);

	memset(&S3, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = D2SN->s3[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(S3.d, t, ECC_BLOCK_LEN);

#if 0
	int S2l = ECC_BLOCK_LEN_DWORD;
	bn_fix_top_sm2_ex(S2.d, &S2l);

	FLKBIGNUM D1XK1XS2_tmp;
	int D1XK1XS2_tmp_top;
	FLKBIGNUM D1XK1XS2;
	int D1XK1XS2_top;

	BN_mul_sm2_ex(D1XK1XS2_tmp.d, &D1XK1XS2_tmp_top, temp.d, temp_top, S2.d, S2l);
	BN_div_sm2_ex(NULL, NULL, D1XK1XS2.d, &D1XK1XS2_top, D1XK1XS2_tmp.d, group->order_top, group->order.d, group->order_top);
	if (D1XK1XS2_top == 0)
	{
		return -1;
	}

	FLKBIGNUM D1S3_tmp;
	int D1S3_tmp_top;
	FLKBIGNUM D1S3;
	int D1S3_top;
	int S3l = ECC_BLOCK_LEN_DWORD;
	bn_fix_top_sm2_ex(S3.d, &S3l);

	BN_mul_sm2_ex(D1S3_tmp.d, &D1S3_tmp_top, SK.d, skl, S3.d, S3l);
	BN_div_sm2_ex(NULL, NULL, D1S3.d, &D1S3_top, D1S3_tmp.d, group->order_top, group->order.d, group->order_top);
	if (D1S3_top == 0)
	{
		return -2;
	}

	FLKBIGNUM  sum_temp;
	FLKBIGNUM stmp, s;
	BN_mod_add_sm2_ex(sum_temp.d, D1XK1XS2.d, D1S3.d, group->order.d, group->order_top);

	BN_mod_sub_sm2_ex(stmp.d, &top, sum_temp.d, r.d, group->field.d, group->field_top);
	if (top == 0)
	{
		return -3;
	}

	BN_div_sm2_ex(NULL, NULL, s.d, &top, stmp.d, group->order_top, group->order.d, group->order_top);
	if (top == 0)
	{
		return -4;
	}

	//FLKBIGNUM tmp1;
	//memset(&tmp1, 0, sizeof(FLKBIGNUM));
	//for(i = 0; i < ECC_BLOCK_LEN; i++)
	//{
	//	t[i] = 1;
	//}
	//memcpy(tmp1.d, t, ECC_BLOCK_LEN);

	//int r_top;
	//BN_mod_sub_sm2_ex(RR.d, &r_top, r.d, tmp1.d, group->field.d, group->field_top);
	//if (r_top == 0)
	//{
	//	return -1;
	//}
	//int s_top;
	//BN_mod_sub_sm2_ex(SS.d, &s_top, S3.d, tmp1.d, group->field.d, group->field_top);
	//if (s_top == 0)
	//{
	//	return -1;
	//}
	// S = (r,s)
#endif
	//将小端模式转换到大端模式，并输出公私钥
	memcpy(RR.d, r.d, ECC_BLOCK_LEN);
	memcpy(t, RR.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCSign.r[i] = t[i]; //MARK
	}
	memcpy(SS.d, S3.d, ECC_BLOCK_LEN);
	memcpy(t, SS.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCSign.s[i] = t[i];//MARK
	}
	ECC_ECCSignature_To_WOLFSSL_ex(&stECCSign, Signature);
#ifdef SM2_DEBUG
	PrintHex("SM2_KeyComponent3Sign Signature->r:", Signature->r, ECCref_MAX_LEN);
	PrintHex("SM2_KeyComponent3Sign Signature->s:", Signature->s, ECCref_MAX_LEN);
	PrintHex("SM2_KeyComponent3Sign D2SN->r:", D2SN->r, ECC_BLOCK_LEN);
	PrintHex("SM2_KeyComponent3Sign D2SN->s2:", D2SN->s2, ECC_BLOCK_LEN);
	PrintHex("SM2_KeyComponent3Sign D2SN->s3:", D2SN->s3, ECC_BLOCK_LEN);
#endif
	return 0;

}

int SM2_KeyComponent1Dec(const ECCrefPrivateKey *D1, ECCCipher *cip, TCipher *T1)
{
	FLKBIGNUM k;
	FLKBIGNUM x,  y;
	EC_POINT R,Q;
	unsigned char t[ECC_BLOCK_LEN];
	int  point_on_curve_flag;
	ECC_PUBLIC_KEY QQ;
	int hg,i;
	ECC_ENCRYPTION 			stECCEnc;
	ECC_PRIVATE_KEY 		stECCSK;
	ECC_ECCEncryption_From_WOLFSSL_ex(&stECCEnc, cip);
	ECC_Private_From_WOLFSSL_ex(&stECCSK, D1);
	EC_GROUP *group = &G_group;
	ECC_ENCRYPTION *pEncryption = &stECCEnc;
	   
	memset(&QQ, 0, sizeof(QQ));
	//初始化C1,判断该点是否在曲线上
	memcpy(&QQ.Qx, stECCEnc.C1, ECC_BLOCK_LEN);
	memcpy(&QQ.Qy, stECCEnc.C1 + ECC_BLOCK_LEN, ECC_BLOCK_LEN);
	
      point_on_curve_flag = POINT_is_on_curve_ex(&G_ECCPara, &QQ);
	if(point_on_curve_flag==1) // 点C1在曲线上
	{
		//将小端模式转换到大端模式，并输出私钥分量D
	  	memcpy(t, stECCSK.Ka, ECC_BLOCK_LEN);								
		for(i = 0; i < ECC_BLOCK_LEN; i++)
		{
			k.d[i] = t[ECC_BLOCK_LEN-1-i];
		}
		
		FLKBIGNUM tmp;
		int len;
	       // 计算D1 的逆
		BN_mod_inverse_sm2_ex(tmp.d, &len, k.d, group->order_top, group->order.d, group->order_top);
		//  初始化C1,判断该点是否在曲线上
		// 该在外围做判断
		unsigned char c1[64];
		memset(&Q, 0, sizeof(EC_POINT));
		memcpy(c1, pEncryption->C1, 2*ECC_BLOCK_LEN);
		for(i = 0; i < ECC_BLOCK_LEN; i++)
		{	
			t[i] = c1[31-i];
		}
		memcpy(Q.X.d, t, ECC_BLOCK_LEN);	

		for(i = 0; i < ECC_BLOCK_LEN; i++)
		{
		     t[i] =  c1[63-i];
		}
		memcpy(Q.Y.d, t, ECC_BLOCK_LEN);


		PrintBIGNUM("before c1 Q.X.d", Q.X);
		BN_mod_mul_montgomery_sm2_ex(Q.X.d, Q.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
		PrintBIGNUM("after c1 Q.X.d", Q.X);

		PrintBIGNUM("before c1 Q.Y.d", Q.Y);
		BN_mod_mul_montgomery_sm2_ex(Q.Y.d, Q.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
		PrintBIGNUM("after c1 Q.Y.d", Q.Y);

		memcpy(Q.Z.d, group->field_data2.d, group->field_top*FLK_BN_BYTES);
		PrintBIGNUM("c1 Q.Z.d", Q.Z);
		Q.Z_is_one=1;

		printPoint("before R:", &R);
		printPoint("before Q:", &Q);

		//(x1,y1)=d-1*C1
		EC_POINTs_mul_sm2_ex(group, &R, &Q, &tmp, NULL,NULL); 
		ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);
		printPoint("after R:", &R);
		PrintBIGNUM("after x:", x);
		PrintBIGNUM("after y:", y);
		//将小端模式转换到大端模式，并输出公钥
		ECC_PUBLIC_KEY 			stECCPK;    
		ECCrefPublicKey 			pucPublicKey;
	  	memcpy(t, x.d, ECC_BLOCK_LEN);								
		for(i = 0; i < ECC_BLOCK_LEN; i++)
		{
			stECCPK.Qx[i] = t[ECC_BLOCK_LEN-1-i];
		}

	  	memcpy(t, y.d, ECC_BLOCK_LEN);								
		for(i = 0; i < ECC_BLOCK_LEN; i++)
		{
			stECCPK.Qy[i] = t[ECC_BLOCK_LEN-1-i];
		}
		ECC_Public_To_WOLFSSL_ex(&stECCPK, &pucPublicKey);
		memcpy(T1, &pucPublicKey, sizeof(ECCrefPublicKey));
		return ERR_SUCCESS;
	}
	return ERR_SM2_DECRYPT;
}

int SM2_KeyComponent2Dec(const ECCrefPrivateKey *D2, TCipher *T1Cip, TCipher *T2)
{
	ECC_PUBLIC_KEY 			stECCT1;    
	ECC_PRIVATE_KEY 		stECCSK;
	EC_POINT T1,R;
	FLKBIGNUM x,  y;
	FLKBIGNUM k;
	int i;
	unsigned char t[ECC_BLOCK_LEN];
	EC_GROUP *group = &G_group;
	ECC_Private_From_WOLFSSL_ex(&stECCSK, D2);
	//初始化公钥 point Q
	ECC_Public_From_WOLFSSL_ex(&stECCT1, (ECCrefPublicKey*)T1Cip);
	memset(&T1, 0, sizeof(EC_POINT));
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCT1.Qx[ECC_BLOCK_LEN-1-i];
	}
	memcpy(T1.X.d, t, ECC_BLOCK_LEN);
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCT1.Qy[ECC_BLOCK_LEN-1-i];
	}
	memcpy(T1.Y.d, t, ECC_BLOCK_LEN);

	BN_mod_mul_montgomery_sm2_ex(T1.X.d, T1.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2_ex(T1.Y.d, T1.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	memcpy(T1.Z.d, group->field_data2.d, group->field_top*FLK_BN_BYTES);
	T1.Z_is_one = 1;

	//将小端模式转换到大端模式，并输出私钥分量D
  	memcpy(t, stECCSK.Ka, ECC_BLOCK_LEN);								
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		k.d[i] = t[ECC_BLOCK_LEN-1-i];
	}
	
	FLKBIGNUM tmp;
	int len;
       // 计算D2 的逆
	BN_mod_inverse_sm2_ex(tmp.d, &len, k.d, group->order_top, group->order.d, group->order_top);
 	EC_POINTs_mul_sm2_ex(group, &R,  &T1, &tmp, NULL, NULL); 
	ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);
	printPoint("after R:", &R);
	PrintBIGNUM("after x:", x);
	PrintBIGNUM("after y:", y);
	//将小端模式转换到大端模式，并输出公钥
	ECC_PUBLIC_KEY 			stECCPK;    
	ECCrefPublicKey 			pucPublicKey;
  	memcpy(t, x.d, ECC_BLOCK_LEN);								
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCPK.Qx[i] = t[ECC_BLOCK_LEN-1-i];
	}

  	memcpy(t, y.d, ECC_BLOCK_LEN);								
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCPK.Qy[i] = t[ECC_BLOCK_LEN-1-i];
	}
  	memcpy(stECCPK.Qy, stECCSK.Ka, ECC_BLOCK_LEN);		
	ECC_Public_To_WOLFSSL_ex(&stECCPK, &pucPublicKey);
	memcpy(T2, &pucPublicKey, sizeof(ECCrefPublicKey));
	return ERR_SUCCESS;
}

int SM2_KeyComponent3Dec(ECCCipher *cip, TCipher *T2Cip, unsigned char *pucData,size_t *puiDataLength)
{
	int i;
	FLKBIGNUM x2,  y2;
	EC_GROUP *group = &G_group;
	unsigned char t[ECC_BLOCK_LEN];
	//初始化公钥 point Q
	EC_POINT T2,R,C1, InverseC1, T2C1;
	ECC_PUBLIC_KEY 			stECCT2;    
	ECC_ENCRYPTION 			stECCEnc;
	ECC_ECCEncryption_From_WOLFSSL_ex(&stECCEnc, cip);
	ECC_ENCRYPTION *pEncryption = &stECCEnc;
	ECC_Public_From_WOLFSSL_ex(&stECCT2, (ECCrefPublicKey*)T2Cip);
	memset(&T2, 0, sizeof(EC_POINT));
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCT2.Qx[ECC_BLOCK_LEN-1-i];
	}
	memcpy(T2.X.d, t, ECC_BLOCK_LEN);
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCT2.Qy[ECC_BLOCK_LEN-1-i];
	}
	memcpy(T2.Y.d, t, ECC_BLOCK_LEN);

	BN_mod_mul_montgomery_sm2_ex(T2.X.d, T2.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2_ex(T2.Y.d, T2.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	memcpy(T2.Z.d, group->field_data2.d, group->field_top*FLK_BN_BYTES);
	T2.Z_is_one = 1;

	// 该在外围做判断
	unsigned char c1[64];
	memset(&C1, 0, sizeof(EC_POINT));
	memcpy(c1, pEncryption->C1, 2*ECC_BLOCK_LEN);
	unsigned char c2[ECC_MAX_ENCRYPT_LENGTH];
	unsigned char c3[32];
	int c2_len = pEncryption->len;
	
	memcpy(c1, pEncryption->C1, 2*ECC_BLOCK_LEN);
	memcpy(c3, pEncryption->C3, ECC_BLOCK_LEN);
	memset(c2, 0, sizeof(c2));
	memcpy(c2, pEncryption->C2, c2_len);	
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{	
		t[i] = c1[31-i];
	}
	memcpy(C1.X.d, t, ECC_BLOCK_LEN);	

	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
	     t[i] =  c1[63-i];
	}
	memcpy(C1.Y.d, t, ECC_BLOCK_LEN);


	PrintBIGNUM("before c1 C1.X.d", C1.X);
	BN_mod_mul_montgomery_sm2_ex(C1.X.d, C1.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	PrintBIGNUM("after c1 C1.X.d", C1.X);

	PrintBIGNUM("before c1 C1.Y.d", C1.Y);
	BN_mod_mul_montgomery_sm2_ex(C1.Y.d,C1.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	PrintBIGNUM("after c1 C1.Y.d", C1.Y);

	memcpy(C1.Z.d, group->field_data2.d, group->field_top*FLK_BN_BYTES);
	PrintBIGNUM("c1 C1.Z.d", C1.Z);
	C1.Z_is_one=1;

	printPoint("before C1:", &C1);	
	memset(&InverseC1, 0, sizeof(EC_POINT));
	ec_GFp_simple_invert_sm2_ex(group, &C1, &InverseC1);

	printPoint("after InverseC1:", &InverseC1);	
	memset(&T2C1, 0, sizeof(EC_POINT));
	ec_GFp_simple_add_sm2_ex(group, &T2C1, &T2, &InverseC1);
	ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &T2C1, &x2, &y2);
	PrintBIGNUM("after x2:", x2);
	PrintBIGNUM("after y2:", y2);

	//KDF的输入和X2,Y2的转化，是否要做x2,y2的数据颠倒。？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？
	// 本处做数据的颠倒
	unsigned char  *c2_kdf = (unsigned char *)malloc(pEncryption->len);
	unsigned char  *t_xor_m = (unsigned char *)malloc(pEncryption->len);
	unsigned char x2_y2[64];
	unsigned char x2in[ECC_BLOCK_LEN],y2in[ECC_BLOCK_LEN];	
	unsigned char  *hash_in = (unsigned char *)malloc(32+32+pEncryption->len);
	unsigned char u[32];//B5
	int char_equal = 0;// B5 判断u和C3是否相等
	memcpy(t, x2.d, ECC_BLOCK_LEN);
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		x2in[i] = t[ECC_BLOCK_LEN-1-i];
	}
	memcpy(t, y2.d, ECC_BLOCK_LEN);
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		y2in[i] = t[ECC_BLOCK_LEN-1-i];
	}
	
	memcpy(x2_y2, x2in, 32);
	memcpy(x2_y2 + 32, y2in, 32);

	//PrintHex("x2_y2",x2_y2,64);

	//B3 kdf
	KDF_ALGRITRHM_ex(x2_y2,64,pEncryption->len,c2_kdf);

	for(i=0;i<c2_len;i++)  // B4
	{ 
		t_xor_m[i] = c2[i] ^ c2_kdf[i];
	}

	//PrintHex("dec:", e, c2_len);
	 
	//B5
	for(i=0;i<32;i++)
	{
		hash_in[i] =x2in[i];
	}
	
	for(i=32;i<32+c2_len;i++)
	{
		hash_in[i] =t_xor_m[i-32];
	}

	for(i=32+c2_len;i<32+c2_len+32;i++)
	{
		hash_in[i] =y2in[i-32-c2_len];
	}

	algrithm_ex( hash_in,32+32+c2_len,0,u);
	for(i=0;i<32;i++)
	{  
		char_equal = char_equal+(unsigned int)(u[i] -c3[i]);
	}
	ECC_PRIVATE_KEY stECCSK;							
	for(i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCSK.Ka[i] = stECCT2.Qy[ECC_BLOCK_LEN-1-i];	//MARK
	}
	int hg = ECES_Decryption_ex(&G_group,&stECCEnc,stECCEnc.len, &stECCSK, pucData);
	if(hg != 1) // 解密 failed
	{
		return ERR_SM2_DECRYPT;
	}
	*puiDataLength = pEncryption->len;
	//memcpy(pucData, t_xor_m, *puiDataLength);
	//show("pucData = %s, *puiDataLength= %d\n", pucData, *puiDataLength);
	free(c2_kdf);
	free(t_xor_m);
	free(hash_in);
	return ERR_SUCCESS;
}
#endif

#if 1
int ECC_do_key(FLKBIGNUM *X, FLKBIGNUM *Y, ECC_PUBLIC_KEY *PubK)
{
	ECC_PRIVATE_KEY 		stECCSK1;
	ECC_PRIVATE_KEY 		stECCSK2;
	ECC_PRIVATE_KEY 		stECCD;

	int i;
	EC_POINT R;
	FLKBIGNUM k;
	FLKBIGNUM x, y;
	FLKBIGNUM DD;
	FLKBIGNUM tmp;
	FLKBIGNUM Plain;
	unsigned char t[ECC_BLOCK_LEN];
	unsigned char rnd[ECC_BLOCK_LEN];// = {0xfd,0xd5,0x08,0x20,0xe3,0x17,0x06,0x84,0x54,0xc1,0xc0,0x41,0x99,0x08,0xb5,0x12,0xcd,0xb4,0xc6,0x96,0x9a,0x72,0x98,0x40,0xdf,0x0b,0x3b,0x21,0x26,0x4c,0x08,0xc0};
	EC_GROUP *group = &G_group;
	int top;

	FLK_BN_ULONG XYtmp[ECC_BLOCK_LEN_DWORD*2];
	FLKBIGNUM SK1, SK2, tmp1, tmp2, XY, XY1, n;
	int temp1_top, temp2_top, XYtmp_top, XY_top, XYsub1_top;
	//初始化私钥
	memset(&SK1, 0, sizeof(FLKBIGNUM));
	memset(&SK2, 0, sizeof(FLKBIGNUM));
	memset(&tmp1, 0, sizeof(FLKBIGNUM));
	memset(&tmp2, 0, sizeof(FLKBIGNUM));
	memset(&XY1, 0, sizeof(FLKBIGNUM));
	memset(&x, 0, sizeof(FLKBIGNUM));
	memset(&y, 0, sizeof(FLKBIGNUM));
	memset(&DD, 0, sizeof(FLKBIGNUM));
	memset(&tmp, 0, sizeof(FLKBIGNUM));

	BN_mod_inverse_sm2_ex(tmp1.d, &temp1_top, X->d, group->order_top, group->order.d, group->order_top);
	BN_mod_inverse_sm2_ex(tmp2.d, &temp2_top, Y->d, group->order_top, group->order.d, group->order_top);

	BN_mul_sm2_ex(XYtmp, &XYtmp_top, tmp1.d, temp1_top, tmp2.d, temp2_top);
	BN_div_sm2_ex(NULL, NULL, XY.d, &XY_top, XYtmp, XYtmp_top, group->order.d, group->order_top);
	if (XY_top == 0)
	{
		return -1;
	}

	memset(&n, 0, sizeof(FLKBIGNUM));
	n.d[0] = 1;
	BN_mod_sub_sm2_ex(XY1.d, &XYsub1_top, XY.d, n.d, group->field.d, group->field_top);
	if (XYsub1_top == 0)
	{
		return -1;
	}
	memcpy(DD.d, XY1.d, ECC_BLOCK_LEN);

	memset(&R, 0, sizeof(EC_POINT));
	EC_POINTs_mul_sm2_ex(group, &R, &group->generator, &XY1, NULL, NULL);
	ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);


	//将小端模式转换到大端模式，并输出公私钥
	memcpy(t, x.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		PubK->Qx[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(t, y.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		PubK->Qy[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	return 0;

}


int SM2_Split_GenKeyComponent1(EC_GROUP *group, ECCrefPrivateKey *D1, ECCrefPublicKey *P1)
{
	int i;
	FLKBIGNUM k;
	unsigned char t[ECC_BLOCK_LEN];
	unsigned char Ka_256[ECC_BLOCK_LEN];
	FLKBIGNUM x, y;

	memset(&k, 0, FLK_BIGNUM_SIZE);
	ECC_PRIVATE_KEY 		stECCSK;
	ECC_PUBLIC_KEY 			stECCPK;
	EC_POINT 				R;

	genrandom(Ka_256, ECC_BLOCK_LEN);//SK,1<=SK<=n-1 

	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = Ka_256[31 - i];
	}
	memcpy(k.d, t, ECC_BLOCK_LEN);

	//1 <= k <= n-1
	while (k.d[ECC_BLOCK_LEN_DWORD - 1] >= group->order.d[ECC_BLOCK_LEN_DWORD - 1])
	{
		k.d[ECC_BLOCK_LEN_DWORD - 1] >>= 1;
	}

	//将小端模式转换到大端模式，并输出私钥分量D
	memcpy(t, k.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCSK.Ka[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	FLKBIGNUM tmp;
	int len;
	// 计算D1 的逆
	BN_mod_inverse_sm2_ex(tmp.d, &len, k.d, group->order_top, group->order.d, group->order_top);
	//计算P1(x1, y1) = D1-1[*]G
	memset(&R, 0x00, sizeof(EC_POINT));
	EC_POINTs_mul_sm2_ex(group, &R, &group->generator, &tmp, NULL, NULL);
	ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);

	BN_mod_add_sm2_ex(x.d, y.d, k.d, group->order.d, group->order_top);

	//将小端模式转换到大端模式，并输出公私钥
	memcpy(t, x.d, ECC_BLOCK_LEN);	/////////TBD							
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCPK.Qx[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(t, y.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCPK.Qy[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	ECC_Private_To_WOLFSSL_ex(&stECCSK, D1);
	ECC_Public_To_WOLFSSL_ex(&stECCPK, P1);
#ifndef SM2_DEBUG
	//PrintHex("SM2_Split_GenKeyComponent1 D1->D:", D1->D, ECCref_MAX_LEN);
	//PrintHex("SM2_Split_GenKeyComponent1 P1->x:", P1->x,ECCref_MAX_LEN);
	//PrintHex("SM2_Split_GenKeyComponent1 P1->y:", P1->y,ECCref_MAX_LEN);
#endif
	return 0;
}


int SM2_Split_GenKeyComponent2(EC_GROUP *group, ECCrefPublicKey *P1, ECCrefPrivateKey *D2, ECCrefPublicKey *P)
{
	int i;
	FLKBIGNUM k;
	unsigned char t[ECC_BLOCK_LEN];
	unsigned char Ka_256[ECC_BLOCK_LEN] = { 0 };
	FLKBIGNUM x, y, DX;

	memset(&k, 0, FLK_BIGNUM_SIZE);
	ECC_PRIVATE_KEY 		stECCSK;
	ECC_PUBLIC_KEY 			stECCPK;

	genrandom(Ka_256, ECC_BLOCK_LEN);//SK,1<=SK<=n-1 

	memcpy(k.d, Ka_256, ECC_BLOCK_LEN);

	//1 <= k <= n-1
	while (k.d[ECC_BLOCK_LEN_DWORD - 1] >= group->order.d[ECC_BLOCK_LEN_DWORD - 1])
	{
		k.d[ECC_BLOCK_LEN_DWORD - 1] >>= 1;
	}

	//将小端模式转换到大端模式，并输出私钥分量D2
	memcpy(t, k.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCSK.Ka[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	FLKBIGNUM tmp;
	int len, DX_top;
	EC_POINT R, Q, S, UG;
	memset(&R, 0, sizeof(EC_POINT));
	memset(&Q, 0, sizeof(EC_POINT));
	memset(&S, 0, sizeof(EC_POINT));
	memset(&UG, 0, sizeof(EC_POINT));

	// 计算D2 的逆
	BN_mod_inverse_sm2_ex(tmp.d, &len, k.d, group->order_top, group->order.d, group->order_top);
	//计算P(x1, y1) = D2-1[*]P1[-]G
	//初始化公钥 point Q
	ECC_Public_From_WOLFSSL_ex(&stECCPK, P1);
	memset(&Q, 0, sizeof(EC_POINT));
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCPK.Qx[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(Q.X.d, t, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCPK.Qy[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(Q.Y.d, t, ECC_BLOCK_LEN);

	/////////TBD
	BN_mod_sub_sm2_ex(DX.d, &DX_top, Q.X.d, Q.Y.d, group->order.d, group->field_top);
	if (DX_top == 0)
	{
		return -1;
	}

	BN_mod_mul_montgomery_sm2_ex(Q.X.d, Q.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2_ex(Q.Y.d, Q.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	memcpy(Q.Z.d, group->field_data2.d, group->field_top*FLK_BN_BYTES);
	Q.Z_is_one = 1;

	EC_POINTs_mul_sm2_ex(group, &R, &Q, &tmp, NULL, NULL);

	memcpy(&UG, &(group->generator), sizeof(EC_POINT));
	ec_GFp_simple_invert_sm2_ex(group, &(group->generator), &UG);

	ec_GFp_simple_add_sm2_ex(group, &S, &R, &UG);


	ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &S, &x, &y);

	//将小端模式转换到大端模式，并输出公钥
	memcpy(t, x.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCPK.Qx[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(t, y.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCPK.Qy[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	ECC_do_key(&DX, &k, &stECCPK);

	ECC_Private_To_WOLFSSL_ex(&stECCSK, D2);

	ECC_Public_To_WOLFSSL_ex(&stECCPK, P);
#ifndef SM2_DEBUG
	//PrintHex("SM2_Split_GenKeyComponent2 P1->x:", P1->x,ECCref_MAX_LEN);
	//PrintHex("SM2_Split_GenKeyComponent2 P1->y:", P1->y,ECCref_MAX_LEN);
	//PrintHex("SM2_Split_GenKeyComponent2 D2->D:", D2->D, ECCref_MAX_LEN);
	//PrintHex("SM2_Split_GenKeyComponent2 P->x:", P->x,ECCref_MAX_LEN);
	//PrintHex("SM2_Split_GenKeyComponent2 P->y:", P->y,ECCref_MAX_LEN);
#endif
	return 0;
}

int SM2_GenKeyComponent1(ECCrefPrivateKey *D1, ECCrefPublicKey *P1)
{
	return SM2_Split_GenKeyComponent1(&G_group, D1, P1);
}


int SM2_GenKeyComponent2(ECCrefPublicKey *P1, ECCrefPrivateKey *D2, ECCrefPublicKey *P)
{
	return  SM2_Split_GenKeyComponent2(&G_group, P1, D2, P);
}


int SM2_KeyComponent1Sign(int flag, const unsigned char *pucData, size_t uiDataLength, const unsigned char *userid, size_t useridlen, ECCrefPublicKey *pubkey, unsigned char *hash, unsigned char *K1, ECCSignature *Q1)
{
	ECC_SIGNATURE 			stECCSign;

	if (flag == ECC_SIGN_FLAG_ORIGINAL)
	{
		if (uiDataLength != SM3_DIGEST_LENGTH)
		{
			return ERR_SM2_SIGN_DATA;
		}
		memcpy(hash, pucData, uiDataLength);
	}
	else if (flag == ECC_SIGN_FLAG_HASH)
	{
		SM2_Sm3Hash(pucData, uiDataLength, userid, useridlen, pubkey, hash);
	}
	else
	{
		return ERR_SM2_SIGN_FLAG;
	}
	int i;
	FLKBIGNUM k;
	FLKBIGNUM x, y;
	unsigned char t[ECC_BLOCK_LEN];
	FLKBIGNUM Plain;
	unsigned char rnd[ECC_BLOCK_LEN];// = {0xfd,0xd5,0x08,0x20,0xe3,0x17,0x06,0x84,0x54,0xc1,0xc0,0x41,0x99,0x08,0xb5,0x12,0xcd,0xb4,0xc6,0x96,0x9a,0x72,0x98,0x40,0xdf,0x0b,0x3b,0x21,0x26,0x4c,0x08,0xc0};
	EC_GROUP *group = &G_group;
	EC_POINT R;
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		genrandom(rnd, ECC_BLOCK_LEN);
	}

	memset(&k, 0, FLK_BIGNUM_SIZE);
	memcpy(k.d, rnd, ECC_BLOCK_LEN);

	while (k.d[ECC_BLOCK_LEN_DWORD - 1] >= group->order.d[ECC_BLOCK_LEN_DWORD - 1])
	{
		k.d[ECC_BLOCK_LEN_DWORD - 1] >>= 1;
	}

	//将小端模式转换到大端模式，并输出K1		
	memcpy(t, k.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		K1[i] = t[ECC_BLOCK_LEN - 1 - i];
	}
	//初始化明文
	memset(&Plain, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = hash[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(Plain.d, t, ECC_BLOCK_LEN);

	EC_POINTs_mul_sm2_ex(group, &R, &group->generator, &k, NULL, NULL);
	ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);

	BN_mod_add_sm2_ex(x.d, k.d, Plain.d, group->order.d, group->order_top);
	BN_mod_add_sm2_ex(y.d, x.d, Plain.d, group->order.d, group->order_top);

	//将小端模式转换到大端模式，并输出公私钥
	memcpy(t, x.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCSign.r[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(t, y.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCSign.s[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	ECC_ECCSignature_To_WOLFSSL_ex(&stECCSign, Q1);

	return 0;
}


int SM2_KeyComponent2Sign(const ECCrefPrivateKey *D2, unsigned char *hash, ECCSignature *QQ1, ECCComponentSignature *D2SN)
{
	ECC_PRIVATE_KEY 		stECCSK;
	ECC_SIGNATURE 			stECCSign;

	ECC_Private_From_WOLFSSL_ex(&stECCSK, D2);
	ECC_ECCSignature_From_WOLFSSL_ex(&stECCSign, QQ1);

	int i;
	EC_POINT R3, Q2, R;
	FLKBIGNUM k, SK;
	FLKBIGNUM x, y;
	unsigned char t[ECC_BLOCK_LEN];
	FLKBIGNUM Plain;
	unsigned char rnd[ECC_BLOCK_LEN];// = {0xfd,0xd5,0x08,0x20,0xe3,0x17,0x06,0x84,0x54,0xc1,0xc0,0x41,0x99,0x08,0xb5,0x12,0xcd,0xb4,0xc6,0x96,0x9a,0x72,0x98,0x40,0xdf,0x0b,0x3b,0x21,0x26,0x4c,0x08,0xc0};
	EC_GROUP *group = &G_group;

	//初始化明文
	memset(&Plain, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = hash[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(Plain.d, t, ECC_BLOCK_LEN);
	//初始化私钥
	memset(&SK, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCSK.Ka[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(SK.d, t, ECC_BLOCK_LEN);

	FLKBIGNUM tmp, tmp1, tmp2, tmp3, tmp4;
	memset(&tmp, 0, FLK_BIGNUM_SIZE);
	memset(&tmp1, 0, FLK_BIGNUM_SIZE);
	memset(&tmp2, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCSign.r[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(tmp1.d, t, ECC_BLOCK_LEN);

	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCSign.s[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(tmp2.d, t, ECC_BLOCK_LEN);

	BN_mod_add_sm2_ex(tmp.d, tmp1.d, Plain.d, group->order.d, group->order_top);
	if (memcmp(tmp2.d, tmp.d, sizeof(tmp.d)) != 0)
	{
		return -1;
	}

	int kl;
	BN_mod_sub_sm2_ex(k.d, &kl, tmp1.d, Plain.d, group->field.d, group->field_top);
	if (kl == 0)
	{
		return -1;
	}

	//将小端模式转换到大端模式，并输出公私钥
	memcpy(t, k.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		rnd[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	ECDSA_Signature_Nornd_ex(&G_group, hash, rnd, &stECCSK, &stECCSign);

	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCSign.r[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(tmp3.d, t, ECC_BLOCK_LEN);

	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCSign.s[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(tmp4.d, t, ECC_BLOCK_LEN);

	FLKBIGNUM  S2;
	int S2l;
	FLKBIGNUM r;

	BN_mod_add_sm2_ex(r.d, tmp3.d, k.d, group->order.d, group->order_top);
	BN_mod_add_sm2_ex(S2.d, tmp4.d, k.d, group->order.d, group->order_top);


	int Plainl = ECC_BLOCK_LEN_DWORD;
	bn_fix_top_sm2_ex(Plain.d, &Plainl);
	BN_div_sm2_ex(NULL, NULL, S2.d, &S2l, Plain.d, Plainl, group->field.d, group->field_top);

	FLKBIGNUM  tmpS3, S3;
	int S3l, tmpS3l;

	BN_mod_inverse_sm2_ex(tmpS3.d, &tmpS3l, SK.d, group->order_top, group->order.d, group->order_top);
	BN_div_sm2_ex(NULL, NULL, S3.d, &S3l, tmpS3.d, tmpS3l, group->field.d, group->field_top);
	PrintBIGNUM("SM2_KeyComponent2Sign tmpS3:", tmpS3);
	PrintBIGNUM("SM2_KeyComponent2Sign SK:", SK);

	FLKBIGNUM  zwk_temp;
	int top;
	BN_mod_add_sm2_ex(zwk_temp.d, tmp1.d, S3.d, group->order.d, group->order_top);
	BN_div_sm2_ex(NULL, NULL, r.d, &top, zwk_temp.d, group->order_top, group->order.d, group->order_top);


	//将小端模式转换到大端模式，并输出公私钥
	memcpy(t, r.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		D2SN->r[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(t, S2.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		D2SN->s2[i] = t[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(t, S3.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		D2SN->s3[i] = t[ECC_BLOCK_LEN - 1 - i];
	}
	return 0;
}


int SM2_KeyComponent3Sign(const ECCrefPrivateKey *D1, unsigned char *K1, ECCComponentSignature *D2SN, ECCSignature *Signature)
{
	ECC_SIGNATURE 			stECCSign;
	ECC_PRIVATE_KEY 		stECCSK;
	FLK_BN_ULONG www[ECC_BLOCK_LEN_DWORD*2+1];
	FLKBIGNUM SK, k1, r, S2, S3,temp;
	FLKBIGNUM Plain;
	FLKBIGNUM  number, www1;
	FLKBIGNUM  zwk_temp;
	int S1S2_top, S1S2sub1_top;
	int temp_top;
	int i;
	int top;
	EC_POINT R;
	FLKBIGNUM k;
	FLKBIGNUM x, y;
	unsigned char t[ECC_BLOCK_LEN];
	unsigned char rnd[ECC_BLOCK_LEN];// = {0xfd,0xd5,0x08,0x20,0xe3,0x17,0x06,0x84,0x54,0xc1,0xc0,0x41,0x99,0x08,0xb5,0x12,0xcd,0xb4,0xc6,0x96,0x9a,0x72,0x98,0x40,0xdf,0x0b,0x3b,0x21,0x26,0x4c,0x08,0xc0};
	EC_GROUP *group = &G_group;


	ECC_Private_From_WOLFSSL_ex(&stECCSK, D1);

	//初始化私钥
	memset(&SK, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCSK.Ka[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(SK.d, t, ECC_BLOCK_LEN);

	memset(&k1, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = K1[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(k1.d, t, ECC_BLOCK_LEN);

	int skl = ECC_BLOCK_LEN_DWORD;
	bn_fix_top_sm2_ex(SK.d, &skl);
	int k1l = ECC_BLOCK_LEN_DWORD;
	bn_fix_top_sm2_ex(k1.d, &k1l);

	memset(&r, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = D2SN->r[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(r.d, t, ECC_BLOCK_LEN);

	memset(&S2, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = D2SN->s2[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(S2.d, t, ECC_BLOCK_LEN);

	memset(&S3, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = D2SN->s3[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(S3.d, t, ECC_BLOCK_LEN);

	memset(&zwk_temp, 0, FLK_BIGNUM_SIZE);
	BN_mod_add_sm2_ex(zwk_temp.d, k1.d, S2.d, group->order.d, group->order_top);
	BN_mod_add_sm2_ex(zwk_temp.d, zwk_temp.d, S3.d, group->order.d, group->order_top);
#if 0
	//int ii = 0;
      //  for(ii =0 ; ii < sizeof(zwk_temp.d) /4 ; ++ii){
        //      if((zwk_temp.d[ii] - r.d[ii]) != 0u)
	//	{
	//		printf("ii = %d %x,%x\n",ii,zwk_temp.d[ii],r.d[ii]);
			//return -1;
	//	}
      //  }
#endif 	
	//if (memcmp(zwk_temp.d, r.d, sizeof(zwk_temp.d)) != 0)
	//{
	//	return -1;
	//}
	BN_mod_inverse_sm2_ex(temp.d, &temp_top, SK.d, group->order_top, group->order.d, group->order_top);

	BN_mul_sm2_ex(www, &S1S2_top, S3.d, temp_top, temp.d, temp_top);

	memset(number.d, 0, sizeof(FLKBIGNUM));
	number.d[0] = 0x1;
	BN_mod_sub_sm2_ex(www1.d, &S1S2sub1_top, www, number.d, group->field.d, group->field_top);
	if (S1S2sub1_top == 0)
	{
		return -1;
	}

	//将小端模式转换到大端模式，并输出私钥分量D
	memcpy(t, www1.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCSK.Ka[i] = t[ECC_BLOCK_LEN - 1 - i];
	}
	PrintBIGNUM("after temp key:", temp);
	PrintBIGNUM("after SK key:", SK);
	PrintBIGNUM("after S3 key:", S3);
	PrintBIGNUM("after www1 key:", www1);

	ECDSA_Signature_ex(&G_group, D2SN->s2, &stECCSK, &stECCSign);

	// S = (r,s)
	//将小端模式转换到大端模式，并输出公私钥
	ECC_ECCSignature_To_WOLFSSL_ex(&stECCSign, Signature);

	return 0;
}

int SM2_KeyComponent1Dec(const ECCrefPrivateKey *D1, ECCCipher *cip, TCipher *T1)
{
	FLKBIGNUM k;
	FLKBIGNUM x, y;
	EC_POINT R, Q;
	unsigned char t[ECC_BLOCK_LEN];
	int  point_on_curve_flag;
	ECC_PUBLIC_KEY QQ;
	int hg, i;
	ECC_ENCRYPTION 			stECCEnc;
	ECC_PRIVATE_KEY 		stECCSK;
	ECC_ECCEncryption_From_WOLFSSL_ex(&stECCEnc, cip);
	ECC_Private_From_WOLFSSL_ex(&stECCSK, D1);
	EC_GROUP *group = &G_group;
	ECC_ENCRYPTION *pEncryption = &stECCEnc;

	memset(&QQ, 0, sizeof(QQ));
	//初始化C1,判断该点是否在曲线上
	memcpy(&QQ.Qx, stECCEnc.C1, ECC_BLOCK_LEN);
	memcpy(&QQ.Qy, stECCEnc.C1 + ECC_BLOCK_LEN, ECC_BLOCK_LEN);

	point_on_curve_flag = POINT_is_on_curve_ex(&G_ECCPara, &QQ);
	if (point_on_curve_flag == 1) // 点C1在曲线上
	{
		//将小端模式转换到大端模式，并输出私钥分量D
		memset(&k, 0, FLK_BIGNUM_SIZE);
		for (i = 0; i < ECC_BLOCK_LEN; i++)
		{
			t[i] = stECCSK.Ka[ECC_BLOCK_LEN - 1 - i];
		}

		memcpy(k.d, t, ECC_BLOCK_LEN);

		FLKBIGNUM tmp;
		int len;
		// 计算D1 的逆
		BN_mod_inverse_sm2_ex(tmp.d, &len, k.d, group->order_top, group->order.d, group->order_top);
		//  初始化C1,判断该点是否在曲线上
		// 该在外围做判断
		unsigned char c1[64];
		memset(&Q, 0, sizeof(EC_POINT));
		memcpy(c1, pEncryption->C1, 2 * ECC_BLOCK_LEN);
		for (i = 0; i < ECC_BLOCK_LEN; i++)
		{
			t[i] = c1[31 - i];
		}
		memcpy(Q.X.d, t, ECC_BLOCK_LEN);

		for (i = 0; i < ECC_BLOCK_LEN; i++)
		{
			t[i] = c1[63 - i];
		}
		memcpy(Q.Y.d, t, ECC_BLOCK_LEN);

		BN_mod_mul_montgomery_sm2_ex(Q.X.d, Q.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
		BN_mod_mul_montgomery_sm2_ex(Q.Y.d, Q.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);

		memcpy(Q.Z.d, group->field_data2.d, group->field_top*FLK_BN_BYTES);
		Q.Z_is_one = 1;

		//(x1,y1)=d-1*C1
		EC_POINTs_mul_sm2_ex(group, &R, &Q, &tmp, NULL, NULL);
		ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);
		BN_mod_add_sm2_ex(x.d, tmp.d, y.d, group->order.d, group->order_top);

		//将小端模式转换到大端模式，并输出公钥
		ECC_PUBLIC_KEY 			stECCPK;
		ECCrefPublicKey 			pucPublicKey;
		memcpy(t, x.d, ECC_BLOCK_LEN);
		for (i = 0; i < ECC_BLOCK_LEN; i++)
		{
			stECCPK.Qx[i] = t[ECC_BLOCK_LEN - 1 - i];
		}

		memcpy(t, y.d, ECC_BLOCK_LEN);
		for (i = 0; i < ECC_BLOCK_LEN; i++)
		{
			stECCPK.Qy[i] = t[ECC_BLOCK_LEN - 1 - i];
		}
		ECC_Public_To_WOLFSSL_ex(&stECCPK, &pucPublicKey);
		memcpy(T1, &pucPublicKey, sizeof(ECCrefPublicKey));
		return ERR_SUCCESS;
	}
	return ERR_SM2_DECRYPT;
}

int SM2_KeyComponent2Dec(const ECCrefPrivateKey *D2, TCipher *T1Cip, TCipher *T2)
{
	ECC_PUBLIC_KEY 			stECCT1;
	ECC_PRIVATE_KEY 		stECCSK;
	EC_POINT T1, R;
	FLKBIGNUM x, y;
	FLKBIGNUM k, tmp;
	FLK_BN_ULONG tmp3[ECC_BLOCK_LEN_DWORD*2+1];
	int i;
	unsigned char t[ECC_BLOCK_LEN];
	EC_GROUP *group = &G_group;
	ECC_Private_From_WOLFSSL_ex(&stECCSK, D2);
	//初始化公钥 point Q
	ECC_Public_From_WOLFSSL_ex(&stECCT1, (ECCrefPublicKey*)T1Cip);
	memset(&T1, 0, sizeof(EC_POINT));
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCT1.Qx[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(T1.X.d, t, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCT1.Qy[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(T1.Y.d, t, ECC_BLOCK_LEN);

	int tmpl;
	memset(&tmp, 0x00, sizeof(FLKBIGNUM));
	BN_mod_sub_sm2_ex(tmp.d, &tmpl, T1.X.d, T1.Y.d, group->order.d, group->order_top);
	if (tmpl == 0)
	{
		return -1;
	}

	BN_mod_mul_montgomery_sm2_ex(T1.X.d, T1.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2_ex(T1.Y.d, T1.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	memcpy(T1.Z.d, group->field_data2.d, group->field_top*FLK_BN_BYTES);
	T1.Z_is_one = 1;

	//将小端模式转换到大端模式，并输出私钥分量D
	memset(&k, 0, FLK_BIGNUM_SIZE);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCSK.Ka[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(k.d, t, ECC_BLOCK_LEN);

	FLKBIGNUM tmp2;
	int len, tmp3l;
	// 计算D2 的逆
	BN_mod_inverse_sm2_ex(tmp2.d, &len, k.d, group->order_top, group->order.d, group->order_top);

	tmpl = ECC_BLOCK_LEN_DWORD;
	bn_fix_top_sm2_ex(tmp.d, &tmpl);
	int tmp2l = ECC_BLOCK_LEN_DWORD;
	bn_fix_top_sm2_ex(tmp2.d, &tmp2l);

	BN_mul_sm2_ex(tmp3, &tmp3l, tmp.d, tmpl, tmp2.d, tmp2l);

	EC_POINTs_mul_sm2_ex(group, &R, &T1, &tmp2, NULL, NULL);
	ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x, &y);
	BN_mod_add_sm2_ex(x.d, tmp3, y.d, group->order.d, group->order_top);

	//将小端模式转换到大端模式，并输出公钥
	ECC_PUBLIC_KEY 			stECCPK;
	ECCrefPublicKey 			pucPublicKey;
	memcpy(t, x.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCPK.Qx[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(t, y.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		stECCPK.Qy[i] = t[ECC_BLOCK_LEN - 1 - i];
	}
	ECC_Public_To_WOLFSSL_ex(&stECCPK, &pucPublicKey);
	memcpy(T2, &pucPublicKey, sizeof(ECCrefPublicKey));
	return ERR_SUCCESS;
}

int SM2_KeyComponent3Dec(ECCCipher *cip, TCipher *T2Cip, unsigned char *pucData, size_t *puiDataLength)
{
	int i;
	FLKBIGNUM x2, y2;
	EC_GROUP *group = &G_group;
	unsigned char t[ECC_BLOCK_LEN];
	//初始化公钥 point Q
	EC_POINT T2, R, C1, InverseC1, T2C1;
	ECC_PUBLIC_KEY 			stECCT2;
	ECC_ENCRYPTION 			stECCEnc;
	ECC_ECCEncryption_From_WOLFSSL_ex(&stECCEnc, cip);
	ECC_ENCRYPTION *pEncryption = &stECCEnc;
	ECC_Public_From_WOLFSSL_ex(&stECCT2, (ECCrefPublicKey*)T2Cip);
	memset(&T2, 0, sizeof(EC_POINT));
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCT2.Qx[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(T2.X.d, t, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = stECCT2.Qy[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(T2.Y.d, t, ECC_BLOCK_LEN);

	FLKBIGNUM tmp, tmp1, number;
	int tmpl, tmp1l;
	BN_mod_sub_sm2_ex(tmp.d, &tmpl, T2.X.d, T2.Y.d, group->order.d, group->order_top);
	if (tmpl == 0)
	{
		return ERR_SM2_DECRYPT;
	}

	memset(&number, 0, sizeof(FLKBIGNUM));
	memset(&tmp1, 0, sizeof(FLKBIGNUM));
	number.d[0] = 0x1;
	BN_mod_sub_sm2_ex(tmp1.d, &tmp1l, tmp.d, number.d, group->field.d, group->field_top);
	if (tmp1l == 0)
	{
		return ERR_SM2_DECRYPT;
	}

	BN_mod_mul_montgomery_sm2_ex(T2.X.d, T2.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	BN_mod_mul_montgomery_sm2_ex(T2.Y.d, T2.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	memcpy(T2.Z.d, group->field_data2.d, group->field_top*FLK_BN_BYTES);
	T2.Z_is_one = 1;

	// 该在外围做判断
	unsigned char c1[64];
	memset(&C1, 0, sizeof(EC_POINT));
	memcpy(c1, pEncryption->C1, 2 * ECC_BLOCK_LEN);
	unsigned char c2[ECC_MAX_ENCRYPT_LENGTH];
	unsigned char c3[32];
	int c2_len = pEncryption->len;

	memcpy(c1, pEncryption->C1, 2 * ECC_BLOCK_LEN);
	memcpy(c3, pEncryption->C3, ECC_BLOCK_LEN);
	memset(c2, 0, sizeof(c2));
	memcpy(c2, pEncryption->C2, c2_len);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = c1[31 - i];
	}
	memcpy(C1.X.d, t, ECC_BLOCK_LEN);

	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		t[i] = c1[63 - i];
	}
	memcpy(C1.Y.d, t, ECC_BLOCK_LEN);

	//PrintBIGNUM("before c1 C1.X.d", C1.X);
	BN_mod_mul_montgomery_sm2_ex(C1.X.d, C1.X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	//PrintBIGNUM("after c1 C1.X.d", C1.X);

	//PrintBIGNUM("before c1 C1.Y.d", C1.Y);
	BN_mod_mul_montgomery_sm2_ex(C1.Y.d, C1.Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	//PrintBIGNUM("after c1 C1.Y.d", C1.Y);

	memcpy(C1.Z.d, group->field_data2.d, group->field_top*FLK_BN_BYTES);
	//PrintBIGNUM("c1 C1.Z.d", C1.Z);
	C1.Z_is_one = 1;

	EC_POINTs_mul_sm2_ex(group, &R, &C1, &tmp1, NULL, NULL);
	ec_GFp_simple_point_get_affine_coordinates_GFp_ex(group, &R, &x2, &y2);

	//KDF的输入和X2,Y2的转化，是否要做x2,y2的数据颠倒。？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？
	// 本处做数据的颠倒
	unsigned char  *c2_kdf = (unsigned char *)malloc(pEncryption->len);
	unsigned char  *t_xor_m = (unsigned char *)malloc(pEncryption->len);
	unsigned char x2_y2[64];
	unsigned char x2in[ECC_BLOCK_LEN], y2in[ECC_BLOCK_LEN];
	unsigned char  *hash_in = (unsigned char *)malloc(32 + 32 + pEncryption->len);
	unsigned char u[32];//B5
	int char_equal = 0;// B5 判断u和C3是否相等
	memcpy(t, x2.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		x2in[i] = t[ECC_BLOCK_LEN - 1 - i];
	}
	memcpy(t, y2.d, ECC_BLOCK_LEN);
	for (i = 0; i < ECC_BLOCK_LEN; i++)
	{
		y2in[i] = t[ECC_BLOCK_LEN - 1 - i];
	}

	memcpy(x2_y2, x2in, 32);
	memcpy(x2_y2 + 32, y2in, 32);

	//B3 kdf
	KDF_ALGRITRHM_ex(x2_y2, 64, pEncryption->len, c2_kdf);

	for (i = 0; i < c2_len; i++)  // B4
	{
		t_xor_m[i] = c2[i] ^ c2_kdf[i];
	}

	//B5
	for (i = 0; i < 32; i++)
	{
		hash_in[i] = x2in[i];
	}

	for (i = 32; i < 32 + c2_len; i++)
	{
		hash_in[i] = t_xor_m[i - 32];
	}

	for (i = 32 + c2_len; i < 32 + c2_len + 32; i++)
	{
		hash_in[i] = y2in[i - 32 - c2_len];
	}

	algrithm_ex(hash_in, 32 + 32 + c2_len, 0, u);

	for (i = 0; i < 32; i++)
	{
		char_equal = char_equal + (unsigned int)(u[i] - c3[i]);
	}
	if (char_equal != 0)
	{
		free(c2_kdf);
		free(t_xor_m);
		free(hash_in);
		return ERR_SM2_DECRYPT;
	}
	*puiDataLength = c2_len;
	memcpy(pucData, t_xor_m, *puiDataLength);

	free(c2_kdf);
	free(t_xor_m);
	free(hash_in);
	return ERR_SUCCESS;
}

#endif

int SM2_GenerateKeyPair(ECCrefPublicKey *pucPublicKey,ECCrefPrivateKey *pucPrivateKey)
{
	ECC_PUBLIC_KEY 			stECCPK;    
	ECC_PRIVATE_KEY 		stECCSK;

    ECC_GenerateKeyPair_ex(&G_group, &stECCPK, &stECCSK);

    ECC_Private_To_WOLFSSL_ex(&stECCSK, pucPrivateKey);
    ECC_Public_To_WOLFSSL_ex(&stECCPK, pucPublicKey);

	return 0;
}

int SM2_Sign(int flag,const ECCrefPrivateKey *pucPrivateKey,const unsigned char *pucData,size_t uiDataLength,ECCSignature *pucSignature)
{
	ECC_PRIVATE_KEY 		stECCSK;
    ECC_SIGNATURE 			stECCSign;
    unsigned char 			hash[SM3_DIGEST_LENGTH];

    ECC_Private_From_WOLFSSL_ex(&stECCSK, pucPrivateKey);

    if(flag == ECC_SIGN_FLAG_ORIGINAL)
	{
		if(uiDataLength != SM3_DIGEST_LENGTH)
		{
            return ERR_SM2_SIGN_DATA;
		}
		memcpy(hash, pucData, uiDataLength);
	}
    else if(flag == ECC_SIGN_FLAG_HASH)
	{
		algrithm_ex(pucData, uiDataLength, 0, hash);
	}
	else
	{
        return ERR_SM2_SIGN_FLAG;
	}

    ECDSA_Signature_ex(&G_group, hash, &stECCSK, &stECCSign);
	
    ECC_ECCSignature_To_WOLFSSL_ex(&stECCSign, pucSignature);
	
	return 0;
}

int SM2_Verify(int flag,const ECCrefPublicKey *pucPublicKey,const unsigned char *pucDataInput,size_t uiInputLength,const ECCSignature *pucSignature)
{
	ECC_PUBLIC_KEY 		stECCPK;
    ECC_SIGNATURE 		stECCSign;
 	unsigned char 		hash[SM3_DIGEST_LENGTH];

    if(flag == ECC_SIGN_FLAG_ORIGINAL)
	{
		if(uiInputLength != SM3_DIGEST_LENGTH)
		{
            return ERR_SM2_SIGN_DATA;
		}
		memcpy(hash, pucDataInput, uiInputLength);
	}
    else if(flag == ECC_SIGN_FLAG_HASH)
	{
		algrithm_ex(pucDataInput, uiInputLength, 0, hash);
	}
	else
	{
        return ERR_SM2_SIGN_FLAG;
	}
    ECC_Public_From_WOLFSSL_ex(&stECCPK, pucPublicKey);
    ECC_ECCSignature_From_WOLFSSL_ex(&stECCSign, pucSignature);

    if(ECDSA_Verification_ex(&G_group,hash, &stECCPK, &stECCSign) == 0)
	{
		//printf("Signature failed!\n");
        return ERR_SM2_VERIRFY;
	}

    return ERR_SUCCESS;
}

int SM2_Encrypt(const ECCrefPublicKey *pucPublicKey,const unsigned char *pucData,size_t uiDataLength,ECCCipher *pucEncData)
{
	ECC_PUBLIC_KEY stECCPK;
    ECC_ENCRYPTION stECCEnc;	

	
    ECC_Public_From_WOLFSSL_ex(&stECCPK, pucPublicKey);
    if(POINT_is_on_curve_ex(&G_ECCPara,&stECCPK))
	{
        ECES_Encryption_ex(&G_group, pucData,uiDataLength, &stECCPK,&stECCEnc);
	}
	else
	{
        return ERR_SM2_KEY;
	}

    ECC_ECCEncryption_To_WOLFSSL_ex(&stECCEnc, pucEncData);
	return 0;
}

int SM2_Decrypt(const ECCrefPrivateKey *pucPrivateKey,const ECCCipher *pucEncData,unsigned char *pucData,size_t *puiDataLength)
{   
	int   point_on_curve_flag;
	ECC_PRIVATE_KEY stECCSK;
    ECC_ENCRYPTION stECCEnc;
    ECC_PUBLIC_KEY QQ;
	

	int hg;
	
    ECC_ECCEncryption_From_WOLFSSL_ex(&stECCEnc, pucEncData);
    ECC_Private_From_WOLFSSL_ex(&stECCSK, pucPrivateKey);

	memset(&QQ, 0, sizeof(QQ));
	//初始化C1,判断该点是否在曲线上
	memcpy(&QQ.Qx, stECCEnc.C1, ECC_BLOCK_LEN);
	memcpy(&QQ.Qy, stECCEnc.C1 + ECC_BLOCK_LEN, ECC_BLOCK_LEN);
	
    point_on_curve_flag = POINT_is_on_curve_ex(&G_ECCPara, &QQ);
	if(point_on_curve_flag==1) // 点C1在曲线上
	{
        hg = ECES_Decryption_ex(&G_group,&stECCEnc,stECCEnc.len, &stECCSK, pucData);
		if(hg != 1) // 解密 failed
		{
			//printf("hg = %d\n",hg);
            return ERR_SM2_DECRYPT;
		}
		*puiDataLength = stECCEnc.len;
	}

    return ERR_SUCCESS;
}

unsigned int BytePrecision_ex(unsigned int value)
{
	unsigned int i;
	for (i=sizeof(value); i; --i)
	{
		if (value >> (i-1)*8)
			break;
	}

	return i;
}
unsigned int DEREncodeString_ex(unsigned char *bt, const unsigned char *str, unsigned int strLen)
{
	unsigned int lengthBytes;
	//????2?Dèòa2100

	if(strLen == 0)
	{
		str--;
		strLen++;
	}

	*bt++ = 0x04;
	lengthBytes = DERLengthEncode_ex(bt, strLen);
	bt += lengthBytes;

	memcpy(bt, str, strLen);

	return 1+lengthBytes+strLen;
}

unsigned int DERLengthEncode_ex(unsigned char *bt, unsigned int length)
{
	unsigned int i = 0;
	int j;

	if (length <= 0x7f)
	{
		*bt++  = (unsigned char)length;
		i++;
	}
	else
	{
		*bt++ = (unsigned char)(BytePrecision_ex(length) | 0x80);
		i++;
		for ( j = BytePrecision_ex(length);  j; --j)
		{
			*bt++ = (unsigned char)(length >> (j-1)*8);
			i++;
		}
	}

	return i;
}

unsigned int DEREncodeInteger_ex(unsigned char *bt, const unsigned char *str, unsigned int strLen)
{
	unsigned int lengthBytes;
	unsigned int bfill = 1;  //????ê?·?Dèòa2100


	while(strLen > 0)
	{
		if(*str == 0)
		{
			str++;
			strLen--;
		}
		else
			break;
	}

	if(strLen == 0)
	{
		str--;
		strLen++;
	}

	if((*str & 0x80) == 0)
	{
		bfill = 0;
	}
	else
	{
		bfill = 1;
		strLen++;
	}


	*bt++ = 02;
	lengthBytes = DERLengthEncode_ex(bt, strLen);
	bt += lengthBytes;

	if(bfill == 1)
	{
		bt[0] = 0;
		memcpy(bt + 1, str, strLen);
	}
	else
	{
		memcpy(bt, str, strLen);
	}


	return 1+lengthBytes+strLen;
}

unsigned int DEREncodeSequence_ex(unsigned char *bt, const unsigned char *str, unsigned int strLen)
{
	unsigned int lengthBytes;

	*bt++ = 0x30;
	lengthBytes = DERLengthEncode_ex(bt, strLen);
	bt += lengthBytes;
	memcpy(bt, str, strLen);
	return 1+lengthBytes+strLen;
}

//公钥Der编码
int EncodePublicKey(const ECCrefPublicKey *pucPublicKey,unsigned char *pucData,size_t *uiDataLength)
{
	pucData[0] = 0x03;
	pucData[1] = 0x42;
	pucData[2] = 0x00;
	pucData[3] = 0x04;
    memcpy(pucData + 4, pucPublicKey->x + ECCref_ALIGNED_LEN, ECC_BLOCK_LEN);
    memcpy(pucData + 4 + ECC_BLOCK_LEN, pucPublicKey->y + ECCref_ALIGNED_LEN, ECC_BLOCK_LEN);
	*uiDataLength = 68;

	return 0;
}
//公钥Der解码
int DecodePublicKey(ECCrefPublicKey *pucPublicKey,const unsigned char *pucData,size_t uiDataLength)
{
	if(uiDataLength != 0x44 ||
		pucData[1] != 0x42)
	{
        return ERR_SM2_DER_LENGTH;
	}
	if(pucData[0] != 0x03 ||
		pucData[2] != 0x00 ||
		pucData[3] != 0x04)
	{
        return ERR_SM2_DER_DATA;
	}
    memset(pucPublicKey, 0, sizeof(ECCrefPublicKey));
	pucPublicKey->bits = 256;
    memcpy(pucPublicKey->x + ECCref_ALIGNED_LEN, pucData + 4, ECC_BLOCK_LEN);
    memcpy(pucPublicKey->y + ECCref_ALIGNED_LEN, pucData + 4 + ECC_BLOCK_LEN, ECC_BLOCK_LEN);

	return 0;
}
//加密数据Der编码
int EncodeECCCipher(const ECCCipher *pucEncData,unsigned char *pucData,size_t *uiDataLength)
{
    unsigned char		tmpData[ECC_MAX_ENCRYPT_LENGTH + 256];
	unsigned int		tmpDataLen = 0;

	//编码C1 的X值
    tmpDataLen = DEREncodeInteger_ex(tmpData, pucEncData->x + ECCref_ALIGNED_LEN, ECC_BLOCK_LEN);
	//编码C1 的y值
    tmpDataLen += DEREncodeInteger_ex(tmpData + tmpDataLen, pucEncData->y +ECCref_ALIGNED_LEN, ECC_BLOCK_LEN);

	//编码C3
	tmpDataLen += DEREncodeString_ex(tmpData + tmpDataLen, pucEncData->M, 32);
	//编码C2
	tmpDataLen += DEREncodeString_ex(tmpData + tmpDataLen, pucEncData->C, pucEncData->L);
	//编码头
	*uiDataLength = (size_t)DEREncodeSequence_ex(pucData, tmpData, tmpDataLen);
	
	return 0;
}
//加密数据Der解码
int DecodeECCCipher(ECCCipher *pucEncData,const unsigned char *pucData,size_t uiDataLength)
{
	unsigned int		i = 0;
	unsigned int		j = 0;
	unsigned short 		resultLen=0;

    memset(pucEncData, 0, sizeof(ECCCipher));

	//检查DER编码是否正确
	// 1,check Sequence 
	if(pucData[0] != 0x30)
	{
        return ERR_SM2_DER_DATA;
	}
	// 2,check der length and datalen
	if(pucData[1]  <= 0x7f)
	{
		if((unsigned int)(pucData[1] + 1 + 1) != uiDataLength)
		{
            return ERR_SM2_DER_LENGTH;
		}
		i = 2;
	}
	else
	{
		i = pucData[1] - 0x80;
		resultLen = 0;
		for(j = 0; j < i; j++)
		{
			resultLen = resultLen * 256 + pucData[2 + j];
		}
		if(resultLen + 1 + 1 + i != uiDataLength)
		{
            return ERR_SM2_DER_LENGTH;
		}
		i = i + 2;
	}

	// 2, check SM2 ENC cipher C1 x
	if(pucData[i++] != 0x02)
	{
        return ERR_SM2_DER_DATA;
	}
		
	if(pucData[i] == 0x20)
	{
		i++;
		if(pucData[i] < 0x80)
		{
            memcpy(pucEncData->x + ECCref_ALIGNED_LEN, pucData + i, 32);
			i += 32;
		}
		else
		{
            return ERR_SM2_DER_LENGTH;
		}
	}
	else if(pucData[i] == 0x21)
	{
		i++;
		if(pucData[i] == 0x00 &&
			pucData[i + 1] > 0x7F)
		{
            memcpy(pucEncData->x + ECCref_ALIGNED_LEN, pucData + i + 1, 32);
			i += 33;
		}
		else
		{
            return ERR_SM2_DER_DATA;
		}
	}
	else
	{
		//i++;
		//memcpy(pucEncData->x + 32 - pucData[i], pucData + i + 1, pucData[i]);
        memcpy(pucEncData->x + ECCref_ALIGNED_LEN + 32 - pucData[i], pucData + i + 1, pucData[i]);
		i += (pucData[i] + 1);
		//return -1;
	}

	// 2, check SM2 ENC cipher C1 y
	if(pucData[i++] != 0x02)
	{
        return ERR_SM2_DER_DATA;
	}
		
	if(pucData[i] == 0x20)
	{
		i++;
		if(pucData[i] < 0x80)
		{
            memcpy(pucEncData->y + ECCref_ALIGNED_LEN, pucData + i, 32);
			i += 32;
		}
		else
		{
            return ERR_SM2_DER_DATA;
		}
	}
	else if(pucData[i] == 0x21)
	{
		i++;
		if(pucData[i] == 0x00 &&
			pucData[i + 1] > 0x7F)
		{
            memcpy(pucEncData->y + ECCref_ALIGNED_LEN, pucData + i + 1, 32);
			i += 33;
		}
		else
		{
            return ERR_SM2_DER_DATA;
		}
	}
	else
	{
        memcpy(pucEncData->y + ECCref_ALIGNED_LEN + 32 - pucData[i], pucData + i + 1, pucData[i]);
		i += (pucData[i] + 1);
	}

	// 3, check SM2 ENC cipher C3 hash
	if(pucData[i++] != 0x04)
	{
        return ERR_SM2_DER_DATA;
	}
		
	if(pucData[i] == 0x20)
	{
		i++;
		memcpy(pucEncData->M, pucData + i, 32);
		i += 32;
	}
	else
	{
        return ERR_SM2_DER_LENGTH;
	}

	// 4, check SM2 ENC cipher C2 Cipher
	if(pucData[i++] != 0x04)
	{
        return ERR_SM2_DER_DATA;
	}
	if(pucData[i]  <= 0x7f)
	{
		pucEncData->L = pucData[i];
		i++;
	}
	else
	{
		resultLen = 0;
		for(j = 0; j < (unsigned int)(pucData[i] - 0x80); j++)
		{
			resultLen = resultLen * 256 + pucData[i + 1 + j];
		}
		pucEncData->L = resultLen;
		i += pucData[i] - 0x80 + 1;
	}

	memcpy(pucEncData->C, pucData + i, pucEncData->L);
		
	return 0;
}
//签名数据Der编码
int EncodeECCSignature(const ECCSignature *pucSignature,unsigned char *pucData,size_t *uiDataLength)
{
	int i = 0;

    if (((pucSignature->r[ECCref_ALIGNED_LEN]) & (0x80)) == 0x80)
	{
		pucData[3] = 0x21;
		pucData[4] = 0x00;
        memcpy(pucData + 5, pucSignature->r + ECCref_ALIGNED_LEN, 32);
		i= 5 + 32;
	}
	else 
	{
		pucData[3] = 0x20;
        memcpy(pucData + 4, pucSignature->r + ECCref_ALIGNED_LEN, 32);
		i= 4 + 32;
	}

    if (((pucSignature->s[ECCref_ALIGNED_LEN]) & (0x80)) == 0x80)
	{
		pucData[i] = 0x02;
		pucData[i+1] = 0x21;
		pucData[i+2] = 0x00;
        memcpy(pucData + i + 3, pucSignature->s + ECCref_ALIGNED_LEN, 32);
		i += 3 + 32;
	}
	else 
	{
		pucData[i] = 0x02;
		pucData[i+1] = 0x20;
        memcpy(pucData + i + 2, pucSignature->s + ECCref_ALIGNED_LEN, 32);
		i += 2 + 32;
	}

	pucData[0] = 0x30;
	pucData[1] = (unsigned char )(i - 2);
	pucData[2] = 0x02;
	*uiDataLength = i;

	return 0;
}
//签名数据Der解码
int DecodeECCSignature(ECCSignature *pucSignature,const unsigned char *pucData,size_t uiDataLength)
{
	unsigned int i = 0;
    memset(pucSignature, 0, sizeof(ECCSignature));
	
	if (pucData[0] != 0x30 || pucData[2] != 0x02)
	{
        return ERR_SM2_DER_DATA;
	}
	if (pucData[3] == 0x20)
	{
        memcpy(pucSignature->r + ECCref_ALIGNED_LEN, pucData + 4, 32);
		i = 4 + 32;
	}
	else if (pucData[3] == 0x21)
	{
        memcpy(pucSignature->r + ECCref_ALIGNED_LEN, pucData + 5, 32);
		i = 5 + 32;
	}
	else 
	{
        return ERR_SM2_DER_LENGTH;
	}

	if (pucData[i] != 0x02)
	{
        return ERR_SM2_DER_DATA;
	}
	if (pucData[i + 1] == 0x20)
	{
        memcpy(pucSignature->s + ECCref_ALIGNED_LEN, pucData + i + 2, 32);
		i += 2 + 32;
	}
	else if (pucData[i + 1] == 0x21)
	{
        memcpy(pucSignature->s + ECCref_ALIGNED_LEN, pucData + i + 3, 32);
		i += 3 + 32;
	}
	else
	{
        return ERR_SM2_DER_LENGTH;
	}

	if (pucData[1] != (i -2) || i != uiDataLength)
	{
        return ERR_SM2_DER_LENGTH;
	}

	return 0;
}

int SM2_Test(void)
{
	//test sm2 wolfssl
	int 							nRet = 0;
    ECCrefPublicKey 		pucPublicKey;
    ECCrefPrivateKey 		pucPrivateKey;
    ECCrefPublicKey 		pucPublicKeyDer;

    int 							flag = ECC_SIGN_FLAG_HASH;
    unsigned char 					pucSignData[ECC_MAX_ENCRYPT_LENGTH] = {0};
    size_t		 					uiSignDataLength = ECC_MAX_ENCRYPT_LENGTH;
    ECCSignature 			pucSignature;
    ECCSignature 			pucSignatureDer;

    unsigned char 					pucEncData[ECC_MAX_ENCRYPT_LENGTH] = {0};
    size_t		 					uiEncDataLength = ECC_MAX_ENCRYPT_LENGTH;
    ECCCipher 				pucCipher;
    ECCCipher 				pucCipherDer;

    unsigned char 					pucDecData[ECC_MAX_ENCRYPT_LENGTH] = {0};
	size_t		 					uiDecDataLength = 0;

	unsigned char 					encodeBuf[8192];
	size_t		 					encodeLen;

	int 							loop = 1;

    nRet = SM2_Init_ECCParameter();
	if(nRet)
	{
        printf("SM2_Init_ECCParameter Error\n");
		return nRet;
	}


	while(loop--)
	{
		
        nRet = SM2_GenerateKeyPair(&pucPublicKey,&pucPrivateKey);
		if(nRet)
		{
            printf("SM2_GenerateKeyPair Error\n");
			return nRet;
		}

        EncodePublicKey(&pucPublicKey, encodeBuf, &encodeLen);
        DecodePublicKey(&pucPublicKeyDer, encodeBuf, encodeLen);
		if(memcmp(&pucPublicKey, &pucPublicKeyDer, sizeof(pucPublicKey)) != 0)
		{
			printf("encode decode public error\n");
            return ERR_SM2_DER_DATA;
		}

		memset(pucSignData, '0', uiSignDataLength);
        nRet = SM2_Sign(flag,&pucPrivateKey,pucSignData,uiSignDataLength,&pucSignature);
		if(nRet)
		{
            printf("SM2_Sign Error\n");
			return nRet;
		}
        EncodeECCSignature(&pucSignature, encodeBuf, &encodeLen);
        DecodeECCSignature(&pucSignatureDer, encodeBuf, encodeLen);

		if(memcmp(&pucSignature, &pucSignatureDer, sizeof(pucSignatureDer)) != 0)
		{
			printf("encode decode signature error\n");
            return ERR_SM2_DER_DATA;
		}

        nRet = SM2_Verify(flag,&pucPublicKey,pucSignData,uiSignDataLength,&pucSignature);
		if(nRet)
		{
            printf("SM2_Verify Error\n");
			return nRet;
		}

		memset(pucEncData, '1', uiEncDataLength);
        nRet = SM2_Encrypt(&pucPublicKey,pucEncData,uiEncDataLength,&pucCipher);
		if(nRet)
		{
            printf("SM2_Encrytp Error\n");
			return nRet;
		}

        EncodeECCCipher(&pucCipher, encodeBuf, (size_t*)&encodeLen);
        DecodeECCCipher(&pucCipherDer, encodeBuf, encodeLen);
		

		if(memcmp(&pucCipher, &pucCipherDer, sizeof(pucCipher)) != 0)
		{
			printf("encode decode cipher error\n");
            return ERR_SM2_DER_DATA;
		}

        nRet = SM2_Decrypt(&pucPrivateKey,&pucCipher,pucDecData,&uiDecDataLength);
		if(nRet)
		{
            printf("SM2_Decrypt Error\n");
			return nRet;
		}
		
		if(uiEncDataLength != uiDecDataLength ||
			memcmp(pucDecData, pucEncData, uiDecDataLength) != 0)
		{
            printf("SM2_Decrypt Data Error\n");
			return 1;
		}

		printf("test sm2 loop = %d\n", loop);
	}
	return 0;
}

void SM2_Sm3Hash(const unsigned char *data, size_t datalen,
                        const unsigned char *userid, size_t useridlen,
                        ECCrefPublicKey *pubkey,
                        unsigned char *digest)
{
	unsigned char 	data1[8192]={0};
    unsigned int    data1_len = 0;  
    unsigned char 	hash[32] = {0};
    unsigned short tmplen = 0;
    
    if (pubkey == NULL && userid == NULL && useridlen == 0)
    {
 
        sm3(data, datalen, digest);
    }
    else if (pubkey != NULL && userid != NULL && useridlen != 0)
    {
        tmplen = htons((unsigned short)(useridlen * 8));
        //*((unsigned short *)data1) = htons((unsigned short)(useridlen * 8));
        memcpy(data1, &tmplen, sizeof(tmplen));
        data1_len = 2;
        memcpy(data1 + 2, userid, useridlen);
        data1_len += useridlen;
        //系数a
		memcpy(data1 + 2 + useridlen, "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC", 32);
        data1_len += 32;
        //系数b
        memcpy(data1 + 2 + useridlen+ 32, "\x28\xE9\xFA\x9E\x9D\x9F\x5E\x34\x4D\x5A\x9E\x4B\xCF\x65\x09\xA7\xF3\x97\x89\xF5\x15\xAB\x8F\x92\xDD\xBC\xBD\x41\x4D\x94\x0E\x93", 32);
        data1_len += 32;
        //Xg
        memcpy(data1 + 2 + useridlen + 32 + 32, "\x32\xC4\xAE\x2C\x1F\x19\x81\x19\x5F\x99\x04\x46\x6A\x39\xC9\x94\x8F\xE3\x0B\xBF\xF2\x66\x0B\xE1\x71\x5A\x45\x89\x33\x4C\x74\xC7", 32);
        data1_len += 32;
        //Yg
        memcpy(data1 + 2 + useridlen + 32 + 32 + 32, "\xBC\x37\x36\xA2\xF4\xF6\x77\x9C\x59\xBD\xCE\xE3\x6B\x69\x21\x53\xD0\xA9\x87\x7C\xC6\x2A\x47\x40\x02\xDF\x32\xE5\x21\x39\xF0\xA0", 32);
        data1_len += 32;
        //X
        memcpy(data1 + 2 + useridlen + 32 + 32 + 32 + 32, pubkey->x + 32, 32);
        data1_len += 32;
		//Y
		memcpy(data1 + 2 + useridlen + 32 + 32 + 32 + 32 + 32, pubkey->y + 32, 32);
        data1_len += 32;

        //保存SM3 杂凑值
        sm3(data1,data1_len, hash);

        //取得杂凑值e
        memcpy(data1, hash, 32);
        data1_len = 32;
        memcpy(data1 + 32, data, datalen);
        data1_len += datalen;

        sm3(data1,data1_len, digest);
        return ;
    }
}

SM2_DLL void SM2_Sm3HashGall(const unsigned char *userid, size_t useridlen, ECCrefPublicKey *pubkey, unsigned char *digest)
{
	unsigned char 	data1[4096] = { 0 };
	unsigned int    data1_len = 0;
	unsigned short tmplen = 0;

	if (pubkey == NULL && userid == NULL && useridlen == 0)
	{
		return;
	}
	else if (pubkey != NULL && userid != NULL && useridlen != 0)
	{
		tmplen = htons((unsigned short)(useridlen * 8));
		//*((unsigned short *)data1) = htons((unsigned short)(useridlen * 8));
		memcpy(data1, &tmplen, sizeof(tmplen));
		data1_len = 2;
		memcpy(data1 + 2, userid, useridlen);
		data1_len += useridlen;
		//系数a
		memcpy(data1 + 2 + useridlen, "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC", 32);
		data1_len += 32;
		//系数b
		memcpy(data1 + 2 + useridlen + 32, "\x28\xE9\xFA\x9E\x9D\x9F\x5E\x34\x4D\x5A\x9E\x4B\xCF\x65\x09\xA7\xF3\x97\x89\xF5\x15\xAB\x8F\x92\xDD\xBC\xBD\x41\x4D\x94\x0E\x93", 32);
		data1_len += 32;
		//Xg
		memcpy(data1 + 2 + useridlen + 32 + 32, "\x32\xC4\xAE\x2C\x1F\x19\x81\x19\x5F\x99\x04\x46\x6A\x39\xC9\x94\x8F\xE3\x0B\xBF\xF2\x66\x0B\xE1\x71\x5A\x45\x89\x33\x4C\x74\xC7", 32);
		data1_len += 32;
		//Yg
		memcpy(data1 + 2 + useridlen + 32 + 32 + 32, "\xBC\x37\x36\xA2\xF4\xF6\x77\x9C\x59\xBD\xCE\xE3\x6B\x69\x21\x53\xD0\xA9\x87\x7C\xC6\x2A\x47\x40\x02\xDF\x32\xE5\x21\x39\xF0\xA0", 32);
		data1_len += 32;
		//X
		memcpy(data1 + 2 + useridlen + 32 + 32 + 32 + 32, pubkey->x + 32, 32);
		data1_len += 32;
		//Y
		memcpy(data1 + 2 + useridlen + 32 + 32 + 32 + 32 + 32, pubkey->y + 32, 32);
		data1_len += 32;

		//保存SM3 杂凑值
		sm3(data1, data1_len, digest);
		return;
	}
}
#endif
