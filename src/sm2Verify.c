#include <stdio.h>
#include "sm2.h"
#include "sm3.h"

int fileHash_sm3(const char *path, unsigned char output[32] )
{
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

	return( 0 );
}

int byteToHex(unsigned char* indata,int inLen,char* outdata,int outLen)
{
    int i;
    if(outLen < inLen*2)
        return -1;
    
    for(i=0;i<inLen;++i)
    {
        sprintf(outdata+i*2,"%02x",indata[i]);
    }

    return 0;
}

int hexCharToByte(char ch)
{
    if(ch >= '0' && ch <= '9')
    {
        return ch - '0';
    }
    if(ch >= 'A' && ch <='F') 
    {
        return ch - 'A' + 10;
    }
    if(ch >= 'a' && ch <= 'f')
    {
        return ch - 'a' + 10;
    }
    return -1;
}

int HexToByte(char* indata,int inLen, unsigned char* outdata,int outLen)
{
    int i;
    if(outLen<inLen/2)
    {
        return -1;
    }

    for(i=0;i<outLen;i++)
    {
        int temp;
        temp = hexCharToByte(*(indata+2*i));
        outdata[i]=temp;
        temp = hexCharToByte(*(indata+2*i+1));
        outdata[i] = outdata[i]*16+temp;
    }
    return 0;
}


int main(int argc,char** argv)
{
    const int hashLen = 32;
    char hashCode[hashLen];
    
    memset(hashCode,0,hashLen);

    char path[4096];
    char verifyfile[4096] ="signCode.file";
    char pubkeyfile[4096] = "publicKey.store";

    int pathFlag=0;
    int verifyFlag =0;
    int keyFlag =0;
    
    for(int i=1;i<argc;++i)
    {
        if(strcmp(argv[i],"--filepath")==0&&(i+1)<argc)
	{
		strcpy(path,argv[i+1]);
		pathFlag=1;
	}

	if(strcmp(argv[i],"--verifyfile")==0&&(i+1)<argc)
	{
		strcpy(verifyfile,argv[i+1]);
		verifyFlag =1;
    }
   

    if(strcmp(argv[i],"--keyfile")==0&&(i+1)<argc)
    {
        strcpy(pubkeyfile,argv[i+1]);
        keyFlag = 1;
    }
  }

    if(pathFlag==0)
    {
       printf("error:not input filepath\n");
       exit(1);
    }
  
    if(verifyFlag==0)
    {
	    printf("default verifyfile is ./%s\n",verifyfile);
    }

    if(keyFlag==0)
    {
        printf("default key file is ./%s\n",pubkeyfile);
    }

   

    int ret = fileHash_sm3(path,hashCode);
    if(ret ==1)
    {
	printf("file %s open error\n",path);
	exit(1);
    }
    
    if(ret ==2)
    {
	printf("file %s read error\n",path);
	exit(2);
    }
    
   
//    printf("input verify code:\n");
//    scanf("%s",verifyCode);
    ECCrefPublicKey pucPublicKey;
    ECCSignature pucSignature;
    int publicKeySize = sizeof(ECCrefPublicKey);
    int signatureSize = sizeof(ECCSignature);
    
    SM2_Init_ECCParameter();

    FILE * pubf = fopen(pubkeyfile,"rb");
    if(pubf==NULL)
    {
        printf("public keyfile %s open error\n",pubkeyfile);
        exit(1);
    }
    int nbytes = fread((char *)&pucPublicKey,1,publicKeySize,pubf);
    if(nbytes!=publicKeySize)
    {
        printf("key file read error,check key file\n");
        fclose(pubf);
        exit(1);
    }
    fclose(pubf);

    char* signatureBuffer = malloc(signatureSize);
    char* signatureValidBuffer = malloc(signatureSize/2);
    
    if(signatureBuffer==NULL || signatureValidBuffer == NULL)
    {
        printf("memory  malloc error\n");
        exit(1);
    }
    FILE* signf = fopen(verifyfile,"r");
    if(signf ==NULL)
    {
       printf("open  verifyfile %s error\n",verifyfile);
       fclose(signf);
       exit(2);
    }
    fread(signatureBuffer,1,signatureSize,signf);
    fclose(signf);
    HexToByte(signatureBuffer,signatureSize,signatureValidBuffer,signatureSize/2);

    char * pSign = (char *)&pucSignature;
    memcpy(pSign+32,signatureValidBuffer,32);
    memcpy(pSign+64+32,signatureValidBuffer+32,32);
    ret = SM2_Verify(ECC_SIGN_FLAG_ORIGINAL,&pucPublicKey,hashCode,hashLen,&pucSignature);
    if(ret==0){
        printf("verify success\n");
    }
    else{
        printf("verify failed  \n");
    }

    free(signatureValidBuffer);
    free(signatureBuffer);

    return 0;
}
