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


void display(char * str,int len)
{
    for(int i=0;i<len;++i)
        printf("%02x",str[i]);
    printf("\n");
}

#if 1
int main(int argc,char ** argv)
{

    /*init part*/
    const int hashLen = 32;
    char hashCode[hashLen];
    memset(hashCode,0,hashLen);

    char path[4096];
    char keyfile[4096]="privateKey.store";
    int pathFlag = 0;
    int keyFlag = 0;
    for(int i=1;i<argc;++i)
    {
       if(strcmp(argv[i],"--filepath")==0 && (i+1)<argc)
       {
	       strcpy(path,argv[i+1]);
	       pathFlag = 1;	
       }

       if(strcmp(argv[i],"--keyfile")==0 && (i+1)<argc)
       {
           strcpy(keyfile,argv[i+1]);
           keyFlag = 1;
       }

    }
    
    if(pathFlag==0)
    {
      printf("error not input filepath\n");
      exit(1);
    }

    if(keyFlag==0)
    {
        printf("default keyfile path is ./%s\n",keyfile);
        
    }

    int ret = fileHash_sm3(path,hashCode);
    if(ret ==1)
    {
        printf("file open error\n");
  	    exit(1);
    }

    if(ret ==2)
    {
	    printf("file read error\n");
        exit(1);
    }

    ECCrefPrivateKey pucPrivateKey;
    ECCSignature     pucSignature;
    int privateKeySize = sizeof(ECCrefPrivateKey);
    int signatureSize = sizeof(ECCSignature);

    SM2_Init_ECCParameter();

   
    FILE * prif = fopen(keyfile,"rb");
    if(prif==NULL)
    {
        printf("key file open error\n");
        exit(1);
    }
    int nReadBytes = fread((char*)&pucPrivateKey,1,privateKeySize,prif);
    if(nReadBytes!=privateKeySize)
    {
        printf("key file read error,check key file\n");
        fclose(prif);
        exit(1);
    }
    fclose(prif);

    SM2_Sign(ECC_SIGN_FLAG_ORIGINAL,&pucPrivateKey,hashCode,hashLen,&pucSignature);

    char * signBuffer =NULL;
    char * signValidBuffer = NULL;
    signBuffer= malloc(2*signatureSize);
    signValidBuffer = malloc(signatureSize);
    if(signBuffer==NULL|| signValidBuffer==NULL)
    {
        printf("memory alloc error\n");
        exit(1);
    }
    byteToHex((char *)&pucSignature,signatureSize,signBuffer,2*signatureSize);

    memcpy(signValidBuffer,signBuffer+64,64);
    memcpy(signValidBuffer+64,signBuffer+128+64,64);

    FILE* signf = fopen("signCode.file","w");
    if(signf ==NULL)
    {
       printf("saved sign code to file error\n");
       exit(2);
    }

    fwrite(signValidBuffer,1,signatureSize,signf);
    
    fclose(signf);
    

    free(signBuffer);
    free(signValidBuffer);
    printf("saved sign code to file signCode.file\n");
    return 0;
}
#endif
