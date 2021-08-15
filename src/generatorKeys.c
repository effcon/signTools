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




int main()
{
    ECCrefPublicKey pucPublicKey;
    ECCrefPrivateKey pucPrivateKey;
    int publicKeySize = sizeof(ECCrefPublicKey);
    int privateKeySize = sizeof(ECCrefPrivateKey);

    
    SM2_Init_ECCParameter();
    SM2_GenerateKeyPair(&pucPublicKey,&pucPrivateKey);
    


    FILE * pubf = fopen("publicKey.store","wb");
    if(pubf==NULL)
    {
        printf("file open error\n");
        exit(1);
    }
    fwrite((char *)&pucPublicKey,1,publicKeySize,pubf);
    fclose(pubf);

    FILE * prif = fopen("privateKey.store","wb");
    if(prif==NULL)
    {
        printf("file open error\n");
        exit(1);
    }
    fwrite((char*)&pucPrivateKey,1,privateKeySize,prif);
    fclose(prif);

    return 0;

}

