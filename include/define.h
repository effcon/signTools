#ifndef FLK_DEFINE_H
#define FLK_DEFINE_H

enum request_type
{
	request_pub_key = 0,
	request_sync_sign,
	request_check_server,
	request_prove_client1,
	request_prove_client2,
	request_sync_decrypt,
	request_sync_delete,			//协同删除，客户端所对应的公私钥对
	request_server_code,
	request_kms_key

};

typedef unsigned char byte;
typedef unsigned char BYTE;

#define MAX_SERVER_ADDR_LEN 128

/* Standard, good-to-have defines */
#ifndef NULL
#define NULL (void*)0
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define FLK_SUCCESS								0
// 接口错误码 (-1 ~ -100)
#define FLK_ERR_IMP_BEGIN						-1
#define FLK_ERR_PARAM_INPUT_INVAILD				FLK_ERR_IMP_BEGIN	//入参非法
#define FLK_ERR_NOT_IMPLEMENTED					FLK_ERR_IMP_BEGIN-1 //接口未实现
#define FLK_ERR_IMP_END							-100	

//socket 通信 错误码(-101~-200)
#define FLK_ERR_COMMUNICATE_BEGIN				-100
#define FLK_ERR_SERVERADDR_ISTOOLONG			FLK_ERR_COMMUNICATE_BEGIN -1 //服务器地址过长max 128
#define FLK_ERR_CONNECT_SERVER_ERROR			FLK_ERR_COMMUNICATE_BEGIN -2 //连接服务器失败
#define FLK_ERR_SENDBUF_ERROR					FLK_ERR_COMMUNICATE_BEGIN -3 //发送数据失败
#define FLK_ERR_RECVBUF_ERROR					FLK_ERR_COMMUNICATE_BEGIN -4 //接受数据失败
#define FLK_ERR_COMMUNICATE_END					-200 

//业务逻辑错误码（-201 ~-300）
#define FLK_ERR_BUSSINESS_BEGIN					-200
#define FLK_ERR_UNINIT_SERVER					FLK_ERR_BUSSINESS_BEGIN -1	 //未设置协同签名服务器
#define FLK_ERR_NO_PUBKEY_VAILD					FLK_ERR_BUSSINESS_BEGIN -2	 //没有可用pubkey
#define FLK_ERR_GENERATE_KEY_FAILED				FLK_ERR_BUSSINESS_BEGIN -3	 //生成非对称密钥失败
#define FLK_ERR_PASER_FORMAT_ERROR				FLK_ERR_BUSSINESS_BEGIN -4	 //Json格式出错
#define FLK_ERR_SERVER_SUPOURT_LCS_FULL			FLK_ERR_BUSSINESS_BEGIN -5	 //服务器设备数达到license上限，请充值
#define FLK_ERR_SERVER_NOT_MATCH_DEVICE			FLK_ERR_BUSSINESS_BEGIN -6	 //服务器设备数未找到匹配该设备的密钥
#define FLK_ERR_LICENSE_LIB_SIZE_INVAILD		FLK_ERR_BUSSINESS_BEGIN -7	 //license库大小不符合
#define FLK_ERR_LICENSE_AUTH_FAILED				FLK_ERR_BUSSINESS_BEGIN -8	 //license库哈希验证失败
#define FLK_ERR_MUTUAL_AUTH_SERVER				FLK_ERR_BUSSINESS_BEGIN -9	 //双向验证-验证服务器失败
#define FLK_ERR_MUTUAL_AUTH_CLIENT				FLK_ERR_BUSSINESS_BEGIN -10	 //双向验证-验证客户端失败
#define FLK_ERR_COMPOSE_JSON_ERROR				FLK_ERR_BUSSINESS_BEGIN -11	 //Json格式出错
#define FLK_ERR_ENC_MAX_SM2_ENCLEN				FLK_ERR_BUSSINESS_BEGIN -12	 //sm2 加密上限目前136
#define FLK_ERR_ENC_SM2_CIPHER_BUF_ISTOOSHORT	FLK_ERR_BUSSINESS_BEGIN -13	 //sm2 加密 密文buf过小
#define FLK_ERR_ENC_SM2_PLAIN_BUF_ISTOOSHORT	FLK_ERR_BUSSINESS_BEGIN -14	 //sm2 解密 原文buf过小
#define FLK_ERR_ENC_SM2_ASYN_STEP1_FAILED		FLK_ERR_BUSSINESS_BEGIN -15	 //sm2 协同解密 第一次失败
#define FLK_ERR_ENC_NOT_MUTUAL_CHECK			FLK_ERR_BUSSINESS_BEGIN -16	 //sm2 未通过双向验证 无权限操作
#define FLK_ERR_ENC_NO_PRIVATE_KEY_PART			FLK_ERR_BUSSINESS_BEGIN -17	 //同步删除失败，客户端本地没有私钥分量

#define FLK_ERR_BUSSINESS_END					-300 


//基础函数错误码（-301 ~-400）
#define FLK_ERR_BASIC_FUNCTION_BEGIN			-300
#define FLK_ERR_MALLOC_ERROR					FLK_ERR_BASIC_FUNCTION_BEGIN -1	// malloc失败
#define FLK_ERR_OPEN_FILE_ERROR					FLK_ERR_BASIC_FUNCTION_BEGIN -2	 //打开文件失败
#define FLK_ERR_BASIC_FUNCTION_END				-400

//算法错误码（-401 ~-400）
#define FLK_ERR_SM2_SIGN_FLAG					FLK_ERR_BASIC_FUNCTION_BEGIN -1
#define FLK_ERR_SM2_SIGN_DATA					FLK_ERR_BASIC_FUNCTION_BEGIN -2
#define FLK_ERR_SM2_VERIRFY						FLK_ERR_BASIC_FUNCTION_BEGIN -3
#define FLK_ERR_SM2_KEY							FLK_ERR_BASIC_FUNCTION_BEGIN -4
#define FLK_ERR_SM2_DECRYPT						FLK_ERR_BASIC_FUNCTION_BEGIN -5
#define FLK_ERR_SM2_DER_LENGTH					FLK_ERR_BASIC_FUNCTION_BEGIN -6
#define FLK_ERR_SM2_DER_DATA					FLK_ERR_BASIC_FUNCTION_BEGIN -7
#define FLK_ERR_SM3WITHSM2_HASH					FLK_ERR_BASIC_FUNCTION_BEGIN -8


//配置文件读取错误码（-401 ~-400）
#define FLK_ERR_SETTINGS_RW_BEGIN				-500
#define FLK_ERR_SETTINGS_READFILE_ERROR			FLK_ERR_SETTINGS_RW_BEGIN -1
#define FLK_ERR_SETTINGS_RW_END					-600

/*get key error code*/
#define FLK_ERR_GETKEY_BEGIN                 			 -700
#define FLK_ERR_GETKEY_ROOTCERT_NOT_FOUND           FLK_ERR_GETKEY_BEGIN - 1 
#define FLK_ERR_GETKEY_SERVERCERT_NOT_FOUND        FLK_ERR_GETKEY_BEGIN - 2
#define FLK_ERR_GETKEY_CERT_IS_INVALID                  	   FLK_ERR_GETKEY_BEGIN - 3

typedef struct server_info_t
{
	char server_addr[MAX_SERVER_ADDR_LEN];
	int port;
}server_info_s;

#define SERVERCODE_LEN 11

#endif//FLK_DEFINE_H
