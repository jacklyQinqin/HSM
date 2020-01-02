#ifndef __HSM_LOGIC_LEVEL_H__
#define __HSM_LOGIC_LEVEL_H__

/*
 * Logic level instruction
 *
 * Copyright (c) 2007  MontaVista Software, Inc.
 * Author：qinxd
 * Data:   2019/10/25
 * Company:Beijing Iste
 * 
 * logic  
 * 
 */



/*
 *
 *
 *
 */
 /*宏定义部分*/
//验签结果
#define VERIFY_SUCCESS       0X00
#define VERIFY_FAIL          0X01

//数据错误类型定义
#define ERROR_CRC            0X04
#define ERROR_XOR	         0X05


//验签模式定义
#define VERIFY_MODE_SIGNLECORE_WITHZ    		0X01 //单核带预处理
#define VERIFY_MODE_SIGNLECORE_WITHOUTZ 		0X02 //单核不带预处理
#define VERIFY_MODE_SIGNLECORE_POINT    		0X03 //待定


#define VERIFY_MODE_MULCORE_WITHZ   		 	0X11 //多核带预处理
#define VERIFY_MODE_MULCORE_WITHOUTZ 			0X12 //多核不带预处理
#define VERIFY_MODE_MULCORE_POINT    			0X13 //点压缩模式待定
#define VERIFY_MODE_MULCORE_WITHZ_PUBKEY    	0X14 //多条验签带预处理即时公钥
#define VERIFY_MODE_MULCORE_WITHOUTZ_PUBKEY    	0X15 //多条验签不带预处理即时公钥

//指令发送状态
//send task status.
typedef enum 
{
	HSM_SEND_OK = 0X00,   //发送成功
	HSM_SEND_BUSY = 0X01, //忙状态，未使用
	HSM_SEND_FAIL = 0X03  //发送失败
}hsm_send_status;


//接受计算结果状态
//rec task status
typedef enum 
{
	HSM_REC_OK = 0X00, //接受成功
	HSM_REC_BUSY = 0X01, //忙状态，未定义
	HSM_REC_FAIL = 0X03 //接受失败
}hsm_receive_status;


//模块初始化状态
typedef enum
{
	HSM_INIT_SUCCESS = 0x00, //初始化成功
	HSM_INIT_FAIL = 0x01	
}hsm_init_status;

//关闭模块状态
typedef enum
{
	HSM_DEINIT_SUCCESS = 0x00, //成功
	HSM_DEINIT_FAIL = 0x01	
}hsm_deinit_status;


//模块的计算状态
typedef enum
{
	HSM_CHIP_IDLE = 0x00,//空闲
	HSM_CHIP_BUSY = 0x01 //忙
}hsm_busy_status;


//验签指令结构体。
//带预处理验签使用。
typedef struct 
{
	unsigned int len;     //验签数据长度
	unsigned char *message;//验签数据:公钥+message
	unsigned char *publickey;
}message_struct;

//send command 发送类指令



/*
 * hsm_send_import_publickey
 * 发送导入公钥指令
 * 传入参数：
 * 1.64字节公钥的指针
 * 返回参数:
 * HSM_SEND_OK  	发送成功
 * HSM_SEND_BUSY    模块忙状态，不接受数据
 * HSM_SEND_FAIL    发送失败
 * 说明:
 * 指令在函数内部完成组包，用户只需要传入公钥指针。
 */
hsm_send_status hsm_send_import_publickey(const char * publickey);


/*
 * hsm_send_export_publickey
 * 发送导出公钥指令
 * 传入参数：
 * 参数1.指针分组索引。目前支持0.
 * 返回参数:
 * HSM_SEND_OK  	发送成功
 * HSM_SEND_BUSY    模块忙状态，不接受数据
 * HSM_SEND_FAIL    发送失败
 * 说明:
 * 指令在函数内部完成组包，用户只需要传入分组index即可。
 */
hsm_send_status hsm_send_export_publickey(unsigned char index);

hsm_send_status hsm_send_import_privatekey(const char * privatekey);
hsm_send_status hsm_send_singlecore_verify(const char * message, char mode,long message_len,unsigned char key_index);

hsm_send_status hsm_send_multiplecore_verify(message_struct * p_message_struct , char mode, int package,int key_index);
hsm_send_status hsm_send_sign_verify(char mode);


//receive result.
hsm_receive_status hsm_receive_result(unsigned char *result,unsigned len);

//get chip busy /ready status
hsm_busy_status hsm_get_status(void);

//module reset
hsm_busy_status hsm_reset(void);

//module init
hsm_init_status hsm_init(unsigned long speed);

//modlue deinit
hsm_deinit_status hsm_deinit(void);


#endif
