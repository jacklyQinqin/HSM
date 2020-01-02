#include <stdio.h>
#include <string.h>
#include "hsm_logic_level.h"
#include "hsm_hardware_level.h"

#define CMD_LEN  12
#define PUBKEY_LEN 64
#define CMD_PACKAGE 4


unsigned char SM2PublicKey[76] = 
{
    0xbf,0x01,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0x00,0x00,0x01,\
    0X09,0XF9,0XDF,0X31,0X1E,0X54,0X21,0XA1,0X50,0XDD,0X7D,0X16,0X1E,0X4B,0XC5,0XC6,    \
    0X72,0X17,0X9F,0XAD,0X18,0X33,0XFC,0X07,0X6B,0XB0,0X8F,0XF3,0X56,0XF3,0X50,0X20,    \
    0XCC,0XEA,0X49,0X0C,0XE2,0X67,0X75,0XA5,0X2D,0XC6,0XEA,0X71,0X8C,0XC1,0XAA,0X60,   \
    0X0A,0XED,0X05,0XFB,0XF3,0X5E,0X08,0X4A,0X66,0X32,0XF6,0X07,0X2D,0XA9,0XAD,0X13
};
//export publickey
unsigned char SM2ExportPublickey[12] = 
	{0XBF,0X06,0X00,0X00,0X00,0X00,0X00,0x0c,0x00,0x00,0x00,0x00};

unsigned char Temp_R1[32] = 
{
		0XA6,0XA5,0X87,0XC8,0X7E,0X03,0XC6,0XA6,0X49,0XE6,0X45,0XB3,0XA3,0X21,0XE9,0X60,
		0XA8,0X62,0X49,0X59,0XF2,0XFB,0X13,0X69,0X4C,0X00,0XEF,0XBF,0X78,0X95,0XD3,0X57
};
unsigned char Temp_S1[32] = 
{
	  0XE4,0XF9,0XD7,0XE4,0X7A,0X98,0XD2,0X8E,0X62,0X2D,0X70,0X01,0XBD,0XB3,0X35,0XC6,
		0X01,0X48,0X98,0X12,0X14,0X6C,0XC8,0X9D,0X44,0X2C,0XC4,0X6A,0X6A,0XFE,0X01,0XFA
};   


unsigned char SM2SignCmd[116]= {0xbf,0x03,0x00,0x00,0x00,0x00,0x00,0x4c,\
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x64,
    0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,\
    0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,\
    0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,\
    0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,\
    0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,\
    0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,\
    0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,\
    0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,\
    0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,\
    0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011,0x11,0x011
};

//signcore verify with Z.
//the len is const. 12(CMD) + 00 00 + LEN + LEN + R+ S + MESSAGE
unsigned char SM2VerifyCmd[12]= {0xbf,0x04,0x00,0x00,0x00,0x00,0x00,0xB4,0X00,0X00,0X00,0X01};

//signcore verify not Z.
//the len is const. 12(CMD) + 64(R+S) + 32(E)
unsigned char SM2VerifyCmd_1[108]= 
{0xbf,0x19,0x00,0x00,0x00,0x00,0x00,0x6c, 0x00,0x00,0x00,0x01,
0X90,0XCB,0X78,0XBD,0XEA,0X56,0X5A,0XC3,0X3D,0X91,
0X83,0XE4,0X15,0XE6,0X4A,0XEB,0X2D,0X37,0XED,0XCB,
0X9A,0X9A,0X65,0X6D,0XCA,0XD0,0XEC,0XC7,0XA4,0X62,
0XD1,0XB4,0XC8,0XB7,0X67,0XEC,0X93,0X6F,0XDD,0XDC,
0X3B,0X13,0X33,0XF5,0X40,0X24,0X10,0XD4,0X36,0X4C,
0XAA,0X77,0XC3,0X16,0X55,0XD1,0XA5,0XDE,0XE3,0XB5,
0XF9,0XF5,0X12,0X5F,

0X76,0XFF,0XFD,0X3C,0XB2,0XB8,0X2D,0X03,0XC0,0X0C,
0XDB,0XBC,0X3D,0X6F,0X59,0X75,0X2D,0X17,0X9B,0X1A,
0XB2,0XC6,0X13,0X0A,0XF9,0X4C,0X11,0X0F,0XE9,0XC6,
0X00,0X99
};


//多核验签带预处理不带即时公钥
unsigned char SM2VerifyCmd_mul_core_without_z[12]= {0xbf,0x23,0x00,0x00,0x00,0x00,0x07,0xec,
0x00,0x00,0x00,0x01};
//多核不带预处理不带即时公钥
unsigned char SM2VerifyCmd_mul_core_with_z[12]= {0xbf,0x22,0x00,0x00,0x00,0x00,0x07,0xec,
0x00,0x00,0x00,0x01};

//多核验签带预处理带即时公钥
unsigned char SM2VerifyCmd_mul_core_with_z_publickey[12]= {0xbf,0x26,0x00,0x00,0x00,0x00,0x07,0xec,
0x00,0x00,0x00,0x00};
//多核验签不带预处理带即时公钥
unsigned char SM2VerifyCmd_mul_core_without_z_publickey[12]= {0xbf,0x28,0x00,0x00,0x00,0x00,0x07,0xec,
0x00,0x00,0x00,0x00};

static unsigned char chip_send_reveive_status = 0;

unsigned char *tx;
unsigned char *rx;
unsigned char dump[8000];
static unsigned char tx_buff[8000];



static void hex_dump(const void *src, size_t length, size_t line_size, char *prefix)
{
	int i = 0;
	const unsigned char *address = src;
	const unsigned char *line = address;
	unsigned char c;

	printf("%s | ", prefix);
	while (length-- > 0) {
		printf("%02X ", *address++);
		if (!(++i % line_size) || (length == 0 && i % line_size)) {
			if (length == 0) {
				while (i++ % line_size)
					printf("__ ");
			}
			printf(" | ");  /* right close */
			while (line < address) {
				c = *line++;
				printf("%c", (c < 33 || c == 255) ? 0x2E : c);
			}
			printf("\n");
			if (length > 0)
				printf("%s | ", prefix);
		}
	}
}



//get moudle send or receive status.
unsigned char hsm_get_send_receive_status(void)
{
	printf("hsm_get_send_receive_status!\n");
	
	return chip_send_reveive_status;
}


//send command 
//import public key. 64 byte.
hsm_send_status hsm_send_import_publickey(const char * publickey)
{
	printf("hsm_send_import_publickey!\n");
	tx = SM2PublicKey;
	rx = dump;
	memcpy(SM2PublicKey+CMD_LEN,publickey,64);
	if(0==transfer(fd, tx, rx, sizeof(SM2PublicKey)))
		return HSM_SEND_OK;

	else
		return HSM_SEND_FAIL;
}

hsm_send_status hsm_send_export_publickey(unsigned char index)
{
	printf("hsm_send_export_publickey!\n");
	tx = SM2ExportPublickey;
	rx = dump;
	if(0==transfer(fd, tx, rx, sizeof(SM2ExportPublickey)))
		return HSM_SEND_OK;

	else
		return HSM_SEND_FAIL;
}




hsm_send_status hsm_send_import_privatekey(const char * privatekey)
{
	printf("hsm_send_import_privatekey!\n");

	return HSM_SEND_OK;

}



hsm_send_status hsm_send_singlecore_verify(const char * message, char mode,long message_len,unsigned char key_index)
{

	//单核带Z
	if(VERIFY_MODE_SIGNLECORE_WITHZ == mode)
	{
		memcpy(tx_buff,SM2VerifyCmd,CMD_LEN);
		memcpy(tx_buff+16,message,message_len);
		
		tx_buff[11] = key_index;

		//计算Message_HIGH和Message_Low
		tx_buff[12] = 00;
		tx_buff[13] = 00;
		tx_buff[14] = (message_len-64)/256;
		tx_buff[15] = (message_len-64)%256;

		//计算LEN_H 和 LEN_LOW
		message_len+=16;
		tx_buff[6] = (message_len) / 256;
		tx_buff[7] = (message_len) % 256;
		
		tx = tx_buff;
		rx = dump;
		//hex_dump(tx_buff, 180, 18, "TX");
		if(0==transfer(fd, tx, rx,message_len))
			return HSM_SEND_OK;

		else
			return HSM_SEND_FAIL;
	}
	else if(VERIFY_MODE_SIGNLECORE_WITHOUTZ == mode) //单核不带Z
	{
		tx = SM2VerifyCmd_1;
		rx = dump;
		memcpy(SM2VerifyCmd_1+CMD_LEN,message,96);
		if(0==transfer(fd, tx, rx, sizeof(SM2PublicKey)))
			return HSM_SEND_OK;

		else
			return HSM_SEND_FAIL;
	}
	else
	{
		return HSM_SEND_FAIL;
	}
	
}



//2.1多核验签不带预处理
static hsm_send_status function_1(message_struct * p_message_struct ,char mode, int package,int key_index)
{
	long len  = 0;
	long i  = 0;

	if(VERIFY_MODE_MULCORE_WITHOUTZ == mode) //多核不带预处理
	{
	    len =  package * 96 + CMD_LEN;
		memcpy(tx_buff,SM2VerifyCmd_mul_core_with_z,CMD_LEN);
		tx_buff[11] = key_index;
		tx_buff[6] = len/256;
		tx_buff[7] = len%256;
		//printf(" the len is %d\n",len);
		//printf(" the index is %d\n",key_index);
		//printf(" the package is %d\n",package);
		for(i=0;i<package;i++)
		{
			memcpy((tx_buff+i*96+12),p_message_struct[i].message ,p_message_struct[i].len);
		}
		//hex_dump(tx_buff, len, 16, "TX");
		tx = tx_buff;
		rx = dump;
		
		if(0==transfer(fd, tx, rx,len))
			return HSM_SEND_OK;

		else
			return HSM_SEND_FAIL;
	}
}

//2.2多核验签带预处理
static hsm_send_status function_2(message_struct * p_message_struct ,char mode, int package,int key_index)
{
	
	long len  = 0;
	long i  = 0;
	//多核带预处理
	if(VERIFY_MODE_MULCORE_WITHZ == mode)
	{
		memset(tx_buff,0x00,sizeof(tx_buff));
		memcpy(tx_buff,SM2VerifyCmd_mul_core_without_z,CMD_LEN);
		tx_buff[11] = key_index;
		tx_buff[6] = package/256;
		tx_buff[7] = package%256;
		//printf(" the len is %d\n",len);
		//printf(" the index is %d\n",key_index);
		//printf(" the package is %d\n",package);
		len  = 12;
		for(i=0;i<package;i++)
		{	
			tx_buff[len]  = 0x00;
			tx_buff[len+1]  = 0x00;
			tx_buff[len+2]  = (p_message_struct[i].len+4)/256;
			tx_buff[len+3]  = (p_message_struct[i].len+4)%256;			
			memcpy((tx_buff+len+4),p_message_struct[i].message ,p_message_struct[i].len);

			len += p_message_struct[i].len + 4;
			len = len + len % 4;
			
		}
		//hex_dump(tx_buff, len, 16, "TX");
		tx = tx_buff;
		rx = dump;
		
		if(0==transfer(fd, tx, rx,len))
			return HSM_SEND_OK;

		else
			return HSM_SEND_FAIL;
	}
}

//2.3多核验签不做预处理带即时公钥
static hsm_send_status function_3(message_struct * p_message_struct ,char mode, int package,int key_index)
{	
	long len  = 0;
	long i	= 0;

	if(VERIFY_MODE_MULCORE_WITHOUTZ_PUBKEY == mode)
	{
		len =  package * 160 + CMD_LEN;
		memcpy(tx_buff,SM2VerifyCmd_mul_core_without_z_publickey,CMD_LEN);
		tx_buff[11] = key_index;
		tx_buff[6] = len/256;
		tx_buff[7] = len%256;
		//printf(" the len is %d\n",len);
		//printf(" the index is %d\n",key_index);
		//printf(" the package is %d\n",package);
		for(i=0;i<package;i++)
		{
			memcpy((tx_buff+i*160+12),p_message_struct[i].publickey,64);
			memcpy((tx_buff+i*160+12+64),p_message_struct[i].message ,p_message_struct[i].len);
		}
		//hex_dump(tx_buff, len, 16, "TX");
		tx = tx_buff;
		rx = dump;
		
		if(0==transfer(fd, tx, rx,len))
			return HSM_SEND_OK;

		else
			return HSM_SEND_FAIL;
	}

}

//2.4多核验签带预处理带即时公钥
static hsm_send_status function_4(message_struct * p_message_struct ,char mode, int package,int key_index)
{
	long len  = 0;
	long i  = 0;
	if(VERIFY_MODE_MULCORE_WITHZ_PUBKEY == mode)
	{
		memset(tx_buff,0x00,sizeof(tx_buff));
		memcpy(tx_buff,SM2VerifyCmd_mul_core_with_z_publickey,CMD_LEN);
		tx_buff[11] = key_index;
		tx_buff[6] = package/256;
		tx_buff[7] = package%256;
		
		//hex_dump(tx_buff, 12, 16, "RX");
		
		//printf(" the index is %d\n",key_index);
		//printf(" the package is %d\n",package);
		len  = 12;
		
		for(i=0;i<package;i++)
		{	
			tx_buff[len]  = 0x00;
			tx_buff[len+1]  = 0x00;
			tx_buff[len+2]  = (p_message_struct[i].len+64+4)/256;
			tx_buff[len+3]  = (p_message_struct[i].len+64+4)%256;
			//hex_dump(p_message_struct[i].publickey, 64, 16, "PUBLICKEY");
			memcpy(tx_buff+len+4,p_message_struct[i].publickey,64);
			memcpy((tx_buff+len+68),p_message_struct[i].message ,p_message_struct[i].len);
			len += p_message_struct[i].len + PUBKEY_LEN + CMD_PACKAGE;
			len = len + len % 4;
		}

		//printf("the len is %d\n",len);
		tx = tx_buff;
		rx = dump;
		
		if(0==transfer(fd, tx, rx,len))
			return HSM_SEND_OK;

		else
			return HSM_SEND_FAIL;

	}
}
hsm_send_status hsm_send_multiplecore_verify(message_struct * p_message_struct ,char mode, int package,int key_index)
{

	long len  = 0;
	long i  = 0;
	//多核带预处理
	if(VERIFY_MODE_MULCORE_WITHZ == mode)
	{
		return function_2(p_message_struct,mode,package,key_index);

	}
	else if(VERIFY_MODE_MULCORE_WITHOUTZ == mode) //多核不带预处理
	{
	    return function_1(p_message_struct,mode,package,key_index);
	}
	else if(VERIFY_MODE_MULCORE_WITHZ_PUBKEY == mode)//多核验签带预处理-即时公钥
	{
		return function_4(p_message_struct,mode,package,key_index);
	}
	else if(VERIFY_MODE_MULCORE_WITHOUTZ_PUBKEY == mode)//多核验签不带预处理-即时公钥
	{
		return function_3(p_message_struct,mode,package,key_index);
	}
	else
	{
		return HSM_SEND_FAIL;
	}

}

hsm_send_status hsm_send_sign_verify(char mode)
{
	printf("hsm_send_sign_verify!\n");
	return HSM_SEND_OK;

}


//receive result.
hsm_receive_status hsm_receive_result(unsigned char *result,unsigned len)
{
	rx = result;
	tx = dump;
	if(0 == transfer(fd, tx, rx, len))
		return HSM_REC_OK;
	else
		return HSM_REC_FAIL;
}


//获取模块的状态。
hsm_busy_status hsm_get_status(void)
{
	printf("hsm_chip_status!\n");
	return  HSM_CHIP_IDLE;

}


//module reset
hsm_busy_status hsm_reset(void)
{

	printf("hsm_reset!\n");
	return  HSM_CHIP_IDLE;

}

//module init
hsm_init_status hsm_init(unsigned long speed)
{

	printf("hsm_init!\n");
	if(hsm_hardware_init(speed))
		return  HSM_CHIP_IDLE;
	
	else
		return  HSM_CHIP_BUSY;
}


hsm_deinit_status hsm_deinit(void)
{

	printf("hsm_deinit!\n");
	if(0 == hsm_hardware_deinit())
		return  HSM_DEINIT_SUCCESS;
	
	else
		return  HSM_DEINIT_FAIL;
}


