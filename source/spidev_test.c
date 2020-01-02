#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>

#include "hsm_logic_level.h"
#include <sys/time.h>



#define  SPI_SPEED_01M 1000000
#define  SPI_SPEED_10M 10000000
#define  SPI_SPEED_15M 15000000
#define  SPI_SPEED_18M 18000000
#define  SPI_SPEED_20M 20000000
#define  SPI_SPEED_22M 22000000
#define  SPI_SPEED_25M 25000000






#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static void pabort(const char *s)
{
	perror(s);
	abort();
}

//单条验签数据R+S+预处理后的E值。不带预处理的数据
unsigned char singlecore_verify_message[96]= 
{
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


//带预处理验签的数据 R+S+MESSAGE
unsigned char singlecore_verify_message2[]= 
{
	0X6C,0X8D,0X41,0X6B,0XF1,0XCE,0X64,0X1D,0X91,0X32,
	0XF6,0X0E,0X34,0XD1,0XCA,0XE2,0XC8,0X2D,0X69,0X4A,
	0XE9,0X02,0X7C,0XC7,0X12,0X58,0XFA,0X1A,0X72,0XE9,
	0X42,0X80,0X4F,0XF4,0XD3,0XCB,0X3A,0XB2,0X4A,0X58,
	0X0E,0XAB,0X36,0XE2,0X77,0XC8,0XA8,0X4E,0X96,0XEF,
	0X29,0XCF,0XA6,0X73,0XAC,0X30,0X68,0X5B,0X9D,0X71,
	0X2A,0X11,0X3A,0XA5,
		
	0X55,0X55,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,
	0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,
	0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,
	0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,
	0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,
	0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,
	0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,
	0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,
	0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,
	0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X11,0X22,0X22,
};


unsigned char PublicKey[64] = 
{
    0X09,0XF9,0XDF,0X31,0X1E,0X54,0X21,0XA1,0X50,0XDD,0X7D,0X16,0X1E,0X4B,0XC5,0XC6,    \
    0X72,0X17,0X9F,0XAD,0X18,0X33,0XFC,0X07,0X6B,0XB0,0X8F,0XF3,0X56,0XF3,0X50,0X20,    \
    0XCC,0XEA,0X49,0X0C,0XE2,0X67,0X75,0XA5,0X2D,0XC6,0XEA,0X71,0X8C,0XC1,0XAA,0X60,   \
    0X0A,0XED,0X05,0XFB,0XF3,0X5E,0X08,0X4A,0X66,0X32,0XF6,0X07,0X2D,0XA9,0XAD,0X13
};


static const char *device = "/dev/spidev32766.0";


extern char bits;
extern int mode;
extern int fd;



unsigned char rx_buff[100];
unsigned char tx_buff[100];
uint8_t default_tx[] = {

	0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
};

char *input_tx;

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


static void print_usage(void)
{
	puts(
	     "  ISTECC IS32U512B SM2 HS MODULE TEST EXAMPLE\n"
	     "  AUTHOR: QINXD \n"
	     "  VERSION: 0.0.3 \n");
}



void signlecore_verify_test(unsigned long time)
{
	int i = 0;
	int delta = 0;
	struct timeval tv;
	struct timeval tv2;
    

	printf("verify without z speed\n");
    gettimeofday(&tv,NULL);
	for(i=0;i<time;i++)
	{
		if(HSM_SEND_OK == hsm_send_singlecore_verify(singlecore_verify_message,VERIFY_MODE_SIGNLECORE_WITHOUTZ,sizeof(singlecore_verify_message),0))	
			;
		else
			printf("HSM_SEND_FAIL\n");
		usleep(540);
		if(HSM_REC_OK == hsm_receive_result(rx_buff,4))
		{
			if(rx_buff[0] == 0x90)
			{
				;
			}
			else
			{
				printf("verify fail\n");
				return;
			}	
		}
		else
		{
			printf("HSM_REC_FAIL\n");
			
		}
	}
	gettimeofday(&tv2,NULL);
	printf("microsecond:%ld\n",tv.tv_sec*1000000 + tv.tv_usec);  //微秒
	
	//printf("second:%ld\n",tv2.tv_sec);  //秒
    //printf("millisecond:%ld\n",tv2.tv_sec*1000 + tv2.tv_usec/1000);  //毫秒
    printf("microsecond:%ld\n",tv2.tv_sec*1000000 + tv2.tv_usec);  //微秒
	delta = (tv2.tv_sec*1000000 + tv2.tv_usec) - (tv.tv_sec*1000000 + tv.tv_usec);
	printf("microsecond interval:%ld\n",delta);  //微秒
    printf("average is  %f time/s \n",time/(delta/1000000.0));


	

	printf("verify with z speed\n");
	gettimeofday(&tv,NULL);
	for(i=0;i<time;i++)
	{
		if(HSM_SEND_OK == hsm_send_singlecore_verify(singlecore_verify_message2,VERIFY_MODE_SIGNLECORE_WITHZ,sizeof(singlecore_verify_message2),0))	
			;
		else
			printf("HSM_SEND_FAIL\n");
		usleep(540);
		if(HSM_REC_OK == hsm_receive_result(rx_buff,4))
		{
			if(rx_buff[0] == 0x90)
			{
				;
			}
			else
			{
				printf("verify fail\n");
				return;
			}	
		}
		else
		{
			printf("HSM_REC_FAIL\n");
			
		}
	}
	gettimeofday(&tv2,NULL);
	printf("microsecond:%ld\n",tv.tv_sec*1000000 + tv.tv_usec);  //微秒
	//printf("second:%ld\n",tv2.tv_sec);  //秒
	//printf("millisecond:%ld\n",tv2.tv_sec*1000 + tv2.tv_usec/1000);  //毫秒
	printf("microsecond:%ld\n",tv2.tv_sec*1000000 + tv2.tv_usec);  //微秒
	delta = (tv2.tv_sec*1000000 + tv2.tv_usec) - (tv.tv_sec*1000000 + tv.tv_usec);
	printf("microsecond interval:%ld\n",delta);  //微秒
	printf("average is	%f time/s \n",time/(delta/1000000.0));

	
}


#define TEST_PACKAGE_NUM 15

//多核验签的消息数据
message_struct mulcore_verify_message[TEST_PACKAGE_NUM] = 
{
	{0,NULL,NULL},
	{0,NULL,NULL},
	{0,NULL,NULL},
	{0,NULL,NULL},
	{0,NULL,NULL},
	{0,NULL,NULL},

};


//多核验签测试

void mulcore_verify_test(unsigned long time)
{
	int i = 0;
	int delta = 0;
	int compare_time = 0;
	struct timeval tv;
	struct timeval tv2;
	

	//初始化多条验签的数据不带预处理不带公钥
	for(i=0;i<TEST_PACKAGE_NUM;i++)
	{
		mulcore_verify_message[i].message = singlecore_verify_message;
		mulcore_verify_message[i].len = sizeof(singlecore_verify_message);
	}
	
	printf("mul core  verify without z speed\n");
	gettimeofday(&tv,NULL);
	for(i=0;i<time;i++)
	{
		if(HSM_SEND_OK == hsm_send_multiplecore_verify(mulcore_verify_message,VERIFY_MODE_MULCORE_WITHOUTZ,TEST_PACKAGE_NUM,0))
		{
			;
		}
		else
			printf("HSM_SEND_FAIL\n");
		//usleep(3450); //21包
		usleep(870*2.5+200); //6package
		if(HSM_REC_OK == hsm_receive_result(rx_buff,TEST_PACKAGE_NUM))
		{
			//hex_dump(rx_buff, TEST_PACKAGE_NUM, 16, "RX");
			for(compare_time=0;compare_time<TEST_PACKAGE_NUM;compare_time++)
			{
				if(rx_buff[0] == 0x90)
				{
					;
				}
				else
				{
					printf("verify fail\n");
					return;
				}
			}
		}
		else
		{
			printf("HSM_REC_FAIL\n");
			
		}
	}
	gettimeofday(&tv2,NULL);
	printf("microsecond:%ld\n",tv.tv_sec*1000000 + tv.tv_usec);  //微秒
	//printf("second:%ld\n",tv2.tv_sec);  //秒
	//printf("millisecond:%ld\n",tv2.tv_sec*1000 + tv2.tv_usec/1000);  //毫秒
	printf("microsecond:%ld\n",tv2.tv_sec*1000000 + tv2.tv_usec);  //微秒
	delta = (tv2.tv_sec*1000000 + tv2.tv_usec) - (tv.tv_sec*1000000 + tv.tv_usec);
	printf("microsecond interval:%ld\n",delta);  //微秒
	printf("average is	%f time/s \n",time*TEST_PACKAGE_NUM/(delta/1000000.0));


	//初始化多条验签的数据 带预处理不带公钥
	for(i=0;i<TEST_PACKAGE_NUM;i++)
	{
		mulcore_verify_message[i].message = singlecore_verify_message2;
		mulcore_verify_message[i].len = sizeof(singlecore_verify_message2);
	}

		printf("mul core  verify with z speed\n");
		gettimeofday(&tv,NULL);
		for(i=0;i<time;i++)
		{
			if(HSM_SEND_OK == hsm_send_multiplecore_verify(mulcore_verify_message,VERIFY_MODE_MULCORE_WITHZ,TEST_PACKAGE_NUM,0))
			{
				;
			}
			else
				printf("HSM_SEND_FAIL\n");
			//usleep(4450);//21package
			usleep(1215*2.5);//6package
			if(HSM_REC_OK == hsm_receive_result(rx_buff,TEST_PACKAGE_NUM))
			{
				//hex_dump(rx_buff, TEST_PACKAGE_NUM, 16, "RX");
				for(compare_time=0;compare_time<TEST_PACKAGE_NUM;compare_time++)
				{
					if(rx_buff[0] == 0x90)
					{
						;
					}
					else
					{
						printf("verify fail\n");
						return;
					}
				}

			}
			else
			{
				printf("HSM_REC_FAIL\n");
				
			}
		}
		gettimeofday(&tv2,NULL);
		printf("microsecond:%ld\n",tv.tv_sec*1000000 + tv.tv_usec);  //微秒
		
		//printf("second:%ld\n",tv2.tv_sec);  //秒
		//printf("millisecond:%ld\n",tv2.tv_sec*1000 + tv2.tv_usec/1000);  //毫秒
		printf("microsecond:%ld\n",tv2.tv_sec*1000000 + tv2.tv_usec);  //微秒
		delta = (tv2.tv_sec*1000000 + tv2.tv_usec) - (tv.tv_sec*1000000 + tv.tv_usec);
		printf("microsecond interval:%ld\n",delta);  //微秒
		printf("average is	%f time/s \n",time*TEST_PACKAGE_NUM/(delta/1000000.0));



	//初始化多条验签的数据不带预处理-即时公钥
	for(i=0;i<TEST_PACKAGE_NUM;i++)
	{
		mulcore_verify_message[i].message = singlecore_verify_message;
		mulcore_verify_message[i].len = sizeof(singlecore_verify_message);
		mulcore_verify_message[i].publickey = PublicKey;
	}
	printf("mul core  verify without z with public  speed \n");
	gettimeofday(&tv,NULL);
	for(i=0;i<time;i++)
	{
		if(HSM_SEND_OK == hsm_send_multiplecore_verify(mulcore_verify_message,VERIFY_MODE_MULCORE_WITHOUTZ_PUBKEY,TEST_PACKAGE_NUM,0))
		{
			;
		}
		else
			printf("HSM_SEND_FAIL\n");
		usleep(995*2.5);
		if(HSM_REC_OK == hsm_receive_result(rx_buff,TEST_PACKAGE_NUM))
		{
			//hex_dump(rx_buff, TEST_PACKAGE_NUM, 16, "RX");
			for(compare_time=0;compare_time<TEST_PACKAGE_NUM;compare_time++)
			{
				if(rx_buff[0] == 0x90)
				{
					;
				}
				else
				{
					printf("verify fail\n");
					return;
				}
			}
		}
		else
		{
			printf("HSM_REC_FAIL\n");
			
		}
	}
	gettimeofday(&tv2,NULL);
	printf("microsecond:%ld\n",tv.tv_sec*1000000 + tv.tv_usec);  //微秒
	//printf("second:%ld\n",tv2.tv_sec);  //秒
	//printf("millisecond:%ld\n",tv2.tv_sec*1000 + tv2.tv_usec/1000);  //毫秒
	printf("microsecond:%ld\n",tv2.tv_sec*1000000 + tv2.tv_usec);  //微秒
	delta = (tv2.tv_sec*1000000 + tv2.tv_usec) - (tv.tv_sec*1000000 + tv.tv_usec);
	printf("microsecond interval:%ld\n",delta);  //微秒
	printf("average is	%f time/s \n",time*TEST_PACKAGE_NUM/(delta/1000000.0));



	//初始化多条验签的数据 带预处理--即时公钥
	for(i=0;i<TEST_PACKAGE_NUM;i++)
	{
		mulcore_verify_message[i].message = singlecore_verify_message2;
		mulcore_verify_message[i].len = sizeof(singlecore_verify_message2);
		mulcore_verify_message[i].publickey = PublicKey;
	}
	printf("mul core  verify with z with  public  speed\n");
	gettimeofday(&tv,NULL);
	for(i=0;i<time;i++)
	{
		if(HSM_SEND_OK == hsm_send_multiplecore_verify(mulcore_verify_message,VERIFY_MODE_MULCORE_WITHZ_PUBKEY,TEST_PACKAGE_NUM,0))
		{
			;
		}
		else
			printf("HSM_SEND_FAIL\n");
		usleep(1660*2.5+200);
		if(HSM_REC_OK == hsm_receive_result(rx_buff,TEST_PACKAGE_NUM))
		{
			//hex_dump(rx_buff, TEST_PACKAGE_NUM, 16, "RX");
			for(compare_time=0;compare_time<TEST_PACKAGE_NUM;compare_time++)
			{
				if(rx_buff[0] == 0x90)
				{
					;
				}
				else
				{
					printf("verify fail\n");
					return;
				}
			}

		}
		else
		{
			printf("HSM_REC_FAIL\n");
			
		}
	}
	gettimeofday(&tv2,NULL);
	printf("microsecond:%ld\n",tv.tv_sec*1000000 + tv.tv_usec);  //微秒

	
	//printf("second:%ld\n",tv2.tv_sec);  //秒
	//printf("millisecond:%ld\n",tv2.tv_sec*1000 + tv2.tv_usec/1000);  //毫秒
	printf("microsecond:%ld\n",tv2.tv_sec*1000000 + tv2.tv_usec);  //微秒
	delta = (tv2.tv_sec*1000000 + tv2.tv_usec) - (tv.tv_sec*1000000 + tv.tv_usec);
	printf("microsecond interval:%ld\n",delta);  //微秒
	printf("average is	%f time/s \n",time*TEST_PACKAGE_NUM/(delta/1000000.0));

}



int main(int argc, char *argv[])
{
	int ret = 0;
	int time = 0;
	print_usage();
 	hsm_init(SPI_SPEED_15M);
	printf("spi mode: 0x%x\n", mode);
	printf("bits per word: %d\n", bits);
	for(time=0;time<1;time++)
	{	
		if(HSM_SEND_OK == hsm_send_import_publickey(PublicKey))	
			printf("HSM_SEND_OK\n");
		else
			printf("HSM_SEND_FAIL\n");
		
		usleep(2000);
		if(HSM_REC_OK == hsm_receive_result(rx_buff,4))
			printf("HSM_REC_OK\n");
		else
			printf("HSM_REC_FAIL\n");
		//hex_dump(rx_buff, 4, 1, "RX");
		
		if(HSM_SEND_OK == hsm_send_export_publickey(0))	
			;
		else
			printf("HSM_SEND_FAIL\n");
		
		usleep(2000);
		
		if(HSM_REC_OK == hsm_receive_result(rx_buff,66))
			//hex_dump(rx_buff, 66, 9, "RX");
			;
		else
			printf("HSM_REC_FAIL\n");
		
		//signlecore_verify_test(2000);
		mulcore_verify_test(200);
	}
	hsm_deinit();
	return 0;
}
