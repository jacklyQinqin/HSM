#include "hsm_hardware_level.h"
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


//hardware init.
//spi init
//and handshake init.
int fd;
int  mode;
char bits = 8;

uint32_t speed = 5000000;
static uint16_t delay = 40;
static int verbose;


unsigned char  hsm_hardware_init(unsigned long in_speed)
{
	int ret = 0;
	speed = in_speed;
	printf("hsm_hardware_init and the speed is %ld \n",in_speed);
	fd = open(SPI_DEV_NAME, O_RDWR);
	if (fd < 0)
		printf("can't open device");
	/*
	 * spi mode
	 */
	ret = ioctl(fd, SPI_IOC_WR_MODE32, &mode);
	if (ret == -1)
		printf("can't set spi mode");

	ret = ioctl(fd, SPI_IOC_RD_MODE32, &mode);
	if (ret == -1)
		printf("can't get spi mode");

	/*
	 * bits per word
	 */
	ret = ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
	if (ret == -1)
		printf("can't set bits per word");

	ret = ioctl(fd, SPI_IOC_RD_BITS_PER_WORD, &bits);
	if (ret == -1)
		printf("can't get bits per word");

	/*
	 * max speed hz
	 */
	ret = ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &in_speed);
	if (ret == -1)
		printf("can't set max speed hz");

	ret = ioctl(fd, SPI_IOC_RD_MAX_SPEED_HZ, &in_speed);
	if (ret == -1)
		printf("can't get max speed hz");

	//初始化handshake
	
	return 0;
}


unsigned char  hsm_hardware_deinit(void)
{
	close(fd);
	
	return 0;
}



unsigned char  transfer(int fd, uint8_t const *tx, uint8_t const *rx, int len)
{
	int ret;
	struct spi_ioc_transfer tr = {
		.tx_buf = (unsigned long)tx,
		.rx_buf = (unsigned long)rx,
		.len = len,
		.delay_usecs = delay,
		.speed_hz = speed,
		.bits_per_word = bits,
	};

	if (mode & SPI_TX_QUAD)
		tr.tx_nbits = 4;
	else if (mode & SPI_TX_DUAL)
		tr.tx_nbits = 2;
	if (mode & SPI_RX_QUAD)
		tr.rx_nbits = 4;
	else if (mode & SPI_RX_DUAL)
		tr.rx_nbits = 2;
	if (!(mode & SPI_LOOP)) {
		if (mode & (SPI_TX_QUAD | SPI_TX_DUAL))
			tr.rx_buf = 0;
		else if (mode & (SPI_RX_QUAD | SPI_RX_DUAL))
			tr.tx_buf = 0;
	}

	ret = ioctl(fd, SPI_IOC_MESSAGE(1), &tr);
	if (ret < 1)
	{
		printf("can't send spi message");		
		return ret;
	}
	return 0;
	//hex_dump(rx, len, 32, "RX");
}


