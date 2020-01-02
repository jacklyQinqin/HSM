#ifndef __HSM_HARDWARE_LEVEL__
#define __HSM_HARDWARE_LEVEL__
#include <stdint.h>
#include <stdlib.h>
/*
 * Logic level instruction
 *
 * Copyright (c) 2007  MontaVista Software, Inc.
 * Author：qinxd
 * Data:   2019/10/25
 * Company:Beijing Iste
 * 
 * hardware recall back.
 * 
 *
 * 
 */

//hardware init.

extern int fd;
extern int mode;
extern char bits;

#define SPI_DEV_NAME  "/dev/spidev32766.0"

unsigned char  hsm_hardware_init(unsigned long speed);
unsigned char  hsm_hardware_deinit(void);
unsigned char transfer(int fd, uint8_t const *tx, uint8_t const *rx, int len);



//hsm module send data.

#endif
