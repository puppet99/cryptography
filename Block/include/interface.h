#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdint.h>


void pkcs7_pad(uint8_t *data, int block_size, int data_size);
int pkcs7_unpad(uint8_t *data, int block_size);


#endif