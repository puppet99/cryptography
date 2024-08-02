#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdint.h>


typedef struct {
    void (*schedule) (void *context);
	void (*encrypt) (void *context, const uint8_t *data, size_t len);
	void (*final) (void *context, uint8_t *hash);
	size_t context_size;
	size_t block_size;
}block_algorithm;

#endif