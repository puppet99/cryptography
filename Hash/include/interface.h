
#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdint.h>

typedef struct {
    void (*init) (void *context);
	void (*update) (void *context, const uint8_t *data, size_t len);
	void (*final) (void *context, uint8_t *hash);
	size_t context_size;
	size_t hash_size;
}hash_algorithm;

#endif // INTERFACE_H