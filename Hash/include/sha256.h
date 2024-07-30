
#ifndef SHA256_H
#define SHA256_H

#include "interface.h"

// SHA-256 结构体
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} sha256_context;

extern const hash_algorithm sha256_algorithm;

#endif //SHA256_H