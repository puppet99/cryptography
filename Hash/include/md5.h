#ifndef MD5_H
#define MD5_H

#include "interface.h"

// MD5 结构体
typedef struct {
    uint32_t state[4];
    uint64_t count;
    uint8_t buffer[64];
} md5_context;

extern const hash_algorithm md5_algorithm;

#endif //MD5_H