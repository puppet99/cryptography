
#ifndef SHA1_H
#define SHA1_H

#include "interface.h"

// SHA-1 结构体
typedef struct {
    uint32_t state[5];
    uint64_t count; //表示处理的总比特数。
    uint8_t buffer[64]; //64字节的缓冲区，用于存储数据块
} sha1_context;

extern const hash_algorithm sha1_algorithm;

#endif //SHA1_H