#include "interface.h"

void pkcs7_pad(uint8_t *data, int block_size, int data_size) {
    int padding = block_size - (data_size % block_size);
    for (int i = data_size; i < data_size + padding; i++) {
        data[i] = padding;
    }
}

uint8_t pkcs7_unpad(uint8_t *data, int block_size) {
    int padding = data[block_size - 1];
    return block_size - padding;
}
