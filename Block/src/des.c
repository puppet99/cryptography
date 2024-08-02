#include "des.h"

void des_key_schedule(const uint8_t *key, uint8_t *round_keys){
	//实现密钥扩展
	uint8_t permuted_key[56];
    uint8_t C[28], D[28];

    // 初始置换
    for (int i = 0; i < 56; i++) {
        permuted_key[i] = key[PC1[i] - 1];
    }

    // 分割密钥
    memcpy(C, permuted_key, 28);
    memcpy(D, permuted_key + 28, 28);

    // 生成子密钥
    for (int i = 0; i < 16; i++) {
        // 左移
        for (int j = 0; j < shifts[i]; j++) {
            uint8_t tempC = C[0], tempD = D[0];
            memmove(C, C + 1, 27);
            memmove(D, D + 1, 27);
            C[27] = tempC;
            D[27] = tempD;
        }

        // 压缩置换
        for (int j = 0; j < 48; j++) {
            round_keys[i * 48 + j] = (j < 24) ? C[PC2[j] - 1] : D[PC2[j] - 1];
        }
    }
}

// F函数
uint32_t f(uint32_t R, const uint8_t *round_key) {
    uint8_t expanded_R[48];
    uint8_t S_output[32];
    uint32_t output = 0;

    // 扩展置换
    for (int i = 0; i < 48; i++) {
        expanded_R[i] = (R >> (32 - E[i])) & 1;
    }

    // S盒替换
    for (int i = 0; i < 8; i++) {
        uint8_t row = (expanded_R[i * 6] << 1) | expanded_R[i * 6 + 5];
        uint8_t col = (expanded_R[i * 6 + 1] << 3) | (expanded_R[i * 6 + 2] << 2) | (expanded_R[i * 6 + 3] << 1) | expanded_R[i * 6 + 4];
        uint8_t S_value = S[i][row * 16 + col];
        for (int j = 0; j < 4; j++) {
            S_output[i * 4 + j] = (S_value >> (3 - j)) & 1;
        }
    }

    // P置换
    for (int i = 0; i < 32; i++) {
        output |= S_output[P[i] - 1] << (31 - i);
    }

    return output;
}


void des_encrypt_block(const uint8_t *in, uint8_t *out, const uint8_t *round_keys) {
    // 实现块加密
	uint32_t L = 0, R = 0;

    // 初始置换
    for (int i = 0; i < 64; i++) {
        if (i < 32) {
            L |= ((in[IP[i] - 1] >> (7 - (i % 8))) & 1) << (31 - i);
        } else {
            R |= ((in[IP[i] - 1] >> (7 - (i % 8))) & 1) << (63 - i);
        }
    }

    // 16轮加密
    for (int i = 0; i < 16; i++) {
        uint32_t temp = R;
        R = L ^ f(R, round_keys + i * 48);
        L = temp;
    }

    // 合并L和R
    uint64_t pre_output = ((uint64_t)R << 32) | L;

    // 逆初始置换
    for (int i = 0; i < 64; i++) {
        out[i / 8] |= ((pre_output >> (63 - FP[i])) & 1) << (7 - (i % 8));
    }
}

void des_decrypt_block(const uint8_t *in, uint8_t *out, const uint8_t *round_keys) {
    // 实现块解密
	uint32_t L = 0, R = 0;

    // 初始置换
    for (int i = 0; i < 64; i++) {
        if (i < 32) {
            L |= ((in[IP[i] - 1] >> (7 - (i % 8))) & 1) << (31 - i);
        } else {
            R |= ((in[IP[i] - 1] >> (7 - (i % 8))) & 1) << (63 - i);
        }
    }

    // 16轮解密
    for (int i = 15; i >= 0; i--) {
        uint32_t temp = L;
        L = R ^ f(L, round_keys + i * 48);
        R = temp;
    }

    // 合并L和R
    uint64_t pre_output = ((uint64_t)R << 32) | L;

    // 逆初始置换
    for (int i = 0; i < 64; i++) {
        out[i / 8] |= ((pre_output >> (63 - FP[i])) & 1) << (7 - (i % 8));
    }
}