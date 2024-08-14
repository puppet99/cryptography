#include "des.h"

#define GET_BIT(x, bit) ((x & (1 << bit)) >> bit) //获取第bit位
#define LEFT_ROTATE(x, bit) ((x) << (bit) | (x) >> (32 - (bit))) //循环左移
#define XOR(a, b) ((a) ^ (b)) //异或

//置换操作
static void permute(uint8_t *output, const uint8_t *input, const uint8_t *table, int n);
//异或操作
static void xor_buffer(uint8_t *output, const uint8_t *input1, const uint8_t *input2, int n);

//S盒替换
static void sbox(uint8_t *output, const uint8_t *input);

// DES 密钥扩展
void des_key_expansion(uint8_t *expanded_key, const uint8_t *key) {
    uint8_t permuted_choice1[56];
    uint8_t C[28], D[28];

    // 密钥置换选择PC-1（64位密钥降为56位密钥）
    permute(permuted_choice1, key, PC1, 56);

    // 将密钥分成左右两部分
    for (int i = 0; i < 28; i++) {
        C[i] = permuted_choice1[i];
        D[i] = permuted_choice1[i + 28];
    }

    // 16轮子密钥的生成
    for (int i = 0; i < 16; i++) {
        shift_left(C, shifts[i]);
        shift_left(D, shifts[i]);

        uint8_t CD[56];
        for (int j = 0; j < 28; j++) {
            CD[j] = C[j];
            CD[j + 28] = D[j];
        }

        // 置换选择表PC-2，生成子密钥
        permute(&expanded_key[i * 6], CD, PC2, 48);
    }
}

// DES 加密
void des_encrypt_block(const uint8_t *expanded_key, const uint8_t *input, uint8_t *output) {
    uint8_t ip[64];
    uint8_t L[32], R[32], R_expanded[48], S_output[32];

    // 初始置换IP
    permute(ip, input, IP, 64);

    // 将输出块分割成两左右两部分
    for (int i = 0; i < 32; i++) {
        L[i] = ip[i];
        R[i] = ip[i + 32];
    }

    // 16 轮迭代
    for (int i = 0; i < 16; i++) {
        // 扩展置换E，将数据右半部分R从32位扩展到48位
        permute(R_expanded, R, E, 48);

        // 扩展置换后的输出与子密钥进行异或
        xor_buffer(R_expanded, R_expanded, &expanded_key[i * 6], 48);

        // S盒
        sbox(S_output, R_expanded);

        // P盒
        permute(S_output, S_output, P, 32);

        // P盒的输出与最初64位分组的左半部分异或
        xor_buffer(S_output, S_output, L, 32);

        // L = R, R = S_output
        memcpy(L, R, 32);
        memcpy(R, S_output, 32);
    }

    // 拼接L和R
    uint8_t RL[64];
    for (int i = 0; i < 32; i++) {
        RL[i] = R[i];
        RL[i + 32] = L[i];
    }

    // 逆初始置换
    permute(output, RL, FP, 64);
}

// DES 解密
void des_decrypt_block(const uint8_t *expanded_key, const uint8_t *input, uint8_t *output) {
    uint8_t ip[64];
    uint8_t L[32], R[32], R_expanded[48], S_output[32];

    // 应用初始置换
    permute(ip, input, IP, 64);

    // 将信息分割成左右两部分
    for (int i = 0; i < 32; i++) {
        L[i] = ip[i];
        R[i] = ip[i + 32];
    }

    // 16 轮迭代 （相反的顺序）
    for (int i = 15; i >= 0; i--) {
        // 将右半部分扩展到48位
        permute(R_expanded, R, E, 48);

        // 输出后的结果与密钥进行异或
        xor_buffer(R_expanded, R_expanded, &expanded_key[i * 6], 48);

        // S盒
        sbox(S_output, R_expanded);

        // P盒
        permute(S_output, S_output, P, 32);

        // 与左半部分进行异或
        xor_buffer(S_output, S_output, L, 32);

        // L = R, R = S_output
        memcpy(L, R, 32);
        memcpy(R, S_output, 32);
    }

    // 拼接L和R
    uint8_t RL[64];
    for (int i = 0; i < 32; i++) {
        RL[i] = R[i];
        RL[i + 32] = L[i];
    }

    // 逆初始置换
    permute(output, RL, FP, 64);
}

// 置换操作(初始置换表、逆初始置换表、E表、P表)
static void permute(uint8_t *output, const uint8_t *input, const uint8_t *table, int n) {
	uint8_t temp = 0;
    for (int i = 0, j = 1; i < n; i++, j++) {
		uint8_t emp = (table[i] - 1) / 8;
		temp << 1;
		temp |= GET_BIT(input[emp], table[i] % 8);
		if (j == 8){
			output[i/8] = temp;
			j = 0;
			temp = 0;
		}
    }
}

// S盒代换
static void sbox(uint8_t *output, const uint8_t *input) {
    for (int i = 0; i < 8; i++) {
        uint8_t row = (input[i * 6] << 1) | input[i * 6 + 5];
        uint8_t col = (input[i * 6 + 1] << 3) | (input[i * 6 + 2] << 2) | (input[i * 6 + 3] << 1) | input[i * 6 + 4];
        output[i * 4] = S[i][row][col];
    }
}