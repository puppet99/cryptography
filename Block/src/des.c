#include "des.h"

#define GET_BIT(x, bit) ((x & (1 << bit)) >> bit) //获取第bit位
#define LEFT_ROTATE(x, bit) ((x) << (bit) | (x) >> (32 - (bit))) //循环左移
#define XOR(a, b) ((a) ^ (b)) //异或

//置换操作
static void permute(uint64_t *output, const uint64_t *input, const uint8_t *table, int n);

//S盒替换
static void sbox(uint64_t *output, const uint64_t *input);

// DES 密钥扩展
void des_key_expansion(uint64_t *expanded_key, const uint64_t *key) {
    uint64_t permuted_choice1;
    uint32_t C, D;

    // 密钥置换选择PC-1（64位密钥降为56位密钥）
    permute(permuted_choice1, key, PC1, 56);

    // 将密钥分成左右两部分
	C = (permuted_choice1 >> 28) & 0x0FFFFF;
	D = permuted_choice1 & 0x0FFFFF;

    // 16轮子密钥的生成
    for (int i = 0; i < 16; i++) {
        LEFT_ROTATE(C, shifts[i]);
        LEFT_ROTATE(D, shifts[i]);

        uint64_t CD = (C << 28) | D;

        // 置换选择表PC-2，生成子密钥
        permute(&expanded_key, CD, PC2, 48);
    }
}

// DES 加密
void des_encrypt_block(const uint64_t *expanded_key, const uint64_t *input, uint64_t *output) {
    uint64_t ip, R_expanded, S_output;
    uint32_t L, R;

    // 初始置换IP
    permute(ip, input, IP, 64);

    // 将输出块分割成两左右两部分
	L = (ip >> 32) & 0xFFFFFF;
	R = ip & 0xFFFFFF;

    // 16 轮迭代
    for (int i = 0; i < 16; i++) {
        // 扩展置换E，将数据右半部分R从32位扩展到48位
        permute(R_expanded, R, E, 48);

        // 扩展置换后的输出与子密钥进行异或
        R_expanded = XOR(R_expanded, *expanded_key);

        // S盒
        sbox(S_output, R_expanded);

        // P盒
        permute(S_output, S_output, P, 32);

        // P盒的输出与最初64位分组的左半部分异或
        S_output = XOR(S_output, L);

        // L = R, R = S_output
        memcpy(L, R, 32);
        memcpy(R, S_output, 32);
    }

    // 拼接L和R
    uint64_t LR;
	LR = ((uint64_t)L << 32) | R;

    // 逆初始置换
    permute(output, LR, FP, 64);
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
        XOR(R_expanded, R_expanded, &expanded_key[i * 6], 48);

        // S盒
        sbox(S_output, (uint64_t)R_expanded);

        // P盒
        permute(S_output, S_output, P, 32);

        // 与左半部分进行异或
        XOR(S_output, S_output, L, 32);

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
static void permute(uint64_t *output, const uint64_t *input, const uint8_t *table, int table_size) {
	*output = 0;
	for(int i = 0; i < table_size; i++){
		uint64_t bit = (*input >> (64 - table[i])) & 0x01;
		*output |= (bit << (table_size -1 -i));
	}
}

// S盒代换
static void sbox(uint64_t *output, const uint64_t *input) {
	//将48位密钥分解成8个6位的输入
	uint8_t temp[8];
	for (int i = 0; i < 8; i++) {
		temp[i] = (*input >> (42 - i * 6)) & 0x3F;
		printf("密钥部分：%d - %02X \n", i + 1, temp[i]);
	}
	
    for (int i = 0; i < 4; i++) {
		//取出第1位以及最后1位来计算行号
        uint8_t row_1 = (GET_BIT(temp[i * 2], 3) << 1) | GET_BIT(temp[i * 2], 8);
		//取出第1位和最后1位中间的4位来计算列号
        uint8_t col_1 = (GET_BIT(temp[i * 2], 4) << 3) | (GET_BIT(temp[i * 2], 5) << 2) | (GET_BIT(temp[i * 2], 6) << 1) | GET_BIT(temp[i * 2], 7);
		
		uint8_t row_2 = (GET_BIT(temp[i * 2 + 1], 3) << 1) | GET_BIT(temp[i * 2 + 1], 8);
		uint8_t col_2 = (GET_BIT(temp[i * 2 + 1], 4) << 3) | (GET_BIT(temp[i * 2 + 1], 5) << 2) | (GET_BIT(temp[i * 2 + 1], 6) << 1) | GET_BIT(temp[i * 2 + 1], 7);
        output[i] = (S[i][row_1][col_1] << 4) | S[i][row_2][col_2];
    }
}