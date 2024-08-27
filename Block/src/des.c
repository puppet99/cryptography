#include "des.h"

#define GET_BIT(x, bit) ((x >> (bit - 1)) & 0x01) //获取第bit位
#define LEFT_ROTATE(x, bit) ((x << bit) | (x) >> (28 - (bit)))
#define XOR(a, b) ((a) ^ (b)) //异或

//置换操作
static void permute(uint8_t *output,const uint8_t *input, const uint8_t *table, int table_size);

//S盒替换
static void sbox(uint32_t *output, const uint64_t *input);

// DES 密钥扩展
void des_key_expansion(uint64_t *expanded_key, const uint8_t *key) {
    uint8_t permuted_choice[7] = {0};
    uint32_t C = 0, D = 0;

    // 密钥置换选择PC-1（64位密钥降为56位密钥）
    permute(permuted_choice, key, PC1, 56);

    // 将密钥分成左右两部分
	for(int i = 0; i < 3; i++){
		C = C << 8;
		C |= permuted_choice[i];
	}
	C = C << 4;
	C |= (uint32_t)((permuted_choice[3] >> 4) & 0x0F);
	D |= (uint32_t)(permuted_choice[3] & 0x0F);
	for(int i = 4; i < 7; i++){
		D = D << 8;
		D |= permuted_choice[i];
	}
	
    // 16轮子密钥的生成
    for (int i = 0; i < 16; i++) {
        C = LEFT_ROTATE(C, shifts[i]) & 0xFFFFFFF;
        D = LEFT_ROTATE(D, shifts[i]) & 0xFFFFFFF;

		//C与D进行合并
        uint8_t CD[7] = {0};
		for(int i = 0; i < 3; i++){
			CD[i] = (C >> (20 - i * 8)) & 0xFF;
		}
		CD[3] = (uint8_t)(C & 0x0F) << 4 | (uint8_t)((D >> 24) & 0x0F);
		for(int i = 4; i < 7; i++){
			CD[i] = (D >> (16 - (i - 4) * 8)) & 0xFF;
		}
		
        // 置换选择表PC-2，生成子密钥
		uint8_t expanded_key_temp[6] = {0};
        permute(expanded_key_temp, CD, PC2, 48);

		expanded_key[i] = 0;
		for(int j = 0; j < 6; j++){
			expanded_key[i] |= (uint64_t)(expanded_key_temp[j]) << (40 - (j * 8));
		}
    }
}

// DES 加密
void des_encrypt_block(const uint8_t *input, uint8_t *output, const uint64_t *expanded_key) {
    uint8_t ip[8] = {0};
	uint8_t R_expanded[6] = {0}, R[4],L[4], S_output[4] = {0};

    // 初始置换IP
    permute(ip, input, IP, 64);

    // 将输出块分割成两左右两部分
	memcpy(L, ip, 4);
	memcpy(R, &ip[4], 4);

    // 16 轮迭代
    for (int i = 0; i < 16; i++) {
        // 扩展置换E，将数据右半部分R从32位扩展到48位
        permute(R_expanded, R, E, 48);

		uint64_t R_expanded_temp = 0;
		for(int j = 0; j < 6; j++){
			R_expanded_temp |= (uint64_t)(R_expanded[j]) << (40 - j * 8);
		}

        // 扩展置换后的输出与子密钥进行异或
        R_expanded_temp = XOR(R_expanded_temp, expanded_key[i]);

		// S盒
		uint32_t S_output_temp = 0;
        sbox(&S_output_temp, &R_expanded_temp);

		for(int j = 0; j < 4; j++){
			S_output[j] = S_output_temp >> (24 - j * 8) &0xFF;
		}

        // P盒
		uint8_t temp[4];
        permute(temp, S_output, P, 32);
		memcpy(S_output, temp, 4);
		// P盒的输出与上轮分组的左半部分异或
		for(int j = 0; j < 4; j++){
			S_output[j] = XOR(S_output[j], L[j]);
		}
		
		memcpy(L, R, 4);
		memcpy(R, S_output, 4);
    }
	
    // 拼接L和R
    uint8_t RL[8];
	for(int j = 0; j < 4; j++){
		RL[j] = R[j];
		RL[j + 4] = L[j];
	}

    // 逆初始置换
	uint8_t emp[8];
    permute(emp, RL, FP, 64);
	memcpy(RL, emp, 8);
	for(int j = 0; j < 8; j++)
		output[j] = RL[j];
	
}

// DES 解密
void des_decrypt_block(const uint8_t *input, uint8_t *output, const uint64_t *expanded_key){
    uint8_t ip[8] = {0};
	uint8_t R_expanded[6] = {0}, R[4],L[4], S_output[4] = {0};
    // 应用初始置换

    // 初始置换IP
    permute(ip, input, IP, 64);

    // 将输出块分割成两左右两部分
	memcpy(L, ip, 4);
	memcpy(R, &ip[4], 4);

    // 16 轮迭代 （相反的顺序）
    for (int i = 15; i >= 0; i--) {
        // 扩展置换E，将数据右半部分R从32位扩展到48位
        permute(R_expanded, R, E, 48);

		uint64_t R_expanded_temp = 0;
		for(int j = 0; j < 6; j++){
			R_expanded_temp |= (uint64_t)(R_expanded[j]) << (40 - j * 8);
		}

        // 扩展置换后的输出与子密钥进行异或
        R_expanded_temp = XOR(R_expanded_temp, expanded_key[i]);

		// S盒
		uint32_t S_output_temp = 0;
        sbox(&S_output_temp, &R_expanded_temp);

		for(int j = 0; j < 4; j++){
			S_output[j] = S_output_temp >> (24 - j * 8) &0xFF;
		}

        // P盒
		uint8_t temp[4];
        permute(temp, S_output, P, 32);
		memcpy(S_output, temp, 4);
		// P盒的输出与上轮分组的左半部分异或
		for(int j = 0; j < 4; j++){
			S_output[j] = XOR(S_output[j], L[j]);
		}
		
		memcpy(L, R, 4);
		memcpy(R, S_output, 4);
    }

    // 拼接L和R
    uint8_t RL[8];
	for(int j = 0; j < 4; j++){
		RL[j] = R[j];
		RL[j + 4] = L[j];
	}

    // 逆初始置换
	uint8_t emp[8];
    permute(emp, RL, FP, 64);
	memcpy(RL, emp, 8);
	for(int j = 0; j < 8; j++)
		output[j] = RL[j];
}

// 置换操作(初始置换表、逆初始置换表、E表、P表)
static void permute(uint8_t *output,const uint8_t *input, const uint8_t *table, int table_size) {
	for(int i = 0; i < table_size / 8; i++){
		output[i] = 0;
	}
	for(int i = 0; i < table_size; i++){
		//计算输入位的位置
		int input_bit = table[i] - 1 ;
		//将输入的位移动到输出中
		output[i / 8] |= ((input[input_bit / 8] >> (7 - (input_bit % 8))) & 0x01) << (7 - (i % 8));
	}

}

// S盒代换
static void sbox(uint32_t *output, const uint64_t *input) {
	*output = 0;

    for (int i = 0; i < 8; i++) {
		// 获取每个6位输入块
		uint8_t block = (*input >> (42 - i * 6)) & 0x3F;

		// 计算行和列
        uint8_t row = ((block & 0x20) >> 4) | (block & 0x01);
        uint8_t col = (block >> 1) & 0x0F;
		
		// 获取 S 盒输出
        uint8_t s_value = S[i][row][col];

        *output |= (s_value << (4 * (7 - i)));
    }
}