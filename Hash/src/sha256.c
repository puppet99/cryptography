
#include "../include/sha256.h"
#include <string.h>

#define ROR(a,b) ((a >> b) | (a << (32 - b))) //循环右移
#define BLOCK_SIZE 64 //块大小定义为64位
#define O_0(x) (ROR(x,7) ^ ROR(x,18) ^ (x >> 3))
#define O_1(x) (ROR(x,17) ^ ROR(x,19) ^ (x >> 10))
#define ch(e,f,g) ((e & f) ^ (~e & g))
#define Ma(a,b,c) ((a & b) ^ (a & c) ^ (b & c))
#define E_0(a) (ROR(a,2) ^ ROR(a,13) ^ ROR(a,22))
#define E_1(e) (ROR(e,6) ^ ROR(e,11) ^ ROR(e,25))

const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_transform(void *context, const uint8_t buffer[64]){
	sha256_context *ctx = (sha256_context *) context;

	//a,b,c,d,e,f,g,h初始链接变量
	uint32_t a,b,c,d,e,f,g,h,T_1,T_2,W[64];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	//W[i]的生成
	for(int i = 0; i < 16;i++)
		W[i] = (buffer[i * 4] << 24) | (buffer[i * 4 + 1] << 16) | (buffer[i * 4 + 2] << 8) | (buffer[i * 4 + 3]);
	
	for(int i = 16;i < 64;i++)
		W[i] = O_1(W[i-2]) + W[i-7] + O_0(W[i-15]) + W[i-16];

	//循环计算
	for(int i = 0;i < 64;i++){
		T_1 = h + E_1(e) + ch(e,f,g) + K[i] +W[i];
		T_2 = E_0(a) + Ma(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d +T_1;
		d = c;
		c = b;
		b = a;
		a = T_1 + T_2;
	}

	//更新哈希值
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}


void sha256_init(void *context) {
    sha256_context *ctx = (sha256_context *)context;
    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

//处理信息
void sha256_update(void *context, const uint8_t *data, size_t len) {
    sha256_context *ctx = (sha256_context *) context;

	ctx->count = len << 3;
	//判断消息长度是否超出64字节
	for(size_t i = 0, j = 0;j < len; ++j){
		ctx->buffer[i++] = data[j];
		if (i == 64){
			sha256_transform(ctx, ctx->buffer);
			i = 0;
		}	
	}
	//对64取余，判断值是否大于56
	size_t i = len & 0x3F;
	//设置占1字节的10000000
	ctx->buffer[i++] = 0x80;

	if(i > 56){
		//若消息长度超出56字节，8字节的消息长度则无法存放，需填充
		memset(ctx->buffer + i ,0 ,64 - i);
		sha256_transform(ctx, ctx->buffer);
		i = 0;
	}
	memset(ctx->buffer + i,0 ,64 - i -8);
	//增添消息长度信息
	for(i=1; i <= 8;i++)
		ctx->buffer[64 - i] = (ctx->count >> 8*(i-1)) & 0xFF;
	sha256_transform(ctx, ctx->buffer);
}

void sha256_final(void *context, uint8_t *hash) {
    sha256_context *ctx = (sha256_context *) context;
	for(size_t i = 0; i < 8; i++){
		hash[i * 4 + 0] = (ctx->state[i] >> 24) & 0xFF;
		hash[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
		hash[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
		hash[i * 4 + 3] = (ctx->state[i] ) & 0xFF;
	}
}

const hash_algorithm sha256_algorithm = {
    .init = sha256_init,
    .update = sha256_update,
    .final = sha256_final,
    .context_size = sizeof(sha256_context),
    .hash_size = 32
};