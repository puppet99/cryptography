#include "../include/sha1.h"
#include <string.h>

#define SHA1_ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

//核心计算函数
void sha1_transform(void *context, const uint8_t buffer[64]) {
	sha1_context *ctx = (sha1_context *) context;
    uint32_t a, b, c, d, e, t, W[80];

    for (int i = 0; i < 16; ++i) 
        W[i] = (buffer[i * 4] << 24) | (buffer[i * 4 + 1] << 16) | (buffer[i * 4 + 2] << 8) | (buffer[i * 4 + 3]);
    
    for (int i = 16; i < 80; ++i) 
        W[i] = SHA1_ROTL(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
    

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

	//循环计算
    for (int i = 0; i < 80; ++i) {
        if (i < 20) {
            t = SHA1_ROTL(a, 5) + ((b & c) | (~b & d)) + e + W[i] + 0x5A827999;
        } else if (i < 40) {
            t = SHA1_ROTL(a, 5) + (b ^ c ^ d) + e + W[i] + 0x6ED9EBA1;
        } else if (i < 60) {
            t = SHA1_ROTL(a, 5) + ((b & c) | (b & d) | (c & d)) + e + W[i] + 0x8F1BBCDC;
        } else {
            t = SHA1_ROTL(a, 5) + (b ^ c ^ d) + e + W[i] + 0xCA62C1D6;
        }
        e = d;
        d = c;
        c = SHA1_ROTL(b, 30);
        b = a;
        a = t;
    }

	//更新哈希值
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

//初始化
void sha1_init(void *context) {
	sha1_context *ctx = (sha1_context *) context;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

//处理输入信息，分块，填充
void sha1_update(void *context, const uint8_t *data, size_t len) {
	sha1_context *ctx = (sha1_context *) context;
	ctx->count += len << 3;
	// 判断消息长度是否超出64字节
	for(size_t i = 0, j = 0; j < len; ++j){
		ctx->buffer[i++] = data[j];
		if(i == 64){
			sha1_transform(ctx, ctx->buffer);
			i = 0;
		}
	}

	
	size_t i = (ctx->count >> 3) & 0x3F;
	ctx->buffer[i++] = 0x80;

	if(i > 56){
		//若消息长度超出56字节，8字节的消息长度则无法存放，需填充
		memset(ctx->buffer + i ,0 ,64 - i);
		sha1_transform(ctx, ctx->buffer);
		i = 0;
	}

	memset(ctx->buffer + i,0 ,64 - i -8);

	for(i=1; i <= 8;i++)
		ctx->buffer[64 - i] = (ctx->count >> 8*(i-1)) & 0xFF;
	
	sha1_transform(ctx, ctx->buffer);
}

//哈希值拼接
void sha1_final(void *context, uint8_t *hash) {
	sha1_context *ctx = (sha1_context *) context;
    for(size_t i = 0; i < 5; i++){
		hash[i * 4 + 0] = (ctx->state[i] >> 24) & 0xFF;
		hash[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
		hash[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
		hash[i * 4 + 3] = (ctx->state[i] ) & 0xFF;
	}
}

const hash_algorithm sha1_algorithm = {
    .init = sha1_init,
    .update = sha1_update,
    .final = sha1_final,
    .context_size = sizeof(sha1_context),
    .hash_size = 20
};
