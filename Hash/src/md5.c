#include "../include/md5.h"
#include <string.h>

#define ROTLEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#define F(X, Y, Z) ((X & Y) | (~X & Z))
#define G(X, Y, Z) ((X & Z) | (Y & ~Z))
#define H(X, Y, Z) (X ^ Y ^ Z)
#define I(X, Y, Z) (Y ^ (X | ~Z))
#define FF(a,b,c,d,W,s,t) (a = b + (ROTLEFT(a + F(b,c,d) + W + t, s)))
#define GG(a,b,c,d,W,s,t) (a = b + (ROTLEFT(a + G(b,c,d) + W + t, s)))
#define HH(a,b,c,d,W,s,t) (a = b + (ROTLEFT(a + H(b,c,d) + W + t, s)))
#define II(a,b,c,d,W,s,t) (a = b + (ROTLEFT(a + I(b,c,d) + W + t, s)))

const uint32_t t[] = {
	0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
	0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,
	0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,
	0xa679438e,0x49b40821,0xf61e2562,0xc040b340,0x265e5a51,
	0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
	0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,
	0xfcefa3f8,0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,
	0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,
	0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
	0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,0xf4292244,
	0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,
	0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,
	0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

void md5_transform(void *context, const uint8_t buffer[64]){
	md5_context *ctx = (md5_context *)context;

	uint32_t a,b,c,d,W[16];
	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];

	for(int i = 0;i < 16;i++)
		W[i] = (buffer[i * 4]) | (buffer[i * 4 + 1] << 8) | (buffer[i * 4 + 2] << 16) | (buffer[i * 4 +3] << 24);

	// size_t j = 0;
	// for(size_t i = 0;i < 16; i += 4){
	// 	FF(a,b,c,d,W[i],7,t[j]);j++;
	// 	FF(d,a,b,c,W[(i + 1) %16],12,t[j]);j++;
	// 	FF(c,d,a,b,W[(i + 2) %16],17,t[j]);j++;
	// 	FF(b,c,d,a,W[(i + 3) %16],22,t[j]);j++;
	// }
	// for(size_t i = 0;i < 16; i += 4){
	// 	GG(a,b,c,d,W[(i + 1) %16],5,t[j]);j++;
	// 	GG(d,a,b,c,W[(i + 6) %16],9,t[j]);j++;
	// 	GG(c,d,a,b,W[(i  + 11) %16],14,t[j]);j++;
	// 	GG(b,c,d,a,W[i],20,t[j]);j++;
	// }
	// for(size_t i = 0;i < 16; i += 4){
	// 	HH(a,b,c,d,W[(5+16 - i) %16],4,t[j]);j++;
	// 	HH(d,a,b,c,W[(8+16 - i) %16],11,t[j]);j++;
	// 	HH(c,d,a,b,W[(11+16 - i) %16],16,t[j]);j++;
	// 	HH(b,c,d,a,W[(14+16 - i) %16],23,t[j]);j++;
	// }
	// for(size_t i = 0;i < 16; i += 4){
	// 	II(a,b,c,d,W[(0+16 - i) %16],6,t[j]);j++;
	// 	II(d,a,b,c,W[(7+16 - i) %16],10,t[j]);j++;
	// 	II(c,d,a,b,W[(14+16 - i) %16],15,t[j]);j++;
	// 	II(b,c,d,a,W[(5+16 - i) %16],21,t[j]);j++;
	// }

	FF(a, b, c, d, W[ 0], 7, 0xd76aa478);   
    FF(d, a, b, c, W[ 1], 12, 0xe8c7b756);   
    FF(c, d, a, b, W[ 2], 17, 0x242070db);   
    FF(b, c, d, a, W[ 3], 22, 0xc1bdceee);   
 
    FF(a, b, c, d, W[ 4], 7, 0xf57c0faf);   
    FF(d, a, b, c, W[ 5], 12, 0x4787c62a);   
    FF(c, d, a, b, W[ 6], 17, 0xa8304613);   
    FF(b, c, d, a, W[ 7], 22, 0xfd469501);   
 
    FF(a, b, c, d, W[ 8], 7, 0x698098d8);   
    FF(d, a, b, c, W[ 9], 12, 0x8b44f7af);   
    FF(c, d, a, b, W[10], 17, 0xffff5bb1);   
    FF(b, c, d, a, W[11], 22, 0x895cd7be);   
 
    FF(a, b, c, d, W[12], 7, 0x6b901122);   
    FF(d, a, b, c, W[13], 12, 0xfd987193);   
    FF(c, d, a, b, W[14], 17, 0xa679438e);   
    FF(b, c, d, a, W[15], 22, 0x49b40821);   
 
 
    /*************第二轮*****************/
    GG(a, b, c, d, W[ 1], 5, 0xf61e2562);   
    GG(d, a, b, c, W[ 6], 9, 0xc040b340);   
    GG(c, d, a, b, W[11], 14, 0x265e5a51);   
    GG(b, c, d, a, W[ 0], 20, 0xe9b6c7aa);   
 
    GG(a, b, c, d, W[ 5], 5, 0xd62f105d);   
    GG(d, a, b, c, W[10], 9,  0x2441453);   
    GG(c, d, a, b, W[15], 14, 0xd8a1e681);   
    GG(b, c, d, a, W[ 4], 20, 0xe7d3fbc8);   
 
    GG(a, b, c, d, W[ 9], 5, 0x21e1cde6);   
    GG(d, a, b, c, W[14], 9, 0xc33707d6);   
    GG(c, d, a, b, W[ 3], 14, 0xf4d50d87);   
    GG(b, c, d, a, W[ 8], 20, 0x455a14ed);   
 
    GG(a, b, c, d, W[13], 5, 0xa9e3e905);   
    GG(d, a, b, c, W[ 2], 9, 0xfcefa3f8);   
    GG(c, d, a, b, W[ 7], 14, 0x676f02d9);   
    GG(b, c, d, a, W[12], 20, 0x8d2a4c8a);   
 
 
    /*************第三轮*****************/
    HH(a, b, c, d, W[ 5], 4, 0xfffa3942);   
    HH(d, a, b, c, W[ 8], 11, 0x8771f681);   
    HH(c, d, a, b, W[11], 16, 0x6d9d6122);   
    HH(b, c, d, a, W[14], 23, 0xfde5380c);   
 
    HH(a, b, c, d, W[ 1], 4, 0xa4beea44);   
    HH(d, a, b, c, W[ 4], 11, 0x4bdecfa9);   
    HH(c, d, a, b, W[ 7], 16, 0xf6bb4b60);   
    HH(b, c, d, a, W[10], 23, 0xbebfbc70);   
 
    HH(a, b, c, d, W[13], 4, 0x289b7ec6);   
    HH(d, a, b, c, W[ 0], 11, 0xeaa127fa);   
    HH(c, d, a, b, W[ 3], 16, 0xd4ef3085);   
    HH(b, c, d, a, W[ 6], 23,  0x4881d05);   
 
    HH(a, b, c, d, W[ 9], 4, 0xd9d4d039);   
    HH(d, a, b, c, W[12], 11, 0xe6db99e5);   
    HH(c, d, a, b, W[15], 16, 0x1fa27cf8);   
    HH(b, c, d, a, W[ 2], 23, 0xc4ac5665);   
 
 
 
    /*************第四轮******************/
    II(a, b, c, d, W[ 0], 6, 0xf4292244);   
    II(d, a, b, c, W[ 7], 10, 0x432aff97);   
    II(c, d, a, b, W[14], 15, 0xab9423a7);   
    II(b, c, d, a, W[ 5], 21, 0xfc93a039);   
 
    II(a, b, c, d, W[12], 6, 0x655b59c3);   
    II(d, a, b, c, W[ 3], 10, 0x8f0ccc92);   
    II(c, d, a, b, W[10], 15, 0xffeff47d);   
    II(b, c, d, a, W[ 1], 21, 0x85845dd1);   
 
    II(a, b, c, d, W[ 8], 6, 0x6fa87e4f);   
    II(d, a, b, c, W[15], 10, 0xfe2ce6e0);   
    II(c, d, a, b, W[ 6], 15, 0xa3014314);   
    II(b, c, d, a, W[13], 21, 0x4e0811a1);   
 
    II(a, b, c, d, W[ 4], 6, 0xf7537e82);   
    II(d, a, b, c, W[11], 10, 0xbd3af235);   
    II(c, d, a, b, W[ 2], 15, 0x2ad7d2bb);   
    II(b, c, d, a, W[ 9], 21, 0xeb86d391);   
	
	//更新参数
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
}

void md5_init(void *context) {
    md5_context *ctx = (md5_context *)context;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void md5_update(void *context, const uint8_t *data, size_t len) {
    md5_context *ctx = (md5_context *)context;

	ctx->count = len << 3;
	//判断消息是否超出64字节
	for(size_t i = 0, j = 0;j < len; j++){
		ctx->buffer[i++] = data[j];
		if (i == 64){
			md5_transform(ctx, ctx->buffer);
			i = 0;
		}	
	}

	size_t i = len & 0x3F;
	ctx->buffer[i++] = 0x80;

	//判断mod64后是否超出56字节
	if(i > 56){
		memset(ctx->buffer + i, 0 ,64 - i);
		md5_transform(ctx,ctx->buffer);
		i = 0;
	}
	memset(ctx->buffer + i, 0, 56 - i);
	for(i = 0; i < 8; i++)
		ctx->buffer[56 + i] = (ctx->count >> 8 * i) & 0xFF;
	md5_transform(ctx,ctx->buffer);
}

void md5_final(void *context, uint8_t *hash) {
	md5_context *ctx = (md5_context *)context;
	for(size_t i = 0; i < 4; i++){
	hash[i * 4 + 0] = (ctx->state[i] ) & 0xFF;
	hash[i * 4 + 1] = (ctx->state[i] >> 8) & 0xFF;
	hash[i * 4 + 2] = (ctx->state[i] >> 16) & 0xFF;
	hash[i * 4 + 3] = (ctx->state[i] >> 24) & 0xFF;
	}
}

const hash_algorithm md5_algorithm = {
    .init = md5_init,
    .update = md5_update,
    .final = md5_final,
    .context_size = sizeof(md5_context),
    .hash_size = 16
};
