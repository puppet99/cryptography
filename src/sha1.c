#include "../include/sha1.h"

#define SHA1_ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

void sha1_transform(void *context, const uint8_t buffer[64]) {
	sha1_context *ctx = (sha1_context *)context;
    uint32_t a, b, c, d, e, t, W[80];

    for (int i = 0; i < 16; ++i) {
        W[i] = (buffer[i * 4] << 24) | (buffer[i * 4 + 1] << 16) | (buffer[i * 4 + 2] << 8) | (buffer[i * 4 + 3]);
    }
    for (int i = 16; i < 80; ++i) {
        W[i] = SHA1_ROTL(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

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

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void sha1_init(void *context) {
    sha1_context *ctx = (sha1_context *)context;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void sha1_update(void *context, const uint8_t *data, size_t len) {
	sha1_context *ctx = (sha1_context *)context;
    size_t i, j;

    j = (ctx->count >> 3) & 63;
    if ((ctx->count += len << 3) < (len << 3)) ctx->count++;
    if ((j + len) > 63) {
        memcpy(&ctx->buffer[j], data, (i = 64 - j));
        sha1_transform(ctx->state, ctx->buffer);
        for (; i + 63 < len; i += 64) {
            sha1_transform(ctx->state, &data[i]);
        }
        j = 0;
    } else i = 0;
    memcpy(&ctx->buffer[j], &data[i], len - i);
}

void sha1_final(void *context, uint8_t *hash) {
    sha1_context *ctx = (sha1_context *)context;
    uint8_t finalcount[8];
    uint8_t c;

    for (int i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((ctx->count >> ((7 - i) * 8)) & 255);
    }
    c = 0x80;
    sha1_update(ctx, &c, 1);
    while ((ctx->count & 504) != 448) {
        c = 0x00;
        sha1_update(ctx, &c, 1);
    }
    sha1_update(ctx, finalcount, 8);
    for (int i = 0; i < 20; i++) {
        hash[i] = (uint8_t)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
}

const hash_algorithm sha1_algorithm = {
    .init = sha1_init,
    .update = sha1_update,
    .final = sha1_final,
    .context_size = sizeof(sha1_context),
    .hash_size = 20
};
