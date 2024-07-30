// main.c

#include <stdio.h>
#include <string.h>
#include "sha1.h"
#include "sha256.h"
#include "md5.h"

int main() {
    uint8_t hash[32];
	sha1_context ctx;
    
	const char *msg = "Security";

    // SHA-1
    sha1_algorithm.init(&ctx);
    sha1_algorithm.update(&ctx, (const uint8_t *) msg, strlen(msg));
    sha1_algorithm.final(&ctx, hash);
	printf("SHA-1:");
    for (int i = 0; i < sha1_algorithm.hash_size; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    // // SHA-256
    // sha256_algorithm.init(NULL);
    // sha256_algorithm.update(NULL, (const uint8_t *)msg, strlen(msg));
    // sha256_algorithm.final(NULL, hash);
    // for (int i = 0; i < sha256_algorithm.hash_size; i++) {
    //     printf("%02x", hash[i]);
    // }
    // printf("\n");

    // // MD5
    // md5_algorithm.init(NULL);
    // md5_algorithm.update(NULL, (const uint8_t *)msg, strlen(msg));
    // md5_algorithm.final(NULL, hash);
    // for (int i = 0; i < md5_algorithm.hash_size; i++) {
    //     printf("%02x", hash[i]);
    // }
    // printf("\n");

    return 0;
}