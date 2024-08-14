// main.c

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sha1.h"
#include "sha256.h"
#include "md5.h"

int main() {
    uint8_t hash[32];
	sha1_context ctx;

	clock_t start_t, end_t;
	double total_t, speed_mbps;
    
	const char *msg = "Happiness is a struggle. Do not forget the original intention, forge ahead. ";
	size_t msg_len = strlen(msg);

    // SHA-1
	start_t = clock();
    sha1_algorithm.init(&ctx);
    sha1_algorithm.update(&ctx, (const uint8_t *) msg, msg_len);
    sha1_algorithm.final(&ctx, hash);
	printf("SHA-1:");
    for (int i = 0; i < sha1_algorithm.hash_size; i++) {
        printf("%02x", hash[i]);
    }
	printf("\n");
	end_t = clock();
	total_t = (double)(end_t - start_t) / CLOCKS_PER_SEC;
	printf("SHA-1程序执行时间：%f ps\n", total_t * 1000000.0);
	speed_mbps = (msg_len * 8.0) / (total_t * 1000000.0);
	printf("SHA-1程序运算速度：%f Mbps\n", speed_mbps);

    // SHA-256
	start_t = clock();
    sha256_algorithm.init(&ctx);
    sha256_algorithm.update(&ctx, (const uint8_t *)msg, msg_len);
    sha256_algorithm.final(&ctx, hash);
	printf("SHA-256:");
    for (int i = 0; i < sha256_algorithm.hash_size; i++) {
        printf("%02x", hash[i]);
    }
	printf("\n");
	end_t = clock();
	total_t = (double)(end_t - start_t) / CLOCKS_PER_SEC;
	printf("SHA-256程序执行时间：%f ps\n", total_t * 1000000.0);
	speed_mbps = (msg_len * 8.0) / (total_t * 1000000.0);
	printf("SHA-256程序运算速度：%f Mbps\n", speed_mbps);


    // MD5
	start_t = clock();
    md5_algorithm.init(&ctx);
    md5_algorithm.update(&ctx, (const uint8_t *)msg, msg_len);
    md5_algorithm.final(&ctx, hash);
	printf("MD5:");
    for (int i = 0; i < md5_algorithm.hash_size; i++) {
        printf("%02x", hash[i]);
    }
	printf("\n");
	end_t = clock();
	total_t = (double)(end_t - start_t) / CLOCKS_PER_SEC;
	printf("MD-5程序执行时间：%f ps\n", total_t * 1000000.0);
	speed_mbps = (msg_len * 8.0) / (total_t * 1000000.0);
	printf("MD-5程序运算速度：%f Mbps\n", speed_mbps);

    return 0;
}