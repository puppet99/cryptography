#include "interface.h"
#include "des.h"

int main(){
	uint8_t des_key[8] = {0x01, 0x03, 0x03, 0x04, 0x06, 0x07, 0x07, 0x09};
	uint64_t expanded_key[16];
	uint8_t des_plaintext[] = "ABCDE";
    uint8_t des_padded_block[8];
    memcpy(des_padded_block, des_plaintext, sizeof(des_plaintext));
    pkcs7_pad(des_padded_block, 8, sizeof(des_plaintext) / sizeof(des_plaintext[0]) - 1);
	printf("des_padded_block =");
	for(int i = 0; i < 8; i++)
		printf(" %02X ", des_padded_block[i]);
	printf("\n");

	uint8_t des_ciphertext[8], des_decrypted[8];
   
    des_key_expansion(expanded_key, des_key);
    des_encrypt_block(des_padded_block, des_ciphertext, expanded_key);
    des_decrypt_block(des_ciphertext, des_decrypted, expanded_key);
   
    int des_unpadded_len = pkcs7_unpad(des_decrypted, 8);

    printf("DES Encrypted: ");
    for (int i = 0; i < 8; i++) {
        printf("%02X ", des_ciphertext[i]);
    }
    printf("\nDES Decrypted: %.*s\n", des_unpadded_len, des_decrypted);
}