#include "interface.h"
#include "des.h"

int main(){
	uint64_t des_key= {0x133457799BBCDFF1}, des_plaintext[2] = "SecurityABCDEF", expanded_key[16] = 0;
	uint64_t des_ciphertext, des_decrypted;
    uint64_t des_padded_block[2];
    memcpy(des_padded_block, des_plaintext, 14);
    pkcs7_pad(des_padded_block, 16, 14);
   
    des_key_expansion(expanded_key, des_key);
    des_encrypt_block(des_padded_block, des_ciphertext, des_key);
    des_decrypt_block(des_ciphertext, des_decrypted, des_key);
   
    uint8_t des_unpadded_len = pkcs7_unpad(des_decrypted, 16);

    printf("DES Encrypted: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", des_ciphertext[i]);
    }
    printf("\nDES Decrypted: %.*s\n", des_unpadded_len, des_decrypted);
}