#include "interface.h"
#include "des.h"

int main(){
	uint64_t des_key= {0x133457799BBCDFF1};
    uint64_t des_exp_key;  // 48位扩展密钥
    uint8_t des_plaintext[16] = "SecurityABCDEF";  // 14 bytes
    uint8_t des_padded_block[16];
    memcpy(des_padded_block, des_plaintext, 14);
    pkcs7_pad(des_padded_block, 16, 14);
   
    uint8_t des_ciphertext[16];
    uint8_t des_decrypted[16];
   
    des_key_expansion(des_exp_key, des_key);
    des_encrypt_block(des_exp_key, des_padded_block, des_ciphertext);
    des_decrypt_block(des_exp_key, des_ciphertext, des_decrypted);
   
    uint8_t des_unpadded_len = pkcs7_unpad(des_decrypted, 16);

    printf("DES Encrypted: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", des_ciphertext[i]);
    }
    printf("\nDES Decrypted: %.*s\n", des_unpadded_len, des_decrypted);
}