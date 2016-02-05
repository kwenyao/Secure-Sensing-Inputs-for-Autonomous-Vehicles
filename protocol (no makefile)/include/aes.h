#ifndef AES_H
#define AES_H

#include "constant.h"
// #include <stdio.h>
// #include <openssl/bio.h>
// #include <openssl/evp.h>
//compile : gcc aesccm.c -lssl -lcrypto -o output

// #define NONCE_LENGTH 7 //In Bytes (valid sizes: 7, 8, 9, 10, 11, 12, 13 bytes)
// #define TAG_LENGTH 8   //In Bytes (valid sizes are: 4, 6, 10, 12, 14 and 16 bytes) 
// #define KEY_LENGTH 32  //In Bytes 

unsigned char* aes_encrypt(unsigned char *plaintext, int plaintextlen, unsigned char* tag, unsigned char* key, unsigned char* nonce);
// unsigned char* aes_decrypt(char* ciphertext, int ciphertextlen, unsigned char* tag, char* key, char* nonce);
void* aes_decrypt(char* ciphertext, int ciphertextlen, unsigned char* tag, char* key, char* nonce, unsigned char* returnval, int returnsize);

#endif /* AES_H */
