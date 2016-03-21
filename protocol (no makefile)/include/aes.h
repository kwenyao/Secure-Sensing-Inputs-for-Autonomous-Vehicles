#ifndef AES_H
#define AES_H

#include "constant.h"

static const unsigned char ccm_adata[] = {
	0x6e, 0x80, 0xdd, 0x7f, 0x1b, 0xad, 0xf3, 0xa1, 0xc9, 0xab,
	0x25, 0xc7,	0x5f, 0x10, 0xbd, 0xe7, 0x8c, 0x23, 0xfa, 0x0e,
	0xb8, 0xf9, 0xaa, 0xa5,	0x3a, 0xde, 0xfb, 0xf4, 0xcb, 0xf7,
	0x8f, 0xe4
};

unsigned char* aes_encrypt(unsigned char *plaintext, int plaintextlen,
                           unsigned char* tag, unsigned char* key,
                           unsigned char* nonce);

void aes_decrypt(unsigned char* ciphertext, int ciphertextlen,
                 unsigned char* tag, unsigned char* key,
                 unsigned char* nonce, unsigned char* returnval,
                 int returnsize, int isHandshake);

#endif /* AES_H */
