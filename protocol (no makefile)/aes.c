#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
//compile : gcc aesccm.c -lssl -lcrypto -o output

#define NONCE_LENGTH 7 //In Bytes (valid sizes: 7, 8, 9, 10, 11, 12, 13 bytes)
#define TAG_LENGTH 8   //In Bytes (valid sizes are: 4, 6, 10, 12, 14 and 16 bytes) 
#define KEY_LENGTH 32  //In Bytes 

unsigned char ccm_key[] = {
  0xce,0xb0,0x09,0xae,0xa4,0x45,0x44,0x51,0xfe,0xad,0xf0,0xe6,
  0xb3,0x6f,0x45,0x55,0x5d,0xd0,0x47,0x23,0xba,0xa4,0x48,0xe8
};

unsigned char ccm_nonce[] = {
  0x76,0x40,0x43,0xc4,0x94,0x60,0xb7
};

unsigned char ccm_pt[] = {
  0xc8,0xd2,0x75,0xf9,0x19,0xe1,0x7d,0x7f,0xe6,0x9c,0x2a,0x1f,
  0x58,0x93,0x9d,0xfe,0x4d,0x40,0x37,0x91,0xb5,0xdf,0x13,0x10
};

unsigned char* aes_encrypt(unsigned char *plaintext, int plaintextlen, unsigned char* key, unsigned char* nonce) {
  EVP_CIPHER_CTX *ctx;
  int outlen, tmplen;
  static unsigned char cipherbuf[1024];

  printf("AES CCM Encrypt:\n");
  
  printf("Plaintext:\n");
  BIO_dump_fp(stdout, plaintext, plaintextlen);
  
  ctx = EVP_CIPHER_CTX_new();
  
  /* Set cipher type and mode */
  EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);
  
  /* Set nonce length if default 96 bits is not appropriate */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, NONCE_LENGTH, NULL);
  
  /* Set tag length */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LENGTH, NULL);
  
  /* Initialise key and IV */
  EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
  
  /* Encrypt plaintext: can only be called once */
  EVP_EncryptUpdate(ctx, cipherbuf, &outlen, plaintext, plaintextlen);
  
  /* Output encrypted block */
  printf("Ciphertext:\n");
  BIO_dump_fp(stdout, cipherbuf, outlen);
  
  /* Finalise: note get no output for CCM */
  EVP_EncryptFinal_ex(ctx, cipherbuf, &outlen);
  

  /* Get tag */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, TAG_LENGTH, &cipherbuf[plaintextlen]);
  
  
  EVP_CIPHER_CTX_free(ctx);
  return cipherbuf;
}

unsigned char* aes_decrypt(char* ciphertext, int ciphertextlen, char* key, char* nonce) {
  EVP_CIPHER_CTX *ctx;
  int outlen, tmplen, rv;
  static unsigned char outbuf[1024];
  printf("AES CCM Derypt:\n");

  printf("Ciphertext:\n");
  BIO_dump_fp(stdout, ciphertext, ciphertextlen);

  ctx = EVP_CIPHER_CTX_new();

  /* Select cipher */
  EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);

  /* Set nonce length, omit for 96 bits */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, NONCE_LENGTH, NULL);

  /* Set expected tag value */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LENGTH, (void *)ciphertext+ciphertextlen);

  /* Specify key and IV */
  EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);

  /* Decrypt plaintext, verify tag: can only be called once */
  rv = EVP_DecryptUpdate(ctx, outbuf, &outlen, ciphertext, ciphertextlen);

  /* Output decrypted block: if tag verify failed we get nothing */
  if (rv > 0) {
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, outbuf, outlen);
  } else {
    printf("Plaintext not available: tag verify failed.\n");
  }
  EVP_CIPHER_CTX_free(ctx);
  return outbuf;
}

int main(int argc, char **argv) {
  int plaintextlen = sizeof(ccm_pt);
  unsigned char* ciphertext = aes_encrypt(ccm_pt, plaintextlen, ccm_key, ccm_nonce);
  unsigned char* plaintext = aes_decrypt(ciphertext, plaintextlen, ccm_key, ccm_nonce);
  printf("Results: \n");
  BIO_dump_fp(stdout, ciphertext, plaintextlen);
  BIO_dump_fp(stdout, plaintext, plaintextlen);
}
