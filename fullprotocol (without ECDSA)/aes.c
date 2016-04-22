#include "aes.h"


unsigned char* aes_encrypt(unsigned char *plaintext, int plaintextlen,
                           unsigned char* tag, unsigned char* key,
                           unsigned char* nonce) {
  EVP_CIPHER_CTX *ctx;
  int outlen;
  static unsigned char cipherbuf[1024];

  ctx = EVP_CIPHER_CTX_new();
  /* Set cipher type and mode */
  EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);
  /* Set nonce length if default 96 bits is not appropriate */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, NONCE_LENGTH, NULL);
  /* Set tag length */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LENGTH, NULL);
  /* Initialise key and IV */
  EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

  // Set plaintext length: only needed if AAD is used
  EVP_EncryptUpdate(ctx, NULL, &outlen, NULL, plaintextlen);
  // Zero or one call to specify any AAD
  EVP_EncryptUpdate(ctx, NULL, &outlen, ccm_adata, sizeof(ccm_adata));

  /* Encrypt plaintext: can only be called once */
  EVP_EncryptUpdate(ctx, cipherbuf, &outlen, plaintext, plaintextlen);
  /* Finalise: note get no output for CCM */
  EVP_EncryptFinal_ex(ctx, cipherbuf, &outlen);

  /* Get tag */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, TAG_LENGTH, tag);

  EVP_CIPHER_CTX_free(ctx);
  return cipherbuf;
}

void aes_decrypt(unsigned char* ciphertext, int ciphertextlen,
                 unsigned char* tag, unsigned char* key,
                 unsigned char* nonce, unsigned char* returnval,
                 int returnsize, int isHandshake) {
  EVP_CIPHER_CTX *ctx;
  int outlen, rv;
  unsigned char *outbuf;
  if (isHandshake) {
    outbuf = malloc(HANDSHAKE_LENGTH);
  } else {
    outbuf = malloc(INPUT_MAX_LEN);
  }
  // printf("\nciphertext in aes.c: "); printHex(ciphertext, ciphertextlen);

  ctx = EVP_CIPHER_CTX_new();

  /* Select cipher */
  EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);
  /* Set nonce length, omit for 96 bits */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, NONCE_LENGTH, NULL);
  /* Set expected tag value */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LENGTH, tag);
  /* Specify key and IV */
  EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);

  /* Set ciphertext length: only needed if we have AAD */
  EVP_DecryptUpdate(ctx, NULL, &outlen, NULL, ciphertextlen);
  /* Zero or one call to specify any AAD */
  EVP_DecryptUpdate(ctx, NULL, &outlen, ccm_adata, sizeof(ccm_adata));

  /* Decrypt plaintext, verify tag: can only be called once */
  rv = EVP_DecryptUpdate(ctx, outbuf, &outlen, ciphertext, ciphertextlen);

  /* Output decrypted block: if tag verify failed we get nothing */
  if (rv < 0) {
    perror("Plaintext not available: tag verify failed.\n");
  }
  printHex(outbuf, ciphertextlen);
  // printf("\noutbuf in aes.c: ");printHex(outbuf, returnsize);
  EVP_CIPHER_CTX_free(ctx);
  memcpy(returnval, outbuf, returnsize);
  free(outbuf);
}
