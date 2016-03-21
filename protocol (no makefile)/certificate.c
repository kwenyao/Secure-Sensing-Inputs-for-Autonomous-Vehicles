#include "certificate.h"

EVP_PKEY* loadKeyFromFile(char *fileName) {
  const char *engineId = "tpm";
  ENGINE *e;
  EVP_PKEY *key;


  ENGINE_load_builtin_engines();
  e = ENGINE_by_id(engineId);
  if (!e) { // Engine not available
    ERR_print_errors_fp(stderr);
    PRINTDEBUG("ENGINE_by_id failed.");
    return NULL;
  }
  if (!ENGINE_init(e)) { // Engine couldn't initialise
    ERR_print_errors_fp(stderr);
    PRINTDEBUG("ENGINE_init failed.");
    ENGINE_free(e);
    ENGINE_finish(e);
    return NULL;
  }
  if (!ENGINE_set_default_RSA(e) || !ENGINE_set_default_RAND(e)) {
    /* This should only happen when 'e' can't initialise, but the previous
     * statement suggests it did. */
    ERR_print_errors_fp(stderr);
    PRINTDEBUG("ENGINE_init failed.");
    ENGINE_free(e);
    ENGINE_finish(e);
    return NULL;
  }
  ENGINE_ctrl_cmd(e, "PIN", 0, SRK_PASSWORD, NULL, 0);
  ENGINE_free(e);

  if ((key = ENGINE_load_private_key(e, fileName, NULL, NULL)) == NULL) {
    ERR_print_errors_fp(stderr);
    PRINTDEBUG("Couldn't load TPM key from file.");
    return NULL;
  }
  ENGINE_finish(e);
  e = NULL;

  return key;
}

void deleteKeyFile(char *fileName) {
  if (remove(fileName) == 0) {
    PRINTDEBUG("Key file deleted.");
  } else {
    fprintf(stderr, "Error deleting key file %s.\n", fileName);
  }
  return;
}

X509* getCertFromFile(char* certName) {
  BIO *certbio = NULL;
  BIO *outbio = NULL;
  X509 *cert = NULL;

  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  certbio = BIO_new(BIO_s_file());
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  BIO_read_filename(certbio, certName);

  if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading cert into memory\n");
    cert = NULL;
  }
  BIO_free_all(certbio);
  BIO_free_all(outbio);

  return cert;
}

EVP_PKEY* getPubKeyFromCert(X509 *cert) {
  EVP_PKEY *pkey = NULL;

  BIO_new_fp(stdout, BIO_NOCLOSE);
  pkey = X509_get_pubkey(cert);
  return pkey;
}

int verifyCert(char* certFile, char* CAcertFile)
{
  int isVerified = 0;

  X509 *certA = getCertFromFile(certFile);
  X509 *CACert = getCertFromFile(CAcertFile);
  if (certA == NULL || CACert == NULL)
  {
    fprintf(stderr, "Getting cert from file failed");
    return 0;
  }

  X509_STORE_CTX *ctx = X509_STORE_CTX_new();
  X509_STORE *store = X509_STORE_new();

  X509_STORE_set_default_paths(store);

  X509_STORE_add_cert(store, CACert);
  X509_STORE_CTX_init(ctx, store, certA, NULL);

  if (X509_verify_cert(ctx) == 0)
  {
    isVerified = 0;
    printf("Verify Failed\n");
    printf("%s\n", X509_verify_cert_error_string(ctx->error));
  }
  else
  {
    isVerified = 1;
    PRINTDEBUG("Certificate verification successful");
  }
  X509_STORE_free(store);
  X509_STORE_CTX_cleanup(ctx);

  return isVerified;
}