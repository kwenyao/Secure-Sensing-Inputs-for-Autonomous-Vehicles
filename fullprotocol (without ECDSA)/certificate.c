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

int verifyCert(char* certFile, char* CAcertFile) {
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

void generateCertificate(EVP_PKEY *key, char *certFileName) {
  X509 *cert;
  X509_NAME *name = NULL;
  FILE * fp = NULL;

  cert = X509_new();

  X509_set_version(cert, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 0);
  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), (long)60 * 60 * 24 * CERT_VALIDITY);

  X509_set_pubkey(cert, key);
  ERR_print_errors_fp(stderr);

  name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (const unsigned char *)CERT_COUNTRY, -1, -1, 0); //country
  X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char *)CERT_STATE, -1, -1, 0); //state
  X509_NAME_add_entry_by_txt(name, "L",  MBSTRING_ASC, (const unsigned char *)CERT_LOCALITY, -1, -1, 0); //locality
  X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (const unsigned char *)CERT_ORGANISATION, -1, -1, 0); //organisation
  X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char *)CERT_ORG_UNIT, -1, -1, 0); //organisational unit
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)CERT_COMMON_NAME, -1, -1, 0); //common name
  X509_set_issuer_name(cert, name); // Its self signed so set the issuer name to be the same as the subject.


  PEM_write_PrivateKey(stdout, key, NULL, NULL, 0, NULL, NULL);
  PEM_write_PUBKEY(stdout, key);

  if (!X509_sign(cert, key, EVP_sha1())) {
    perror("Error signing certificate\n");
    printf("Error code %lu\n", ERR_get_error());
    ERR_print_errors_fp(stderr);
    return;
  } else {
    PEM_write_X509(stdout, cert);

    fp = fopen(certFileName, "wb");
    if (fp != NULL) {
      PEM_write_X509(fp, cert);
    }
    fclose(fp);
    X509_free(cert);
  }
  return;
}

X509_REQ* generateCSR(EVP_PKEY *pk)
{
  X509_REQ *req;
  X509_NAME *name = NULL;

  if ((req = X509_REQ_new()) == NULL)
  {
    fprintf(stderr, "Failed to create new CSR");
    return NULL;
  }

  X509_REQ_set_pubkey(req, pk);
  name = X509_REQ_get_subject_name(req);

  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)"SG", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"192.168.1.103", -1, -1, 0);

  if (!X509_REQ_sign(req, pk, EVP_sha1()))
  {
    fprintf(stderr, "Failed to initialise CSR");
    return NULL;
  }

  FILE *csr = fopen(CSR_FILENAME, "wb");
  if (csr != NULL)
  {
    PEM_write_X509_REQ(csr, req);
    fclose(csr);
  }
  else
  {
    fprintf(stderr, "Failed to open csr file");
  }
  return req;
}

RSA* readPubKeyFromCert(char* certFileName) {
  X509 *cert = NULL;
  EVP_PKEY *pkey = NULL;
  RSA *rsa;

  cert = getCertFromFile(certFileName);
  pkey = getPubKeyFromCert(cert);
  rsa = EVP_PKEY_get1_RSA(pkey);
  return rsa;
}
