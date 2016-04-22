#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include "constant.h"

EVP_PKEY* 	loadKeyFromFile(char *fileName);
void 		deleteKeyFile(char *fileName);

X509* 		getCertFromFile(char* certName);
EVP_PKEY* 	getPubKeyFromCert(X509 *cert);
int 		verifyCert(char* certFile, char* CAcertFile);

void generateCertificate(EVP_PKEY *key, char *certFileName);
X509_REQ* generateCSR(EVP_PKEY *pk);

#endif /* CERTIFICATE_H */