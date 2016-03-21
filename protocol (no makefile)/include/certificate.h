#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include "constant.h"

EVP_PKEY* 	loadKeyFromFile(char *fileName);
void 		deleteKeyFile(char *fileName);

X509* 		getCertFromFile(char* certName);
EVP_PKEY* 	getPubKeyFromCert(X509 *cert);
int 		verifyCert(char* certFile, char* CAcertFile);

#endif /* CERTIFICATE_H */