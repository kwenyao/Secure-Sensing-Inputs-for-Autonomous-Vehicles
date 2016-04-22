#include "tpm.h"

#define A_SIGN_KEY_UUID SIGN_KEY_UUID

int main(int argc, char **argv) {
	tpmArgs tpm;
	EVP_PKEY *akey = NULL;
	X509_REQ *acsr = NULL;

	tpm = preamble();

	createKey(tpm, (TSS_UUID) A_SIGN_KEY_UUID, (char *) KEY_FILENAME);

	akey = loadKeyFromFile(KEY_FILENAME);
	deleteKeyFile(KEY_FILENAME);

	acsr = generateCSR(akey);
	EVP_PKEY_free(akey);
	X509_REQ_free(acsr);
	Tspi_Context_Close(tpm.hContext);
	return 0;
}

