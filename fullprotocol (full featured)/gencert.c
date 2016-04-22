#include "tpm.h"

int main(int argc, char **argv) {
	tpmArgs tpm;
	EVP_PKEY *key;

	tpm = preamble();
	createKey(tpm, (TSS_UUID)SIGN_KEY_UUID, CA_KEY_FILENAME);

	key = loadKeyFromFile(CA_KEY_FILENAME);
	printf("done\n");
	generateCertificate(key, CA_CERT_FILENAME);

	EVP_PKEY_free(key);
	Tspi_Context_Close(tpm.hContext);
	return 0;
}
