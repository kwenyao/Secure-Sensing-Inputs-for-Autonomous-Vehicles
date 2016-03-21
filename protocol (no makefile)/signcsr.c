#include "certificate.h"

EVP_PKEY* loadAKey(char* fileName);
void signCSR (char *CSRfile, char *CAfile, char *CAkeyfile);

int main()
{
	signCSR(CSR_FILENAME, CA_CERT_FILENAME, CA_KEY_FILENAME);
	return 0;
}

void signCSR (char *CSRfile, char *CAfile, char *CAkeyfile)
{
	EVP_PKEY *pkey = NULL;
	X509 *x = NULL, *ssl_cert = NULL;
	X509_STORE *store;

	FILE *csr = fopen(CSRfile, "r");
	X509_REQ *req = PEM_read_X509_REQ(csr, NULL, 0, NULL);
	fclose(csr);
	if (req == NULL)
	{
		X509_REQ_free(req);
		fprintf(stderr, "Failed to load CSR from file");
		return;
	}

	X509 *cacert = getCertFromFile(CAfile);
	EVP_PKEY *cakey = loadKeyFromFile(CAkeyfile);

	pkey = X509_REQ_get_pubkey(req);
	if (pkey == NULL)
	{
		fprintf(stderr, "Failed to get pubkey from CSR");
		return;
	}
	if (X509_REQ_verify(req, pkey) < 0)
	{
		fprintf(stderr, "Failed to verify pubkey from CSR");
		goto ret1;
	}

	store = X509_STORE_new();
	X509_STORE_set_default_paths(store);
	X509_STORE_add_cert(store, cacert);

	x = X509_new();
	if (x == NULL)
	{
		fprintf(stderr, "Failed to initialise temp cert");
		goto ret1;
	}
	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * 10);
	X509_set_pubkey(x, pkey);

	if (!X509_set_subject_name(x, req->req_info->subject))
	{
		fprintf(stderr, "Failed to set subject name");
		goto ret2;
	}
	if (!X509_set_issuer_name(x, X509_get_subject_name(cacert)))
	{
		fprintf(stderr, "Failed to set issuer name");
		goto ret3;
	}

	X509_STORE_CTX *xsc = X509_STORE_CTX_new();

	if (!X509_STORE_CTX_init(xsc, store, x, NULL))
	{
		fprintf(stderr, "Failed to initialise xsc");
		goto ret3;
	}

	if (!X509_sign(x, cakey, EVP_sha1()))
	{
		fprintf(stderr, "Failed to sign CSR");
		goto ret3;
	}

	if ((ssl_cert = X509_dup(x)) == NULL)
	{
		fprintf(stderr, "Failed to duplicate x");
		goto ret3;
	}


	/* WRITE CA-SIGNED CERT */
	PEM_write_X509(stdout, ssl_cert);

	FILE* fp = fopen(CERT_FILENAME, "wb");
	if (fp != NULL) {
		PEM_write_X509(fp, ssl_cert);
	}
	fclose(fp);

	/* CLOSING */
	X509_free(ssl_cert);
ret3:
	X509_STORE_CTX_cleanup(xsc);
ret2:
	X509_free(x);
	X509_STORE_free(store);
ret1:
	X509_REQ_free(req);
	EVP_PKEY_free(pkey);
	EVP_PKEY_free(cakey);
	X509_free(cacert);
}