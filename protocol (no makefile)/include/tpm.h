#ifndef TPM_H
#define TPM_H

#include "certificate.h"

typedef struct {
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_HKEY hSRK;
	TSS_HPOLICY hSRKPolicy;
	BYTE wks[20]; //For the well known secret
} tpmArgs;


//READ WRITE
void printHex(unsigned char * msg, int size);

//TPM SETUP & TEARDOWN
tpmArgs preamble();
void postlude(TSS_HPOLICY hSRKPolicy, TSS_HCONTEXT hContext);

//GENERATION
BYTE* genNonce(TSS_HTPM hTPM, int nonceSize);
void createKey(tpmArgs tpm, TSS_UUID keyUUID, char *keyFileName); //Create a key in specified UUID and save it to specified file
TSS_HHASH createHash(TSS_HCONTEXT hContext, BYTE* data, UINT32 dataLength);

// RSA ENCRYPTING & DECRYPTING
BYTE* RSAencrypt(BYTE* data, UINT32 dataLength, UINT32* bindDataLength);
BYTE* RSAdecrypt(TSS_HCONTEXT hContext, TSS_HKEY hSRK, BYTE* encrypted, UINT32 encryptedLength, UINT32* decryptedLength);

// SIGNING & VERIFYING
BYTE* sign(TSS_HCONTEXT hContext, TSS_HKEY hSRK, BYTE* data, UINT32 dataLength);
gboolean verifySHA1WithRSA(RSA *rsa, gpointer data, gsize data_len, gpointer sig, gsize sig_len);
int isVerified(tpmArgs tpm, BYTE* signature, UINT32 signatureLength, BYTE* data, UINT32 dataLength);

// LOADING/UNREGISTERING KEY
void loadPrivateKey(TSS_HCONTEXT hContext, TSS_HKEY hSRK);
void unregisterOldKey(tpmArgs tpm, TSS_UUID KEY_UUID);

#endif /* TPM_H */
