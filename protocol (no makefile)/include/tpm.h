#ifndef TPM_H
#define TPM_H

#include "constant.h"
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

tpmArgs preamble();
void postlude(TSS_HPOLICY hSRKPolicy, TSS_HCONTEXT hContext);

BYTE* genNonce(TSS_HTPM hTPM, int nonceSize);

// RSA ENCRYPTING & DECRYPTING
BYTE* RSAencrypt(BYTE* data, UINT32 dataLength, UINT32* bindDataLength);
BYTE* RSAdecrypt(TSS_HCONTEXT hContext, TSS_HKEY hSRK, BYTE* encrypted, UINT32 encryptedLength, UINT32* decryptedLength);

// SIGNING & VERIFYING
TSS_HHASH createHash(TSS_HCONTEXT hContext, BYTE* data, UINT32 dataLength);
BYTE* sign(TSS_HCONTEXT hContext, TSS_HKEY hSRK, BYTE* data, UINT32 dataLength);
gboolean verifySHA1WithRSA(RSA *rsa, gpointer data, gsize data_len, gpointer sig, gsize sig_len);
int isVerified(tpmArgs tpm, BYTE* signature, UINT32 signatureLength, BYTE* data, UINT32 dataLength);

void loadPrivateKey(TSS_HCONTEXT hContext, TSS_HKEY hSRK);
void unregisterOldKey(tpmArgs tpm, TSS_UUID KEY_UUID);

#endif /* TPM_H */
