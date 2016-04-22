#ifndef TPM_H
#define TPM_H

#include "certificate.h"
#include "fileio.h"

#include <openssl/crypto.h>
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

#define TPM_ENGINE_EX_DATA_UNINIT -1

typedef struct {
	TSS_HKEY hKey;
	TSS_HHASH hHash;
	TSS_HENCDATA hEncData;
	UINT32 encScheme;
	UINT32 sigScheme;
} rsa_app_data;

typedef struct {
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_HKEY hSRK;
	TSS_HPOLICY hSRKPolicy;
	BYTE wks[20]; //For the well known secret
} tpmArgs;

RSA *loadRSAkey(TSS_HCONTEXT hContext, TSS_HKEY hSRK);

int createRSAObj(TSS_HCONTEXT hContext, RSA *rsa, TSS_HKEY hSRK);
void ERR_TSS_error(int function, int reason, char *file, int line);
TSS_HKEY getRSAEncryptKey(TSS_HCONTEXT hContext, TSS_HKEY hSRK);

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
BYTE* RSAencrypt(BYTE* data, UINT32 dataLength, RSA* rsa, UINT32* bindDataLength);
BYTE* RSAdecrypt(TSS_HCONTEXT hContext, TSS_HKEY hSRK, BYTE* encrypted, UINT32 encryptedLength, UINT32* decryptedLength);

// SIGNING & VERIFYING
BYTE* sign(TSS_HCONTEXT hContext, TSS_HKEY hSRK, BYTE* data, UINT32 dataLength);
gboolean verifySHA1WithRSA(RSA *rsa, gpointer data, gsize data_len, gpointer sig, gsize sig_len);
int isVerified(BYTE *signature, UINT32 signatureLength, BYTE *data, UINT32 dataLength, RSA *rsa);

// LOADING/UNREGISTERING KEY
void loadPrivateKey(TSS_HCONTEXT hContext, TSS_HKEY hSRK);
void unregisterOldKey(tpmArgs tpm, TSS_UUID KEY_UUID);

#endif /* TPM_H */
