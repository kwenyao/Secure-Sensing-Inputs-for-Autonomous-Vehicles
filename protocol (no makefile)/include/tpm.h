#ifndef TPM_H
#define TPM_H

#include "constant.h"

typedef struct {
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_HKEY hSRK;
	TSS_HPOLICY hSRKPolicy;
	BYTE wks[20]; //For the well known secret
} tpmArgs;


//READ WRITE
void writeFile(const char *fileName, char *data);
char* readFile(const char *fileName, long *fileLength);
void printHex(unsigned char * msg, int size);

tpmArgs preamble();
void postlude(TSS_HPOLICY hSRKPolicy, TSS_HCONTEXT hContext);
TSS_HHASH createHash(TSS_HCONTEXT hContext, BYTE* data, UINT32 dataLength);
BYTE* genNonce(TSS_HTPM hTPM, int nonceSize);
BYTE* RSAencrypt(TSS_HCONTEXT hContext, BYTE* data, UINT32 dataLength, UINT32* bindDataLength);
BYTE* RSAdecrypt(TSS_HCONTEXT hContext, TSS_HKEY hSRK, BYTE* boundData, UINT32 boundDataLength, UINT32* unBoundDataLength);
BYTE* sign(TSS_HCONTEXT hContext, TSS_HKEY hSRK, BYTE* data, UINT32 dataLength);
BYTE* CreateBindKey(TSS_HCONTEXT hContext, TSS_HKEY hSRK, UINT32* pubKeySize);
UINT32 readPublicKey(char* file, BYTE** pubKey);
int isVerified(TSS_HCONTEXT hContext, BYTE* signature, UINT32 signatureLength, BYTE* data, UINT32 dataLength);


#endif /* TPM_H */
