#ifndef TPM_H
#define TPM_H

// #include <argp.h>
// #include <assert.h>
// #include <sys/types.h>
// #include <sys/stat.h>

// #include <stdio.h>
// #include <stddef.h>
// #include <string.h>
// #include <stdlib.h>

// #include <unistd.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <netdb.h>

// #include <tss/tss_error.h>
// #include <tss/platform.h>
// #include <tss/tss_defines.h>
// #include <tss/tss_typedef.h>
// #include <tss/tss_structs.h>
// #include <tss/tspi.h>
// #include <trousers/trousers.h>
// #include "base64.h"
#include "constant.h"

//CONSTANTS
// #define NONCE_LENGTH 7
// #define SIGN_KEY_UUID {0,0,0,0,0,{0,0,0,2,11}}
// #define BACKUP_KEY_UUID {0,0,0,0,0,{0,0,0,2,10}}
// #define PADDING_SCHEME TSS_SS_RSASSAPKCS1V15_SHA1
// #define DEBUG 0
// #define DBG(message, tResult) if(DEBUG){printf("Line %d, %s) %s returned 0x%08x. %s.\n", __LINE__, __FUNCTION__, message, tResult, (char *)Trspi_Error_String(tResult));}
// #define SIGNATURE_FILENAME "/home/debian/fullprotocol/signature.dat"
// #define PUBLIC_KEY_FILENAME "/home/debian/fullprotocol/signingkey.pub"
// #define SIGNATURE_LENGTH 256
// #define ENCRYPTED_AES_KEY_LENGTH 256
// #define ECC_PUBKEY_LENGTH 65
// #define ENCRYPTED_ECC_PUBKEY_LENGTH ECC_PUBKEY_LENGTH

// #define MESSAGE_RECEIVED EXIT_SUCCESS

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
