#include "constant.h"

#define SRK_PW "hello"
// #define SIGNATURE_FILENAME "signature.dat"
// #define DATA_FILENAME "file.dat"

void printHex(unsigned char * msg, int size);
void writeFile(const char *fileName, char *data);

int main(int argc, char **argv) {

	/*******************************
	 * PREAMBLE
	 *******************************/
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_RESULT result;
	TSS_HKEY hSRK;
	TSS_HPOLICY hSRKPolicy = 0;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;

	//Pick the TPM you are talking to.
	// In this case, it is the system TPM (indicated with NULL).
	result = Tspi_Context_Create(&hContext);
	DBG("Create Context", result);
	result = Tspi_Context_Connect(hContext, NULL);
	DBG("Context Connect", result);
	// Get the TPM handle
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	DBG("Get TPM Handle", result);
	// Get the SRK handle
	result = Tspi_Context_LoadKeyByUUID(hContext,
	                                    TSS_PS_TYPE_SYSTEM,
	                                    SRK_UUID,
	                                    &hSRK);
	DBG("Got the SRK handle", result);
	//Get the SRK policy
	result = Tspi_GetPolicyObject(hSRK,
	                              TSS_POLICY_USAGE,
	                              &hSRKPolicy);
	DBG("Got the SRK policy", result);
	//Then set the SRK policy to be the well known secret
	result = Tspi_Policy_SetSecret(hSRKPolicy,
	                               TSS_SECRET_MODE_PLAIN,
	                               SRK_PASSWORD_LENGTH,
	                               (BYTE*)SRK_PASSWORD);
	DBG("Set the SRK secret in its policy", result);

	/*******************************
	* UNREGISTERING OLD KEY
	*******************************/
	TSS_HKEY hSigningKey;
	TSS_UUID MY_UUID = SIGN_KEY_UUID;

	result = Tspi_Context_GetKeyByUUID(hContext,
	                                   TSS_PS_TYPE_SYSTEM,
	                                   MY_UUID,
	                                   &hSigningKey);
	DBG("Get key handle", result);
	result = Tspi_Context_UnregisterKey(hContext,
	                                    TSS_PS_TYPE_SYSTEM,
	                                    MY_UUID,
	                                    &hSigningKey);
	DBG("Key unregistered", result);

	/*******************************
	 * CREATE SIGNING KEY
	 *******************************/
	// Signing key variables
	TSS_FLAG initFlags;
	BYTE *pubKey;
	UINT32 pubKeySize;

	initFlags = TSS_KEY_TYPE_LEGACY |
	            TSS_KEY_SIZE_2048 |
	            TSS_KEY_NO_AUTHORIZATION |
	            TSS_KEY_NOT_MIGRATABLE;
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hSigningKey);
	DBG("Create key object", result);

	//Set padding type
	result = Tspi_SetAttribUint32(hSigningKey,
	                              TSS_TSPATTRIB_KEY_INFO,
	                              TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
	                              PADDING_SCHEME);
	DBG("Set the key's padding type", result);

	result = Tspi_Key_CreateKey(hSigningKey, hSRK, 0);
	DBG("Create key in TPM", result);
	result = Tspi_Context_RegisterKey(hContext,
	                                  hSigningKey,
	                                  TSS_PS_TYPE_SYSTEM,
	                                  MY_UUID,
	                                  TSS_PS_TYPE_SYSTEM,
	                                  SRK_UUID);
	DBG("Key Registration", result);

	result = Tspi_Key_LoadKey(hSigningKey, hSRK);
	DBG("Load key into TPM", result);

	// Get public key
	result = Tspi_Key_GetPubKey(hSigningKey, &pubKeySize, &pubKey);
	DBG("Get public key blob", result);

	char *pubKeyStr = malloc(base64_enc_len(pubKeySize));
	base64_encode(pubKeyStr, (char*)pubKey, pubKeySize);
	writeFile(PUBLIC_KEY_FILENAME, pubKeyStr);

	Tspi_Policy_FlushSecret(hSRKPolicy);
	/*******************************
	 * POSTLUDE
	 *******************************/
	// Clean up
	Tspi_Context_Close(hContext);
	Tspi_Context_FreeMemory(hContext, NULL);
	// This frees up memory automatically allocated for you.
	Tspi_Context_Close(hContext);

	return 0;
}


void printHex(unsigned char * msg, int size) {
	int i;
	for (i = 0; i < size; i++) {
		printf("%x", msg[i] >> 4);
		printf("%x", msg[i] & 0xf);
	}
	printf("\n");
}

void writeFile(const char *fileName, char *data) {
	FILE *fout;
	fout = fopen(fileName, "w");
	if (fout != NULL) {
		fputs(data, fout);
		printf("%s created\n", fileName);
		fclose(fout);
	} else {
		printf("Error creating %s\n", fileName);
	}
}
