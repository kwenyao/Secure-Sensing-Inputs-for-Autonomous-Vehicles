#include "tpm.h"

void writeFile(const char *fileName, char *data) {
	FILE *fout;
	fout = fopen(fileName, "w");
	if (fout != NULL) {
		fputs(data, fout);
		printf("%s created\n", fileName);
	} else {
		printf("Error creating %s\n", fileName);
	}
	fclose(fout);
}

char* readFile(const char *fileName, long *fileLength) {
	FILE *fStream = fopen(fileName, "r");
	fseek(fStream, 0, SEEK_END);
	*fileLength = ftell(fStream);
	char *data = malloc(*fileLength);
	fseek(fStream, 0, SEEK_SET);
	if (data) {
		fread(data, 1, *fileLength, fStream);
		// printf("\nData read from %s:\n%s\n\n", fileName, data);
	} else {
		printf("Error opening %s!\n", fileName);
	}
	fclose(fStream);
	return data;
}

void printHex(unsigned char * msg, int size) {
	int i;
	for (i = 0; i < size; i++) {
		printf("%x", msg[i] >> 4);
		printf("%x", msg[i] & 0xf);
	}
	printf("\n");
}

tpmArgs preamble() {
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	TSS_RESULT result;
	tpmArgs tpm;
	tpm.hSRKPolicy = 0;

	//Pick the TPM you are talking to.
	// In this case, it is the system TPM (indicated with NULL).
	result = Tspi_Context_Create(&tpm.hContext);
	DBG("Create Context", result);
	result = Tspi_Context_Connect(tpm.hContext, NULL);
	DBG("Context Connect", result);
	// Get the TPM handle
	result = Tspi_Context_GetTpmObject(tpm.hContext, &tpm.hTPM);
	DBG("Get TPM Handle", result);
	// Get the SRK handle
	result = Tspi_Context_LoadKeyByUUID(tpm.hContext,
	                                    TSS_PS_TYPE_SYSTEM,
	                                    SRK_UUID,
	                                    &tpm.hSRK);
	DBG("Got the SRK handle", result);
	//Get the SRK policy
	result = Tspi_GetPolicyObject(tpm.hSRK,
	                              TSS_POLICY_USAGE,
	                              &tpm.hSRKPolicy);
	DBG("Got the SRK policy", result);
	//Then set the SRK policy to be the well known secret
	result = Tspi_Policy_SetSecret(tpm.hSRKPolicy,
	                               TSS_SECRET_MODE_PLAIN,
	                               SRK_PASSWORD_LENGTH,
	                               (BYTE*)SRK_PASSWORD);
	DBG("Set the SRK secret in its policy", result);
	return tpm;
}

void postlude(TSS_HPOLICY hSRKPolicy, TSS_HCONTEXT hContext) {
	Tspi_Policy_FlushSecret(hSRKPolicy);
	// Clean up
	Tspi_Context_Close(hContext);
	Tspi_Context_FreeMemory(hContext, NULL);
	// This frees up memory automatically allocated for you.
	Tspi_Context_Close(hContext);
	return;
}

TSS_HHASH createHash(TSS_HCONTEXT hContext, BYTE* data, UINT32 dataLength) {
	TSS_RESULT result;
	TSS_HHASH hHash;

	result = Tspi_Context_CreateObject(hContext,
	                                   TSS_OBJECT_TYPE_HASH,
	                                   TSS_HASH_SHA1,
	                                   &hHash);
	DBG("Create hash object", result);
	result = Tspi_Hash_UpdateHashValue(hHash, dataLength, data);
	DBG("Update hash value", result);
	return hHash;
}

BYTE* genNonce(TSS_HTPM hTPM, int nonceSize) {
	BYTE* nonce = malloc(nonceSize);
	Tspi_TPM_GetRandom(hTPM, nonceSize, &nonce);

	// print nonce DEBUG
	// printf("\nNONCE VALUE\n");
	// printHex(nonce, NONCE_LENGTH);
	// printf("\n");
	return nonce;
}

BYTE* RSAencrypt(TSS_HCONTEXT hContext, BYTE* data, UINT32 dataLength, UINT32* bindDataLength) {
	// Create bind key
	UINT32 pubKeyLength;
	BYTE *pubKey;
	TSS_HKEY hBindKey;
	TSS_RESULT result;

	pubKey = malloc(286);
	pubKeyLength = readPublicKey(OTHER_PUBLIC_KEY_FILENAME, &pubKey);
	// pubKey = CreateBindKey(hContext, hSRK, &pubKeyLength);

	TSS_FLAG initFlags = TSS_KEY_TYPE_BIND |
	                     TSS_KEY_SIZE_2048 |
	                     TSS_KEY_AUTHORIZATION |
	                     TSS_KEY_NOT_MIGRATABLE;

	result = Tspi_Context_CreateObject(hContext,
	                                   TSS_OBJECT_TYPE_RSAKEY,
	                                   initFlags, &hBindKey);
	DBG("Tspi_Context_CreateObject BindKey", result);

	// Feed bind key with public key
	result = Tspi_SetAttribData(hBindKey,
	                            TSS_TSPATTRIB_KEY_BLOB,
	                            TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
	                            pubKeyLength, pubKey);
	DBG("Set Public key into new key object", result);
	// Create data object
	TSS_HENCDATA hEncData;
	result = Tspi_Context_CreateObject(hContext,
	                                   TSS_OBJECT_TYPE_ENCDATA,
	                                   TSS_ENCDATA_BIND,
	                                   &hEncData);
	DBG("Create data object", result);

	// Bind data (AES KEY)
	result = Tspi_Data_Bind(hEncData, hBindKey,	dataLength,	data);
	DBG("Bind data", result);

	//Get the encrypted data out of the data object
	BYTE* rgbBoundData;
	result = Tspi_GetAttribData(hEncData,
	                            TSS_TSPATTRIB_ENCDATA_BLOB,
	                            TSS_TSPATTRIB_ENCDATABLOB_BLOB,
	                            bindDataLength, &rgbBoundData);
	DBG("Get encrypted data", result);

	return rgbBoundData;
}

BYTE* RSAdecrypt(TSS_HCONTEXT hContext, TSS_HKEY hSRK, BYTE* boundData, UINT32 boundDataLength, UINT32* unBoundDataLength) {
	//Create data object
	TSS_RESULT result;
	TSS_HENCDATA hEncData;
	result = Tspi_Context_CreateObject(hContext,
	                                   TSS_OBJECT_TYPE_ENCDATA,
	                                   TSS_ENCDATA_BIND,
	                                   &hEncData);
	DBG("Create data object", result);

	result = Tspi_SetAttribData(hEncData,
	                            TSS_TSPATTRIB_ENCDATA_BLOB,
	                            TSS_TSPATTRIB_ENCDATABLOB_BLOB,
	                            boundDataLength, boundData);

	TSS_UUID BIND_UUID = SIGN_KEY_UUID;
	TSS_HKEY hUnbindKey;
	result = Tspi_Context_GetKeyByUUID(hContext,
	                                   TSS_PS_TYPE_SYSTEM,
	                                   BIND_UUID,
	                                   &hUnbindKey);
	DBG("Get Unbinding key", result);

	result = Tspi_Key_LoadKey(hUnbindKey, hSRK);
	DBG("Loaded key", result);

	//Use the Unbinding key to decrypt the encrypted AES key
	BYTE* unBoundData;
	result = Tspi_Data_Unbind(hEncData, hUnbindKey, unBoundDataLength, &unBoundData);
	DBG("Unbound", result);

	return unBoundData;
}

BYTE* sign(TSS_HCONTEXT hContext, TSS_HKEY hSRK, BYTE* data, UINT32 dataLength) {
	//Variables
	TSS_RESULT result;
	TSS_UUID MY_UUID = SIGN_KEY_UUID;
	TSS_HKEY hSigningKey;
	TSS_HHASH hHash;
	//Output Variables
	BYTE *signature;
	UINT32 signatureLength;

	result = Tspi_Context_GetKeyByUUID(hContext,
	                                   TSS_PS_TYPE_SYSTEM,
	                                   MY_UUID,
	                                   &hSigningKey);
	DBG("Get key by UUID", result);

	// Load private key into TPM
	result = Tspi_Key_LoadKey(hSigningKey, hSRK);
	DBG("Load Key", result);

	// Create hash object
	hHash = createHash(hContext, data, dataLength);

	// Sign hash
	result = Tspi_Hash_Sign(hHash,
	                        hSigningKey,
	                        &signatureLength,
	                        &signature);
	DBG("Sign data", result);

	return signature;
}

BYTE* CreateBindKey(TSS_HCONTEXT hContext, TSS_HKEY hSRK, UINT32* pubKeySize) {
	TSS_RESULT result;
	TSS_HKEY hESS_Bind_Key;
	TSS_UUID MY_UUID = BACKUP_KEY_UUID;
	TSS_HPOLICY hBackup_Policy;
	TSS_FLAG initFlags;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	BYTE* pubKey;

	//Create policy for new key; pw = 123;
	result = Tspi_Context_CreateObject(hContext,
	                                   TSS_OBJECT_TYPE_POLICY,
	                                   0, &hBackup_Policy);
	DBG("Create a backup policy object", result);

	result = Tspi_Policy_SetSecret(hBackup_Policy,
	                               TSS_SECRET_MODE_PLAIN,
	                               3, (BYTE*)"123");
	DBG("Set backup policy object secret", result);

	initFlags = TSS_KEY_TYPE_BIND |
	            TSS_KEY_SIZE_2048 |
	            TSS_KEY_AUTHORIZATION |
	            TSS_KEY_NOT_MIGRATABLE;

	result = Tspi_Context_CreateObject(hContext,
	                                   TSS_OBJECT_TYPE_RSAKEY,
	                                   initFlags, &hESS_Bind_Key);
	DBG("Set the key's padding type", result);

	//Assign the key's policy to the key object
	result = Tspi_Policy_AssignToObject(hBackup_Policy, hESS_Bind_Key);
	DBG("Assign the key's policy to the key", result);

	//Create the key, with the SRK as its parent
	printf("Creating the key could take awhile\n");
	result = Tspi_Key_CreateKey(hESS_Bind_Key, hSRK, 0);
	DBG("Asking TP to create the key", result);

	//Register key
	result = Tspi_Context_RegisterKey(hContext,
	                                  hESS_Bind_Key,
	                                  TSS_PS_TYPE_SYSTEM,
	                                  MY_UUID,
	                                  TSS_PS_TYPE_SYSTEM,
	                                  SRK_UUID);
	DBG("Bind Key Registration", result);

	result = Tspi_Key_LoadKey(hESS_Bind_Key, hSRK);
	DBG("Load key into TPM", result);

	// Get public key
	result = Tspi_Key_GetPubKey(hESS_Bind_Key, pubKeySize, &pubKey);
	DBG("Get public key blob", result);

	return pubKey;
}

UINT32 readPublicKey(char* file, BYTE** pubKey) {
	long pubKeyStrSize;
	char *pubKeyStr = readFile(file, &pubKeyStrSize);
	UINT32 length;

	// Decode public key string to BYTE
	int arrSize = base64_dec_len(pubKeyStr, pubKeyStrSize);
	char *pubKeyArr = malloc(arrSize);
	// pubKey = malloc(arrSize);
	// printf("pubkeylength: %d\n", arrSize);
	length = base64_decode(pubKeyArr, pubKeyStr, pubKeyStrSize);
	*pubKey = (BYTE*)pubKeyArr;
	return length;
}

int isVerified(TSS_HCONTEXT hContext, BYTE* signature, UINT32 signatureLength, BYTE* data, UINT32 dataLength) {
	//Variables
	TSS_RESULT result;
	UINT32 otherPubKeyLength;
	BYTE *otherPubKey;
	TSS_FLAG initFlags;
	TSS_HKEY hVerifyKey;
	TSS_HHASH hHash;

	otherPubKey = malloc(286);
	otherPubKeyLength = readPublicKey(OTHER_PUBLIC_KEY_FILENAME, &otherPubKey);
	// printHex(pubKey, pubKeyLength);

	// Create hash object
	hHash = createHash(hContext, data, dataLength);

	// Create verify key
	initFlags = TSS_KEY_TYPE_SIGNING |
	            TSS_KEY_SIZE_2048 |
	            TSS_KEY_NO_AUTHORIZATION |
	            TSS_KEY_NOT_MIGRATABLE;

	result = Tspi_Context_CreateObject(hContext,
	                                   TSS_OBJECT_TYPE_RSAKEY,
	                                   initFlags,
	                                   &hVerifyKey);
	DBG("Create verify key object", result);
	if (otherPubKey == NULL) {
		printf("pubkey is null");
	}
	result = Tspi_SetAttribData(hVerifyKey,
	                            TSS_TSPATTRIB_KEY_BLOB,
	                            TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
	                            otherPubKeyLength,
	                            otherPubKey);
	DBG("Set attribute for verify key", result);

	// Verify signature
	result = Tspi_Hash_VerifySignature(hHash, hVerifyKey, signatureLength, signature);
	DBG("Verify signature", result);
	if (result != TSS_SUCCESS) {
		return 0;
	} else {
		return 1;
	}
}
