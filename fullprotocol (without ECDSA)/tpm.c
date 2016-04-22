#include "tpm.h"
#include "fileio.h"

void printHex(unsigned char *msg, int size) {
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

BYTE* genNonce(TSS_HTPM hTPM, int nonceSize) {
	BYTE* nonce = malloc(nonceSize);
	Tspi_TPM_GetRandom(hTPM, nonceSize, &nonce);
	return nonce;
}

void createKey(tpmArgs tpm, TSS_UUID keyUUID, char *keyFileName) {
	BYTE				*blob;
	UINT32				blob_size;
	BIO 				*outb;
	ASN1_OCTET_STRING 	*blob_str;
	unsigned char		*blob_asn1 = NULL;
	int 				asn1_len;

	TSS_FLAG initFlags;
	TSS_HKEY hKey;
	TSS_HPOLICY keyMigrationPolicy;
	TSS_RESULT result;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;

	unregisterOldKey(tpm, keyUUID);

	initFlags = TSS_KEY_TYPE_LEGACY |
	            TSS_KEY_SIZE_2048 |
	            TSS_KEY_NO_AUTHORIZATION |
	            TSS_KEY_MIGRATABLE;


	result = Tspi_Context_CreateObject(tpm.hContext,
	                                   TSS_OBJECT_TYPE_RSAKEY,
	                                   initFlags,
	                                   &hKey);
	DBG("Create key object", result);

	if ((result = Tspi_Context_CreateObject(tpm.hContext,
	                                        TSS_OBJECT_TYPE_POLICY,
	                                        TSS_POLICY_MIGRATION,
	                                        &keyMigrationPolicy))) {
		DBG("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(tpm.hContext);
		exit(result);
	}

	if ((result = Tspi_Policy_SetSecret(keyMigrationPolicy,
	                                    TSS_SECRET_MODE_NONE,
	                                    0, NULL))) {
		DBG("Tspi_Policy_SetSecret", result);
		Tspi_Context_Close(tpm.hContext);
		exit(result);
	}

	if ((result = Tspi_Policy_AssignToObject(keyMigrationPolicy, hKey))) {
		DBG("Tspi_Policy_AssignToObject", result);
		Tspi_Context_CloseObject(tpm.hContext, hKey);
		Tspi_Context_Close(tpm.hContext);
		exit(result);
	}

	result = Tspi_SetAttribUint32(hKey,
	                              TSS_TSPATTRIB_KEY_INFO,
	                              TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
	                              ENCRYPTION_SCHEME);
	//Set padding type
	result = Tspi_SetAttribUint32(hKey,
	                              TSS_TSPATTRIB_KEY_INFO,
	                              TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
	                              PADDING_SCHEME);
	DBG("Set the key's padding type", result);


	result = Tspi_Key_CreateKey(hKey, tpm.hSRK, 0);
	DBG("Create key in TPM", result);
	result = Tspi_Context_RegisterKey(tpm.hContext,
	                                  hKey,
	                                  TSS_PS_TYPE_SYSTEM,
	                                  keyUUID,
	                                  TSS_PS_TYPE_SYSTEM,
	                                  SRK_UUID);
	DBG("Key Registration", result);

	result = Tspi_Key_LoadKey(hKey, tpm.hSRK);
	DBG("Load key into TPM", result);

	result = Tspi_GetAttribData(hKey,
	                            TSS_TSPATTRIB_KEY_BLOB,
	                            TSS_TSPATTRIB_KEYBLOB_BLOB,
	                            &blob_size,
	                            &blob);
	DBG("Get key blob", result);

	if ((outb = BIO_new_file(keyFileName, "w")) == NULL) {
		fprintf(stderr, "Error opening file for write: %s\n", keyFileName);
		Tspi_Context_CloseObject(tpm.hContext, hKey);
		Tspi_Context_Close(tpm.hContext);
		exit(-1);
	}
	blob_str = ASN1_OCTET_STRING_new();
	if (!blob_str) {
		fprintf(stderr, "Error allocating ASN1_OCTET_STRING\n");
		Tspi_Context_CloseObject(tpm.hContext, hKey);
		Tspi_Context_Close(tpm.hContext);
		exit(-1);
	}
	ASN1_STRING_set(blob_str, blob, blob_size);
	asn1_len = i2d_ASN1_OCTET_STRING(blob_str, &blob_asn1);
	PEM_write_bio(outb, "TSS KEY BLOB", "", blob_asn1, asn1_len);

	BIO_free(outb);

	Tspi_Context_CloseObject (tpm.hContext, hKey);

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

BYTE* RSAencrypt(BYTE* data, UINT32 dataLength, RSA *rsa, UINT32* bindDataLength) {
	BYTE *encrypt = malloc(RSA_size(rsa));
	int encryptLength;
	encryptLength = RSA_public_encrypt((int)dataLength,
	                                   (unsigned char*)data,
	                                   (unsigned char*)encrypt,
	                                   rsa,
	                                   RSA_PKCS1_PADDING);
	*bindDataLength = encryptLength;
	if (encryptLength < 0) {
		PRINTDEBUG("Error encrypting message");
		return NULL;
	}
	return encrypt;
}

BYTE* RSAdecrypt(TSS_HCONTEXT hContext, TSS_HKEY hSRK, BYTE* encrypt,
                 UINT32 encryptedLength, UINT32* decryptedLength) {
	BYTE *decrypt = NULL;
	EVP_PKEY *key;
	RSA *rsa = NULL;

	loadPrivateKey(hContext, hSRK);
	key = loadKeyFromFile(KEY_FILENAME);
	deleteKeyFile(KEY_FILENAME);
	rsa = EVP_PKEY_get1_RSA(key);

	decrypt = malloc(RSA_size(rsa));
	int len = RSA_private_decrypt((int)encryptedLength,
	                              (unsigned char*)encrypt,
	                              (unsigned char*)decrypt,
	                              rsa,
	                              RSA_PKCS1_PADDING);
	*decryptedLength = (UINT32) len;
	return decrypt;
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

gboolean verifySHA1WithRSA(RSA *rsa, gpointer data, gsize data_len,
                           gpointer sig, gsize sig_len) {
	gboolean ret = FALSE;
	gsize msg_buf_size = 512;
	gchar msg_buf[msg_buf_size];

	/* calculated digest of the provided data */
	guint8 digest[256];
	gsize digest_size = RSA_public_decrypt (sig_len, sig, digest, rsa, RSA_PKCS1_PADDING);

	guint8 digest_info_der[20];
	SHA1 (data, data_len, &digest_info_der[0]);

	if (digest_size == -1) {
		PRINTDEBUG("digest size -1");
		ERR_error_string_n (ERR_get_error (), msg_buf, sizeof (msg_buf));
		g_critical (G_STRLOC ": %s", msg_buf);
		goto done;
	}

	if (digest_size == sizeof(digest_info_der) && memcmp (digest_info_der, digest, digest_size) == 0) {
		ret = TRUE;
	}

done:
	return ret;
}

int isVerified(BYTE *signature, UINT32 signatureLength, BYTE *data, UINT32 dataLength, RSA *rsa) {
	gboolean verified = verifySHA1WithRSA(rsa,
	                                      (gpointer)data,
	                                      (gsize)dataLength,
	                                      (gpointer)signature,
	                                      (gsize)signatureLength);
	if (verified == TRUE) {
		return 1;
	} else {
		return 0;
	}
}

int createRSAObj(TSS_HCONTEXT hContext, RSA *rsa, TSS_HKEY hSRK) {
	int  ex_app_data = TPM_ENGINE_EX_DATA_UNINIT;
	TSS_RESULT result;
	UINT32 pubkey_len, encScheme, sigScheme;
	BYTE *pubkey;
	rsa_app_data *app_data;

	TSS_HKEY hKey;
	TSS_UUID ENCRYPT_UUID = SIGN_KEY_UUID;
	result = Tspi_Context_GetKeyByUUID(hContext,
	                                   TSS_PS_TYPE_SYSTEM,
	                                   ENCRYPT_UUID,
	                                   &hKey);
	DBG("Get key by UUID", result);
	result = Tspi_Key_LoadKey(hKey, hSRK);
	DBG("Loaded key", result);

	result = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	                              TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
	                              &encScheme);
	DBG("get enc scheme", result);

	result = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
	                              TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
	                              &sigScheme);
	DBG("get sig scheme", result);

	/* pull out the public key and put it into the RSA object */
	result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
	                            TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
	                            &pubkey_len, &pubkey);
	DBG("get modulus", result);

	rsa->n = BN_bin2bn(pubkey, pubkey_len, rsa->n);

	Tspi_Context_FreeMemory(hContext, pubkey);

	/* set e in the RSA object */
	rsa->e = BN_new();

	BN_set_word(rsa->e, 65537);

	app_data = OPENSSL_malloc(sizeof(rsa_app_data));

	DBG("Setting hKey(0x%x) in RSA object", hKey);
	DBG("Setting encScheme(0x%x) in RSA object", encScheme);
	DBG("Setting sigScheme(0x%x) in RSA object", sigScheme);

	memset(app_data, 0, sizeof(rsa_app_data));
	app_data->hKey = hKey;
	app_data->encScheme = encScheme;
	app_data->sigScheme = sigScheme;
	RSA_set_ex_data(rsa, ex_app_data, app_data);

	return 1;
}

TSS_HKEY getRSAEncryptKey(TSS_HCONTEXT hContext, TSS_HKEY hSRK) {
	TSS_HKEY hKey;
	TSS_RESULT result;
	TSS_UUID ENCRYPT_UUID = SIGN_KEY_UUID;
	result = Tspi_Context_GetKeyByUUID(hContext,
	                                   TSS_PS_TYPE_SYSTEM,
	                                   ENCRYPT_UUID,
	                                   &hKey);
	DBG("Get key by UUID", result);
	result = Tspi_Key_LoadKey(hKey, hSRK);
	DBG("Loaded key", result);
	return hKey;
}

void loadPrivateKey(TSS_HCONTEXT hContext, TSS_HKEY hSRK) {
	ASN1_OCTET_STRING *blob_str;
	BYTE *blob;
	BIO *outb;
	int asn1_len;
	TSS_HKEY hKey;
	TSS_RESULT result;
	TSS_UUID BIND_UUID = SIGN_KEY_UUID;
	UINT32 blob_size;
	unsigned char *blob_asn1 = NULL;

	result = Tspi_Context_GetKeyByUUID(hContext,
	                                   TSS_PS_TYPE_SYSTEM,
	                                   BIND_UUID,
	                                   &hKey);
	DBG("Get key by UUID", result);

	result = Tspi_Key_LoadKey(hKey, hSRK);
	DBG("Loaded key", result);

	result = Tspi_GetAttribData(hKey,
	                            TSS_TSPATTRIB_KEY_BLOB,
	                            TSS_TSPATTRIB_KEYBLOB_BLOB,
	                            &blob_size,
	                            &blob);
	DBG("Get key blob", result);

	if ((outb = BIO_new_file(KEY_FILENAME, "w")) == NULL) {
		fprintf(stderr, "Error opening file for write: %s\n", KEY_FILENAME);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(-1);
	}
	blob_str = ASN1_OCTET_STRING_new();
	if (!blob_str) {
		fprintf(stderr, "Error allocating ASN1_OCTET_STRING\n");
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(-1);
	}
	ASN1_STRING_set(blob_str, blob, blob_size);
	asn1_len = i2d_ASN1_OCTET_STRING(blob_str, &blob_asn1);
	PEM_write_bio(outb, "TSS KEY BLOB", "", blob_asn1, asn1_len);

	BIO_free(outb);

	Tspi_Context_CloseObject (hContext, hKey);
}

void unregisterOldKey(tpmArgs tpm, TSS_UUID KEY_UUID) {
	TSS_HKEY hOldKey;
	TSS_RESULT result;

	result = Tspi_Context_GetKeyByUUID(tpm.hContext,
	                                   TSS_PS_TYPE_SYSTEM,
	                                   KEY_UUID,
	                                   &hOldKey);
	DBG("Get key handle", result);
	result = Tspi_Context_UnregisterKey(tpm.hContext,
	                                    TSS_PS_TYPE_SYSTEM,
	                                    KEY_UUID,
	                                    &hOldKey);
	DBG("Key unregistered", result);
}

RSA *loadRSAkey(TSS_HCONTEXT hContext, TSS_HKEY hSRK)
{
	TSS_UUID BIND_UUID = SIGN_KEY_UUID;
	TSS_HKEY hKey;
	TSS_RESULT result;
	BYTE *blob;
	UINT32 blob_size;
	RSA *rsa = NULL;

	result = Tspi_Context_GetKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, BIND_UUID, &hKey);
	DBG("Get key by UUID", result);

	result = Tspi_Key_LoadKey(hKey, hSRK);
	DBG("Loaded key", result);

	result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB, &blob_size, &blob);
	DBG("Get key blob", result);
	printf("debug loadRSAkey:\n");
	printf("blob_size: %d\n", blob_size);
	printf("blob: ");
	printHex(blob, blob_size);
	const unsigned char *p = (unsigned char *) blob;
	rsa = d2i_RSAPrivateKey(NULL, &p, (long) blob_size);
	if (rsa == NULL)
	{
		printf("d2i_RSAPrivateKey failed\n");
	}

	Tspi_Context_CloseObject (hContext, hKey);
	return rsa;
}