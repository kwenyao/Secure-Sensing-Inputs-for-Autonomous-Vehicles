#include <argp.h>
#include <assert.h>
#include "cli_commands.h"
#include "config.h"
#include <string.h>
#include <libcryptoauth.h>
#include "../driver/personalize.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>
#include <unistd.h>
#include "/home/debian/authentication/base64.cpp" /*to be changed*/

//TPM
#define NONCE_LENGTH 4
#define SIGN_KEY_UUID {0,0,0,0,0,{0,0,0,2,11}}
#define BACKUP_KEY_UUID {0,0,0,0,0,{0,0,0,2,10}}
#define PADDING_SCHEME TSS_SS_RSASSAPKCS1V15_SHA1
#define DEBUG 1
#define DBG(message, tResult) if(DEBUG){printf("Line %d, %s) %s returned 0x%08x. %s.\n", __LINE__, __FUNCTION__, message, tResult, (char *)Trspi_Error_String(tResult));}
#define SIGNATURE_FILENAME "/home/debian/Full Protocol Implementation/signature.dat"
#define PUBLIC_KEY_FILENAME "/home/debian/Full Protocol Implementation/signingkey.pub"
#define SIGNATURE_LENGTH 256

//ECC
#define FILENAME_INPUT "/home/debian/EClet3/Files/file.txt"
#define FILENAME_SIGNATURE "/home/debian/EClet3/Files/signature.txt"
#define FILENAME_PUBLICKEY "/home/debian/EClet3/Files/pubkey.txt"
#define INPUT "Hello World"
#define NUM_OF_LOOPS 100

//READ WRITE FUNCTIONS
void printHex(unsigned char * msg, int size);
void writeFile(const char *fileName, char *data);
char* readFile(const char *fileName, long *fileLength);
char* read_file(char* file_name);

//TPM FUNCTIONS
TSS_HHASH createHash(TSS_HCONTEXT hContext, BYTE* data, UINT32 dataLength);
BYTE* genNonce(TSS_HTPM hTPM);
BYTE* sign(TSS_HCONTEXT hContext, TSS_HKEY hSRK, BYTE* data, UINT32 dataLength, UINT32* signatureLength);
BYTE* CreateBindKey(TSS_HCONTEXT hContext, TSS_HKEY hSRK, UINT32* pubKeySize);
UINT32 readPublicKey(char* file, BYTE** pubKey);
int isVerified(TSS_HCONTEXT hContext, BYTE* signature, UINT32 signatureLength, BYTE* data, UINT32 dataLength);

//ECC FUNCTIONS
int ecc_gen_key();
int ecc_verify(struct lca_octet_buffer signature);
struct lca_octet_buffer ecc_sign();

void printHex(unsigned char * msg, int size){
	int i;
	for (i=0; i<size; i++){
		printf("%x",msg[i]>>4);
		printf("%x",msg[i]&0xf);
	}
	printf("\n");
}

void writeFile(const char *fileName, char *data){
	FILE *fout;
	fout = fopen(fileName, "w");
	if(fout != NULL){
		fputs(data, fout);
		printf("%s created\n", fileName);
		fclose(fout);
	} else {
		printf("Error creating %s\n", fileName);
	}
}

char* readFile(const char *fileName, long *fileLength){
	FILE *fStream = fopen(fileName, "r");
	fseek(fStream, 0, SEEK_END);
	*fileLength = ftell(fStream);
	char *data = malloc(*fileLength);
	fseek(fStream, 0, SEEK_SET);
	if(data){
		fread(data, 1, *fileLength, fStream);
		// printf("\nData read from %s:\n%s\n\n", fileName, data);
	} else {
		printf("Error opening %s!\n", fileName);
	}
	fclose(fStream);
	return data;
}

BYTE* genNonce(TSS_HTPM hTPM){
	 //Variables
	BYTE* nonce;

	nonce = malloc(NONCE_LENGTH);
	Tspi_TPM_GetRandom(hTPM,NONCE_LENGTH,&nonce);

	 // print nonce DEBUG
	// printf("\nNONCE VALUE\n");
	// printHex(nonce, NONCE_LENGTH);
	// printf("\n");

	return nonce;
}

TSS_HHASH createHash(TSS_HCONTEXT hContext, BYTE* data, UINT32 dataLength){
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

BYTE* sign(TSS_HCONTEXT hContext, TSS_HKEY hSRK, BYTE* data, UINT32 dataLength, UINT32* signatureLength){
	//Variables
	TSS_RESULT result;
	TSS_UUID MY_UUID=SIGN_KEY_UUID;
	TSS_HKEY hSigningKey;
	TSS_HHASH hHash;
	 //Output Variables
	BYTE *signature;

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
		signatureLength,
		&signature);
	DBG("Sign data", result);

	return signature;
}

UINT32 readPublicKey(char* file, BYTE** pubKey){
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

int isVerified(TSS_HCONTEXT hContext, BYTE* signature, UINT32 signatureLength, BYTE* data, UINT32 dataLength){
	//Variables
	TSS_RESULT result;
	UINT32 pubKeyLength;
	BYTE *pubKey;
	TSS_FLAG initFlags;
	TSS_HKEY hVerifyKey;
	TSS_HHASH hHash;

	pubKey = malloc(286);
	pubKeyLength = readPublicKey(PUBLIC_KEY_FILENAME, &pubKey);
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
	if(pubKey == NULL){
		printf("pubkey is null");
	}
	result = Tspi_SetAttribData(hVerifyKey,
		TSS_TSPATTRIB_KEY_BLOB,
		TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
		pubKeyLength,
		pubKey);
	DBG("Set attribute for verify key", result);

	// Verify signature
	result = Tspi_Hash_VerifySignature(hHash, hVerifyKey, signatureLength, signature);
	DBG("Verify signature", result);
	if (result != TSS_SUCCESS){
		return 0;
	} else {
		return 1;
	}
}

BYTE* CreateBindKey(TSS_HCONTEXT hContext, TSS_HKEY hSRK, UINT32* pubKeySize){
	TSS_RESULT result;
	TSS_HKEY hESS_Bind_Key;
	TSS_UUID MY_UUID=BACKUP_KEY_UUID;
	TSS_HPOLICY hBackup_Policy;
	TSS_FLAG initFlags;
	TSS_UUID SRK_UUID=TSS_UUID_SRK;
	BYTE* pubKey;

	//Create policy for new key; pw = 123;
	result = Tspi_Context_CreateObject(hContext,
		TSS_OBJECT_TYPE_POLICY,
		0, &hBackup_Policy);
	DBG("Create a backup policy object",result);

	result=Tspi_Policy_SetSecret(hBackup_Policy,
		TSS_SECRET_MODE_PLAIN,
		3, (BYTE*)"123");
	DBG("Set backup policy object secret",result);

	initFlags = TSS_KEY_TYPE_BIND |
		TSS_KEY_SIZE_2048 |
		TSS_KEY_AUTHORIZATION |
		TSS_KEY_NOT_MIGRATABLE;

	result = Tspi_Context_CreateObject(hContext,
		TSS_OBJECT_TYPE_RSAKEY,
		initFlags, &hESS_Bind_Key);
	DBG("Set the key's padding type",result);

	//Assign the key's policy to the key object
	result = Tspi_Policy_AssignToObject(hBackup_Policy, hESS_Bind_Key);
	DBG("Assign the key's policy to the key",result);

	//Create the key, with the SRK as its parent
	printf("Creating the key could take awhile\n");
	result = Tspi_Key_CreateKey(hESS_Bind_Key, hSRK, 0);
	DBG("Asking TP to create the key",result);

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


char* read_file(char* file_name){
	FILE *f;
	f=fopen(file_name,"r");
	fseek(f, 0, SEEK_END);
	int len = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *buffer = malloc(len);
	fread(buffer, len, 1, f);
	// printf("Read: %s\n",buffer);
	fclose(f);
	return buffer;
}

int ecc_gen_key(){
	struct arguments args;
	set_defaults(&args);
	// Sets up device for communication
	int fd = lca_atmel_setup(args.bus, args.address);

	FILE* pubkeyfile;
	pubkeyfile = fopen(FILENAME_PUBLICKEY,"w");

	int result = HASHLET_COMMAND_FAIL;
	if(fd<0)
		printf("ERROR fd < 0");
	else
	{
		struct lca_octet_buffer pub_key = lca_gen_ecc_key (fd, args.key_slot, true);

		pub_key = lca_gen_ecc_key (fd, args.key_slot, true);

	// If public key not NULL
		if (NULL != pub_key.ptr)
		{
			struct lca_octet_buffer uncompressed = 
			lca_add_uncompressed_point_tag (pub_key);

			assert (NULL != uncompressed.ptr);
			assert (65 == uncompressed.len);
			output_hex (pubkeyfile, uncompressed);

			fclose(pubkeyfile);
			lca_free_octet_buffer (uncompressed);
			result = HASHLET_COMMAND_SUCCESS;
		}
		else
		{
			fprintf (stderr, "%s\n", "Gen key command failed");
		}
	}
	lca_atmel_teardown(fd);
	return result;
}

struct lca_octet_buffer ecc_sign()
{
	struct arguments args;
	set_defaults(&args);
	// Sets up device for communication
	int fd = lca_atmel_setup(args.bus, args.address);

	unsigned char* input_string =(unsigned char*) INPUT;
	struct lca_octet_buffer input;
	input.ptr = input_string;
	input.len = 11;

	struct lca_octet_buffer signature = {0,0};
	struct lca_octet_buffer file_digest = {0,0};

	if(fd<0)
		printf("ERROR fd < 0");
	else
	{
    	/* Digest the file then proceed */
		file_digest = lca_sha256_buffer (input);

		if (NULL != file_digest.ptr)
		{

        	/* Forces a seed update on the RNG */
			struct lca_octet_buffer r = lca_get_random (fd, true);

        	/* Loading the nonce is the mechanism to load the SHA256 hash into the device */
			if (load_nonce (fd, file_digest))
			{
				signature = lca_ecc_sign (fd, args.key_slot);

				if (NULL == signature.ptr)
				{
					fprintf (stderr, "%s\n", "Sign Command failed.");
				}

			}
			lca_free_octet_buffer (r);
		}
	}
	lca_atmel_teardown(fd);
	return signature;
}

int ecc_verify(struct lca_octet_buffer signature)
{
	int result = HASHLET_COMMAND_FAIL;

	struct arguments args;
	set_defaults(&args);
	// Sets up device for communication
	int fd = lca_atmel_setup(args.bus, args.address);

	unsigned char* input_string =(unsigned char*) INPUT;
	struct lca_octet_buffer input;
	input.ptr = input_string;
	input.len = 11;

	struct lca_octet_buffer pub_key = {0,0};
	struct lca_octet_buffer file_digest = {0,0};
	
	// long testSize;
	// char* test = readFile(FILENAME_PUBLICKEY,&testSize);
	// pub_key = lca_ascii_hex_2_bin(test,(unsigned int)testSize);
	// printf("readFile Test\n");
	// printHex(pub_key.ptr,pub_key.len);

	char* buffer = read_file(FILENAME_PUBLICKEY);
	args.pub_key = buffer;
	pub_key = lca_ascii_hex_2_bin (args.pub_key, 130);
	// printf("read_file Control\n");
	// printHex(pub_key.ptr,pub_key.len);

	if (NULL == signature.ptr)
	{
		perror ("Signature required");
	}
	else if (NULL == pub_key.ptr)
	{
		perror ("Public Key required");
	}
	else
	{
     	/* Digest the file then proceed */
		file_digest = lca_sha256_buffer (input);

		if (NULL != file_digest.ptr)
		{
			/* Loading the nonce is the mechanism to load the SHA256 hash into the device */
			if (load_nonce (fd, file_digest))
			{
				/* The ECC108 doesn't use the leading uncompressed point format tag */
				pub_key.ptr = pub_key.ptr + 1;
				pub_key.len = pub_key.len - 1;
				if (lca_ecc_verify (fd, pub_key, signature))
				{
					printf("Verify Successful\n");
					result = HASHLET_COMMAND_SUCCESS;
				}
				else
				{
					fprintf (stderr, "%s\n", "Verify Command failed.");
					printf("Verify Failed\n");
				}

				/* restore pub key */
				pub_key.ptr = pub_key.ptr - 1;
				pub_key.len = pub_key.len + 1;
			}
		}
		else
		{
      /* temp_key_loaded already false */
		}
		lca_free_octet_buffer (file_digest);
		lca_free_octet_buffer (pub_key);
		lca_free_octet_buffer (signature);
	}
	free(buffer);
	lca_atmel_teardown(fd);
	return result;
}

int main()
{
	/*******************************
	 * PREAMBLE
	 *******************************/
	 TSS_HCONTEXT hContext;
	 TSS_HTPM hTPM;
	 TSS_RESULT result;
	 TSS_HKEY hSRK;
	 TSS_HPOLICY hSRKPolicy=0;
	 TSS_UUID SRK_UUID=TSS_UUID_SRK;
	BYTE wks[20]; //For the well known secret

	memset(wks,0,20);

	//Pick the TPM you are talking to.
	// In this case, it is the system TPM (indicated with NULL).
	result = Tspi_Context_Create(&hContext);
	DBG("Create Context",result);
	result = Tspi_Context_Connect(hContext, NULL);
	DBG("Context Connect",result);
	// Get the TPM handle
	result=Tspi_Context_GetTpmObject(hContext, &hTPM);
	DBG("Get TPM Handle",result);
	// Get the SRK handle
	result=Tspi_Context_LoadKeyByUUID(hContext,
		TSS_PS_TYPE_SYSTEM,
		SRK_UUID,
		&hSRK);
	DBG("Got the SRK handle", result);
	//Get the SRK policy
	result = Tspi_GetPolicyObject(hSRK,
		TSS_POLICY_USAGE,
		&hSRKPolicy);
	DBG("Got the SRK policy",result);
	//Then set the SRK policy to be the well known secret
	result=Tspi_Policy_SetSecret(hSRKPolicy,
		TSS_SECRET_MODE_SHA1,
		20,
		wks);
	DBG("Set the SRK secret in its policy", result);

	/*******************************
	 * NONCE
	 *******************************/
	 BYTE* nonceA = genNonce(hTPM);

	 /*******************************
	 * SIGN NONCE
	 *******************************/
	 //Variables
	 UINT32 signatureLength = 0;
	 BYTE *signature = sign(hContext, hSRK, nonceA, NONCE_LENGTH, &signatureLength);

	 // printf("\nSignature length: %d\n\n",signatureLength);

	//write signature DEBUG
	 char *signatureStr = malloc(base64_enc_len(signatureLength));
	 base64_encode(signatureStr, (char*)signature, signatureLength);
	 writeFile(SIGNATURE_FILENAME, signatureStr);

	 /*******************************
	 * VERIFY SIGNATURE
	 *******************************/
	 if(isVerified(hContext, signature, SIGNATURE_LENGTH, nonceA, NONCE_LENGTH)){
	 	printf("Verification success!\n\n");
	 	
	 	/*******************************
	 	* SIGN BOTH NONCE
	 	*******************************/
	 	BYTE* nonceB = genNonce(hTPM);
	 	BYTE* nonceAB;
	 	nonceAB = malloc(NONCE_LENGTH*2);
	 	memcpy(nonceAB, nonceA, NONCE_LENGTH);
	 	memcpy(nonceAB+4, nonceB, NONCE_LENGTH);
	 	signature = sign(hContext, hSRK, nonceAB, NONCE_LENGTH*2, &signatureLength);

	 	/*******************************
	 	* BIND AES KEY
	 	*******************************/
	 	// Create bind key
	 	UINT32 pubKeyLength;
		BYTE *pubKey;
		TSS_HKEY hBindKey;

		pubKey = malloc(286);
		pubKeyLength = readPublicKey(PUBLIC_KEY_FILENAME, &pubKey);
		printHex(pubKey, pubKeyLength);
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
		DBG("Set Public key into new key object",result);

		// Create data object
		TSS_HENCDATA hEncData;
		result = Tspi_Context_CreateObject(hContext,
			TSS_OBJECT_TYPE_ENCDATA,
			TSS_ENCDATA_BIND,
			&hEncData);
		DBG("Create data object",result);

		// Bind data (AES KEY)
		BYTE* AESkey = malloc(NONCE_LENGTH*4);
		memcpy(AESkey, nonceAB, NONCE_LENGTH*2);
		memcpy(AESkey+8, nonceAB, NONCE_LENGTH*2);
		result = Tspi_Data_Bind(hEncData,
			hBindKey,
			NONCE_LENGTH*4,
			AESkey);
		DBG("Bind data",result);

		//Get the encrypted data out of the data object
		UINT32 ulDataLength;
		BYTE* rgbBoundData;
		result = Tspi_GetAttribData(hEncData,
			TSS_TSPATTRIB_ENCDATA_BLOB,
			TSS_TSPATTRIB_ENCDATABLOB_BLOB,
			&ulDataLength, &rgbBoundData);
		DBG("Get encrypted data",result);

		/*******************************
	 	* A Verify B
	 	*******************************/
	 	BYTE* receivedNonce;
	 	receivedNonce = malloc(NONCE_LENGTH*2);
	 	memcpy(receivedNonce, nonceA, NONCE_LENGTH);
	 	memcpy(receivedNonce+NONCE_LENGTH, nonceB, NONCE_LENGTH);
	 	if(isVerified(hContext, signature, signatureLength, receivedNonce, NONCE_LENGTH*2)){
	 		printf("Verification success!\n\n");
	 		if(HASHLET_COMMAND_FAIL == ecc_gen_key()){
	 			goto postlude;
	 		}
	 		char* buffer = read_file(FILENAME_PUBLICKEY);
	 		struct lca_octet_buffer ecc_pub_key = lca_ascii_hex_2_bin (buffer, 130);

	 		signature = sign(hContext, hSRK, (BYTE*)ecc_pub_key.ptr, ecc_pub_key.len, &signatureLength);
 			/*******************************
 		 	* B Verify A
 		 	*******************************/
 		 	if(isVerified(hContext, signature, signatureLength, (BYTE*)ecc_pub_key.ptr, ecc_pub_key.len)){
 		 		//HANDSHAKE DONE
 		 		printf("Handshake complete\n");
 		 	}
	 	} else {
	 		printf("Verification failed\n");
	 	}

	 }
	 else{
	 	printf("Verification failed\n");
	 }

	 /*******************************
	 * ECC
	 *******************************/
	 // printf("\nECC STARTS HERE\n");
	 // ecc_gen_key();
	 // struct lca_octet_buffer ecc_signature = ecc_sign();
	 // ecc_verify(ecc_signature);

	/*******************************
	 * POSTLUDE
	 *******************************/
	 postlude:
	 Tspi_Policy_FlushSecret(hSRKPolicy);
	// Clean up
	 Tspi_Context_Close(hContext);
	 Tspi_Context_FreeMemory(hContext,NULL);
	// This frees up memory automatically allocated for you.
	 Tspi_Context_Close(hContext);
	return 1;
}