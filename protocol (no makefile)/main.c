#include <libcryptoauth.h>
#include "tpm.c"
//ECC
#define NUM_ARGS 1
#define HASHLET_COMMAND_FAIL EXIT_FAILURE
#define HASHLET_COMMAND_SUCCESS EXIT_SUCCESS
#define FILENAME_INPUT "/home/debian/EClet/Files/file.txt"
#define FILENAME_SIGNATURE "/home/debian/EClet/Files/signature.txt"
#define FILENAME_PUBLICKEY "/home/debian/EClet/Files/pubkey.txt"
#define INPUT "Hello World"
#define NUM_OF_LOOPS 100

//AES
#define AES_KEY_LENGTH 32
#define AES_TAG_LENGTH 4

struct arguments {
	char *args[NUM_ARGS];
	int silent, verbose;
	bool update_seed;
	char *output_file;
	char *input_file;
	unsigned int key_slot;
	bool test;
	uint8_t address;
	const char *challenge;
	const char *challenge_rsp;
	const char *signature;
	const char *pub_key;
	const char *meta;
	const char *write_data;
	const char *bus;
};


//READ WRITE FUNCTIONS
char* read_file(char* file_name);

//ECC FUNCTIONS
int ecc_gen_key();
int ecc_verify(struct lca_octet_buffer signature);
struct lca_octet_buffer ecc_sign();
void set_defaults (struct arguments *args);
void output_hex (FILE *stream, struct lca_octet_buffer buf);

int main() {
	// TSS_RESULT result;
	tpmArgs tpm = preamble();
	BYTE* nonceA = genNonce(tpm.hTPM, NONCE_LENGTH);

	printHex(nonceA, NONCE_LENGTH);

	/*******************************
	* SIGN NONCE
	*******************************/
	//Variables
	UINT32 signatureLength = 0;
	BYTE *signature = sign(tpm.hContext, tpm.hSRK, nonceA, NONCE_LENGTH, &signatureLength);

	printf("Signature length: %d\n", signatureLength);

	//write signature DEBUG
	char *signatureStr = malloc(base64_enc_len(signatureLength));
	base64_encode(signatureStr, (char*)signature, signatureLength);
	writeFile(SIGNATURE_FILENAME, signatureStr);
	printf("\n");

	/*******************************

			A SEND TO B

	*******************************/

	if (isVerified(tpm.hContext, signature, SIGNATURE_LENGTH, nonceA, NONCE_LENGTH)) {
		printf("Verification success!\n");

		/*******************************
		* SIGN BOTH NONCE
		*******************************/
		BYTE* nonceB = genNonce(tpm.hTPM, NONCE_LENGTH);
		BYTE* nonceAB;
		nonceAB = malloc(NONCE_LENGTH * 2);
		memcpy(nonceAB, nonceA, NONCE_LENGTH);
		memcpy(nonceAB + NONCE_LENGTH, nonceB, NONCE_LENGTH);
		signature = sign(tpm.hContext, tpm.hSRK, nonceAB, NONCE_LENGTH * 2, &signatureLength);

		/*******************************
		* BIND (ENCRYPT) AES KEY
		*******************************/
		// Bind data (AES KEY)
		BYTE* boundData;
		UINT32 boundDataLength;
		BYTE* AESkey = genNonce(tpm.hTPM, AES_KEY_LENGTH);
		printf("AES Key: ");
		printHex(AESkey, AES_KEY_LENGTH);
		boundData = RSAencrypt(tpm.hContext, AESkey, AES_KEY_LENGTH, &boundDataLength);
		printf("\n");

		/*******************************

				B SEND TO A

		*******************************/

		// //Use the Unbinding key to decrypt the encrypted AES key
		UINT32 unBoundDataLength;
		BYTE* unBoundData;
		unBoundData = RSAdecrypt(tpm.hContext, tpm.hSRK, boundData, boundDataLength, &unBoundDataLength);
		printf("Unbound AES Key: ");
		printHex(unBoundData, unBoundDataLength);

		BYTE* receivedNonce;
		receivedNonce = malloc(NONCE_LENGTH * 2);
		memcpy(receivedNonce, nonceA, NONCE_LENGTH);
		memcpy(receivedNonce + NONCE_LENGTH, nonceB, NONCE_LENGTH);
		if (isVerified(tpm.hContext, signature, signatureLength, receivedNonce, NONCE_LENGTH * 2)) {
			printf("Verification success!\n");
			if (HASHLET_COMMAND_FAIL == ecc_gen_key()) {
				goto postlude;
			}
			//read ECC public key
			char* buffer = read_file(FILENAME_PUBLICKEY);
			struct lca_octet_buffer ecc_pub_key = lca_ascii_hex_2_bin (buffer, 130);
			printf("ECC public key: ");
			output_hex (stdout, ecc_pub_key);

			//encrypt ECC public key
			boundData = RSAencrypt(tpm.hContext, (BYTE*)ecc_pub_key.ptr, ecc_pub_key.len, &boundDataLength);

			//sign ECC public key
			signature = sign(tpm.hContext, tpm.hSRK, (BYTE*)ecc_pub_key.ptr, ecc_pub_key.len, &signatureLength);
			printf("\n");

			/*******************************

					A SEND TO B

			*******************************/

			/*******************************
			* B Verify A
			*******************************/
			if (isVerified(tpm.hContext, signature, signatureLength, (BYTE*)ecc_pub_key.ptr, ecc_pub_key.len)) {
				//decrypt encrypted ECC public key
				unBoundData = RSAdecrypt(tpm.hContext, tpm.hSRK, boundData, boundDataLength, &unBoundDataLength);
				printf("Unbound ECC public key: ");
				printHex(unBoundData, unBoundDataLength);
				//HANDSHAKE DONE
				printf("Handshake complete\n");
			}
		} else {
			printf("Verification failed\n");
		}

	} else {
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
	postlude(tpm.hSRKPolicy, tpm.hContext);
	return 1;
}

void set_defaults (struct arguments *args) {
	assert (NULL != args);

	args->silent = 0;
	args->verbose = 0;
	args->output_file = "-";
	args->input_file = NULL;
	args->update_seed = false;
	args->key_slot = 0;

	args->signature = NULL;
	args->write_data = NULL;

	args->address = 0x60;
	args->bus = "/dev/i2c-1";
}

void output_hex (FILE *stream, struct lca_octet_buffer buf) {
	assert (NULL != stream);

	if (NULL == buf.ptr)
		printf ("Command failed\n");
	else
	{
		unsigned int i = 0;

		for (i = 0; i < buf.len; i++)
		{
			fprintf (stream, "%02X", buf.ptr[i]);
		}

		fprintf (stream, "\n");
	}
}

char* read_file(char* file_name) {
	FILE *f;
	f = fopen(file_name, "r");
	fseek(f, 0, SEEK_END);
	int len = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *buffer = malloc(len);
	fread(buffer, len, 1, f);
	// printf("Read: %s\n",buffer);
	fclose(f);
	return buffer;
}

int ecc_gen_key() {
	struct arguments args;
	set_defaults(&args);
	// Sets up device for communication
	int fd = lca_atmel_setup(args.bus, args.address);

	FILE* pubkeyfile;
	pubkeyfile = fopen(FILENAME_PUBLICKEY, "w");

	int result = HASHLET_COMMAND_FAIL;
	if (fd < 0)
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

	unsigned char* input_string = (unsigned char*) INPUT;
	struct lca_octet_buffer input;
	input.ptr = input_string;
	input.len = 11;

	struct lca_octet_buffer signature = {0, 0};
	struct lca_octet_buffer file_digest = {0, 0};

	if (fd < 0)
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

int ecc_verify(struct lca_octet_buffer signature) {
	int result = HASHLET_COMMAND_FAIL;

	struct arguments args;
	set_defaults(&args);
	// Sets up device for communication
	int fd = lca_atmel_setup(args.bus, args.address);

	unsigned char* input_string = (unsigned char*) INPUT;
	struct lca_octet_buffer input;
	input.ptr = input_string;
	input.len = 11;

	struct lca_octet_buffer pub_key = {0, 0};
	struct lca_octet_buffer file_digest = {0, 0};

	// long testSize;
	// char* test = readFile(FILENAME_PUBLICKEY,&testSize);
	// pub_key = lca_ascii_hex_2_bin(test,(unsigned int)testSize);
	// printf("readFile Test\n");
	// printHex(pub_key.ptr,pub_key.len);

	char* buffer = read_file(FILENAME_PUBLICKEY);
	args.pub_key = buffer;
	pub_key = lca_ascii_hex_2_bin (args.pub_key, 130);
	// printf("read_file Control\n");
	// printHex(pub_key.ptr, pub_key.len);

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
