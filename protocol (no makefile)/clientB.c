#include "socket.h"
#include "serialization.c"

//COMMUNICATION
#define HS_BUFFER_SIZE HANDSHAKE_LENGTH
#define DATA_BUFFER_SIZE DATA_LENGTH
#define PORT_NUMBER 9999

//AES
#define AES_KEY_LENGTH 32
#define UINT_LENGTH 4

// typedef struct {
// 	unsigned char* encrypted_msg;
// 	int encrypted_msg_length;
// 	struct lca_octet_buffer ecc_signature;
// } message;

int verify_message (unsigned char *plaintext, int oldCount, int newCount, message msg);
void splitMessage (unsigned char* plaintext, int plaintext_len, unsigned char* data, unsigned int* counter);

int main(int argc, char *argv[]) {
	// TSS_RESULT result;
	tpmArgs tpm = preamble();

	/*******************************

		RECEIVE DATA FROM A

	*******************************/
	int sockfd, newsockfd;
	socklen_t clilen;
	BYTE* buffer = malloc(HS_BUFFER_SIZE);
	struct sockaddr_in serv_addr, cli_addr;
	int n;

	/* First call to socket() function */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		perror("ERROR opening socket");
		exit(1);
	}
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(PORT_NUMBER);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		error("ERROR on binding socket\n");
	}
	else {
		printf("server start\n");
	}

	listen(sockfd, 5);
	clilen = sizeof(cli_addr);
	newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
	printf("connection established\n");

	if (newsockfd < 0) {
		error("ERROR on accept");
	}
	buffer = malloc(HS_BUFFER_SIZE);
	bzero(buffer, HS_BUFFER_SIZE);
	printf("Waiting for message...\n");
	n = read(newsockfd, buffer, HS_BUFFER_SIZE);

	// DECODE MESSAGE
	handshake hsMsg = deserializeHandshake(buffer, 1, 0, 0);

	// Get NonceA from message
	BYTE* nonceA = hsMsg.nonce;

	// Get signature from message
	UINT32 signatureLength = 0;
	BYTE* signature = hsMsg.signature;

	BYTE* nonceB;
	BYTE* boundData;
	UINT32 boundDataLength;
	BYTE* AESkey;

	if (isVerified(tpm.hContext, signature, SIGNATURE_LENGTH, nonceA, NONCE_LENGTH)) {
		printf("Nonce A Verified!\n");

		//Sign NonceA + NonceB
		nonceB = genNonce(tpm.hTPM, NONCE_LENGTH);
		BYTE* nonceAB;
		nonceAB = malloc(NONCE_LENGTH * 2);
		memcpy(nonceAB, nonceA, NONCE_LENGTH);
		memcpy(nonceAB + NONCE_LENGTH, nonceB, NONCE_LENGTH);
		signature = sign(tpm.hContext, tpm.hSRK, nonceAB, NONCE_LENGTH * 2);

		// Generate & Bind AES KEY
		AESkey = genNonce(tpm.hTPM, AES_KEY_LENGTH);
		boundData = RSAencrypt(tpm.hContext, AESkey, AES_KEY_LENGTH, &boundDataLength);
		printf("\n");
	} else {
		printf("Verification failed\n");
	}

	/*******************************

		SEND MESSAGE TO A

	*******************************/
	BYTE* response = calloc(HS_BUFFER_SIZE, sizeof(BYTE));
	handshake hsResp = createHandshake(1, nonceB, 0, NULL, NULL, signature, 1, boundData);
	int responseLen = serializeHandshake(hsResp, response);
	int x = write(newsockfd, response, responseLen);

	/*******************************

		RECEIVE DATA FROM A

	*******************************/
	n = read(newsockfd, buffer, HS_BUFFER_SIZE);
	hsMsg = deserializeHandshake(buffer, 0, 1, 0);
	signature = hsMsg.signature;
	BYTE* aesTag = malloc(TAG_LENGTH);
	aesTag = hsMsg.tag;
	unsigned char *eccPubKey = aes_decrypt((char*)hsMsg.ecc,
	                                       ECC_PUBKEY_LENGTH,
	                                       (unsigned char*)aesTag,
	                                       (unsigned char*)AESkey,
	                                       (char*)nonceA);

	if (isVerified(tpm.hContext, signature, SIGNATURE_LENGTH,
	               (BYTE*)eccPubKey, ECC_PUBKEY_LENGTH)) {
		printf("ECC Public Key Verified.\nHandshake complete. Sending ACK to A...\n");
		signature = sign(tpm.hContext, tpm.hSRK, (BYTE*)eccPubKey, ECC_PUBKEY_LENGTH);
		hsResp = createHandshake(0, NULL, 0, NULL, NULL, signature, 0, NULL);
		response = calloc(HS_BUFFER_SIZE, sizeof(BYTE));
		responseLen = serializeHandshake(hsResp, response);
		x = write(newsockfd, response, responseLen);
		if (x < 0) {
			printf("WRITE TO SOCKET FAILED.\n");
		}
	} else {
		printf("ECC pubkey verification failed\n");
	}

	/*******************************

		DATA TRANSMISSION TEST

	*******************************/
	unsigned int count, newCount = 0;
	BYTE* dataBuffer;
	unsigned char *data;

	//LOOP HERE
	dataBuffer = calloc(DATA_BUFFER_SIZE, sizeof(BYTE));
	n = read(newsockfd, dataBuffer, DATA_BUFFER_SIZE);
	message msg = deserializeData(dataBuffer);

	unsigned char *plaintext = aes_decrypt(msg.encrypted_msg, msg.encrypted_msg_length,
	                                       msg.aes_tag, AESkey, nonceA);
	data = malloc(msg.encrypted_msg_length - UINT_LENGTH);
	splitMessage(plaintext, msg.encrypted_msg_length, data, &newCount);

	if (verify_message(plaintext, count, newCount, msg)) {
		count = newCount;
		printf("forwarding data to CPU\n");
		printHex((BYTE*)data, msg.encrypted_msg_length - UINT_LENGTH);

		//FORWARD DATA (TO BE ADDED)
	}

	/*******************************
	 * POSTLUDE
	 *******************************/
postlude:
	postlude(tpm.hSRKPolicy, tpm.hContext);
	return 1;
}

int verify_message (unsigned char *plaintext, int oldCount, int newCount, message msg) {
	if (ecc_verify(msg.ecc_signature, plaintext, msg.encrypted_msg_length) == HASHLET_COMMAND_SUCCESS) {
		if (oldCount < newCount) {
			return 1;
		} else {
			printf("ERROR: INVALID COUNT\n");
			return 0;
		}
	} else {
		printf("ERROR: PLAINTEXT VERIFICATION FAILED\n");
		return 0;
	}
}

void splitMessage (unsigned char* plaintext, int plaintext_len, unsigned char* data, unsigned int* counter) {
	memcpy(counter, plaintext, UINT_LENGTH);
	memcpy(data, plaintext + UINT_LENGTH, plaintext_len - UINT_LENGTH);
}
