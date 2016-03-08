#include "socket.h"
#include "serialization.c"

//COMMUNICATION
#define HS_BUFFER_SIZE HANDSHAKE_LENGTH
#define MSG_BUFFER_SIZE MSG_LENGTH
#define PORT_NUMBER 9999

//AES
#define AES_KEY_LENGTH 32
#define UINT_LENGTH 4

int verify_message (unsigned char *plaintext, int oldCount, int newCount, message msg, BYTE *eccPubKey);
void splitMessage (unsigned char *plaintext, int plaintext_len, unsigned char *data, unsigned int *counter);
int establishTCP();
int startTCPserver();
int startUDPserver(int *addr_len);

int main(int argc, char *argv[]) {
	int x;
	int udpAddrLen;
	int bytesRead;
	int responseLen;
	int sockfd;

	unsigned int count = 0;
	unsigned int newCount = 0;

	unsigned char *data;
	unsigned char *plaintext;
	unsigned char *eccPubKey;

	BYTE *nonceA, *nonceB, *nonceAB;
	BYTE *hsBuffer, *dataBuffer;
	BYTE *signature;
	BYTE *boundData;
	BYTE *AESkey;
	BYTE *aesTag;
	BYTE *response;

	UINT32 boundDataLength;

	handshake hsMsg;
	handshake hsResp;
	message msg;
	tpmArgs tpm;

	struct sockaddr_in client_addr;

	tpm = preamble();
	sockfd = establishTCP();

	hsBuffer = malloc(HS_BUFFER_SIZE);
	bzero(hsBuffer, HS_BUFFER_SIZE);
	PRINTDEBUG("Waiting for message...");

	bytesRead = read(sockfd, hsBuffer, HS_BUFFER_SIZE);
	hsMsg = deserializeHandshake(hsBuffer, 1, 0, 0);
	

	nonceA = hsMsg.nonce;
	signature = hsMsg.signature;

	if (isVerified(tpm.hContext, signature, SIGNATURE_LENGTH, nonceA, NONCE_LENGTH)) {
		PRINTDEBUG("Nonce A Verified!");

		//Sign NonceA + NonceB
		nonceB = genNonce(tpm.hTPM, NONCE_LENGTH);
		nonceAB = malloc(NONCE_LENGTH * 2);
		memcpy(nonceAB, nonceA, NONCE_LENGTH);
		memcpy(nonceAB + NONCE_LENGTH, nonceB, NONCE_LENGTH);
		signature = sign(tpm.hContext, tpm.hSRK, nonceAB, NONCE_LENGTH * 2);

		// Generate & Bind AES KEY
		AESkey = genNonce(tpm.hTPM, AES_KEY_LENGTH);
		boundData = RSAencrypt(tpm.hContext, AESkey, AES_KEY_LENGTH, &boundDataLength);
	} else {
		PRINTDEBUG("Error: Nonce A verification failed");
	}

	/*******************************

		SEND MESSAGE TO A

	*******************************/
	response = calloc(HS_BUFFER_SIZE, sizeof(BYTE));
	hsResp = createHandshake(1, nonceB, 0, NULL, NULL, signature, 1, boundData);
	
	responseLen = serializeHandshake(hsResp, response);

	x = write(sockfd, response, responseLen);
	if (x < 0) {
		PRINTDEBUG("Error: Write to socket failed.");
	}

	/*******************************

		RECEIVE DATA FROM A

	*******************************/
	bytesRead = read(sockfd, hsBuffer, HS_BUFFER_SIZE);
	hsMsg = deserializeHandshake(hsBuffer, 0, 1, 0);
	
	signature = hsMsg.signature;
	aesTag = malloc(TAG_LENGTH);
	aesTag = hsMsg.tag;
	eccPubKey = malloc(ECC_PUBKEY_LENGTH);
	aes_decrypt((unsigned char*)hsMsg.ecc,
	            ECC_PUBKEY_LENGTH,
	            (unsigned char*)aesTag,
	            (unsigned char*)AESkey,
	            (unsigned char*)nonceA,
	            eccPubKey,
	            ECC_PUBKEY_LENGTH,
	            1);
	if (isVerified(tpm.hContext, signature, SIGNATURE_LENGTH, (BYTE*)eccPubKey, ECC_PUBKEY_LENGTH)) {
		PRINTDEBUG("ECC Public Key Verified! Handshake complete. Sending ACK to A...");
		signature = sign(tpm.hContext, tpm.hSRK, (BYTE*)eccPubKey, ECC_PUBKEY_LENGTH);
		hsResp = createHandshake(0, NULL, 0, NULL, NULL, signature, 0, NULL);
		
		response = calloc(HS_BUFFER_SIZE, sizeof(BYTE));
		responseLen = serializeHandshake(hsResp, response);

		x = write(sockfd, response, responseLen);
		if (x < 0) {
			PRINTDEBUG("Error: Write to socket failed.");
		}
	} else {
		PRINTDEBUG("ECC pubkey verification failed.");
	}

	/*******************************

		DATA TRANSMISSION

	*******************************/

	dataBuffer = calloc(MSG_BUFFER_SIZE, sizeof(BYTE));
	bytesRead = read(sockfd, dataBuffer, MSG_BUFFER_SIZE);
	if (bytesRead == 0) {
		PRINTDEBUG("TCP connection lost, Starting UDP server..");
		free(hsBuffer);
		sockfd = startUDPserver(&udpAddrLen);
	} else {
		printf("Error: Data received before TCP connection closed. Bytes read: %d\n", bytesRead);
	}

	while (1) {
		dataBuffer = calloc(MSG_BUFFER_SIZE, sizeof(BYTE));
		bytesRead = recvfrom(sockfd,
		                     (char *)dataBuffer,
		                     MSG_BUFFER_SIZE,
		                     0,
		                     (struct sockaddr *)&client_addr,
		                     (socklen_t*)&udpAddrLen);

		if (DEBUG) {
			printf("Bytes Read: %d\n", bytesRead);
			printf("MSG_LENGTH: %d\n", MSG_LENGTH);
		}

		msg = deserializeData(dataBuffer);
		plaintext = malloc(msg.encrypted_msg_length);

		aes_decrypt(msg.encrypted_msg,
		            msg.encrypted_msg_length,
		            msg.aes_tag,
		            AESkey,
		            nonceA,
		            plaintext,
		            INPUT_MAX_LEN,
		            0);


		data = calloc(msg.encrypted_msg_length - UINT_LENGTH, sizeof(char));
		splitMessage(plaintext, msg.encrypted_msg_length, data, &newCount);

		if (verify_message(plaintext, count, newCount, msg, (BYTE*)eccPubKey)) {
			count = newCount;
			PRINTDEBUG("Message verified! Forwarding data to CPU...");
			printf("%s\n", data);

			//FORWARD DATA (TO BE ADDED)
		}
	}

	postlude(tpm.hSRKPolicy, tpm.hContext);
	return 1;
}


int verify_message (unsigned char *plaintext, int oldCount, int newCount, message msg, BYTE* eccPubKey) {

	if (ecc_verify(msg.ecc_signature, plaintext, msg.encrypted_msg_length, eccPubKey) == HASHLET_COMMAND_SUCCESS) {
		if (oldCount < newCount) {
			printf("verify success\n");
			return 1;
		} else {
			printf("ERROR: INVALID COUNT\n");
			return 0;
		}
	} else {
		printf("ERROR: PLAINTEXT VERIFICATION FAILED\n");
		printf("DATA LENGTH: %d\n", DATA_LENGTH);
		return 0;
	}
}

void splitMessage (unsigned char* plaintext, int plaintext_len, unsigned char* data, unsigned int* counter) {
	memcpy(counter, plaintext, UINT_LENGTH);
	memcpy(data, plaintext + UINT_LENGTH, plaintext_len - UINT_LENGTH);
}

int startTCPserver() {
	int sockfd;
	struct sockaddr_in serv_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		perror("ERROR opening socket");
		exit(1);
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(PORT_NUMBER);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		PRINTDEBUG("ERROR on binding socket\n");
	}
	else {
		PRINTDEBUG("Server started\n");
	}

	return sockfd;
}

int establishTCP() {
	int sockfd, newsockfd;

	socklen_t clilen;
	struct sockaddr_in cli_addr;

	sockfd = startTCPserver();

	listen(sockfd, 5);
	clilen = sizeof(cli_addr);
	newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
	printf("connection established\n");

	if (newsockfd < 0) {
		PRINTDEBUG("ERROR on accept");
	}

	return newsockfd;
}

int startUDPserver(int *addr_len) {
	int sock;
	struct sockaddr_in server_addr;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("Socket");
		exit(1);
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT_NUMBER);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	bzero(&(server_addr.sin_zero), 8);

	if (bind(sock, (struct sockaddr *)&server_addr,
	         sizeof(struct sockaddr)) == -1) {
		perror("Bind");
		exit(1);
	}

	*addr_len = sizeof(struct sockaddr);

	printf("UDPServer Waiting for client on port %d\n", PORT_NUMBER);
	fflush(stdout);

	return sock;
}