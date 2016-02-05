#include "socket.h"
#include "serialization.c"

//COMMUNICATION
#define HS_BUFFER_SIZE HANDSHAKE_LENGTH
#define MSG_BUFFER_SIZE MSG_LENGTH
#define PORT_NUMBER 9999

//AES
#define AES_KEY_LENGTH 32
#define UINT_LENGTH 4

int verify_message (unsigned char *plaintext, int oldCount, int newCount, message msg, BYTE* eccPubKey);
void splitMessage (unsigned char* plaintext, int plaintext_len, unsigned char* data, unsigned int* counter);
int establishTCP();
int startUDPserver(int *addr_len);

int main(int argc, char *argv[]) {
	tpmArgs tpm;
	
	int sockfd;
	int n;
	int udpAddrLen;

	BYTE *nonceA, *nonceB;
	BYTE* signature;
	BYTE* boundData;
	BYTE* AESkey;

	UINT32 signatureLength;
	UINT32 boundDataLength;

	handshake hsResp;
	
	tpm = preamble();
	sockfd = establishTCP();

	BYTE* buffer = malloc(HS_BUFFER_SIZE);
	bzero(buffer, HS_BUFFER_SIZE);
	PRINTDEBUG("Waiting for message...");

	n = read(sockfd, buffer, HS_BUFFER_SIZE);
	handshake hsMsg = deserializeHandshake(buffer, 1, 0, 0);

	nonceA = hsMsg.nonce;
	signature = hsMsg.signature;
	signatureLength = 0;

	if (isVerified(tpm.hContext, signature, SIGNATURE_LENGTH, nonceA, NONCE_LENGTH)) {
		PRINTDEBUG("Nonce A Verified!");

		//Sign NonceA + NonceB
		BYTE *nonceAB;
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
	BYTE* response = calloc(HS_BUFFER_SIZE, sizeof(BYTE));
	hsResp = createHandshake(1, nonceB, 0, NULL, NULL, signature, 1, boundData);
	int responseLen = serializeHandshake(hsResp, response);

	int x = write(sockfd, response, responseLen);

	/*******************************

		RECEIVE DATA FROM A

	*******************************/
	n = read(sockfd, buffer, HS_BUFFER_SIZE);
	hsMsg = deserializeHandshake(buffer, 0, 1, 0);
	signature = hsMsg.signature;
	BYTE* aesTag = malloc(TAG_LENGTH);
	aesTag = hsMsg.tag;
	unsigned char *eccPubKey = malloc(ECC_PUBKEY_LENGTH);
	aes_decrypt((char*)hsMsg.ecc,
	            ECC_PUBKEY_LENGTH,
	            (unsigned char*)aesTag,
	            (unsigned char*)AESkey,
	            (char*)nonceA,
	            eccPubKey,
	            ECC_PUBKEY_LENGTH);
	if (isVerified(tpm.hContext, signature, SIGNATURE_LENGTH,
	               (BYTE*)eccPubKey, ECC_PUBKEY_LENGTH)) {
		PRINTDEBUG("ECC Public Key Verified! Handshake complete. Sending ACK to A...");
		signature = sign(tpn.hContext, tpm.hSRK, (BYTE*)ACK, ACK_LENGTH);
		// signature = sign(tpm.hContext, tpm.hSRK, (BYTE*)eccPubKey, ECC_PUBKEY_LENGTH);
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

		DATA TRANSMISSION TEST

	*******************************/
	unsigned int count, newCount = 0;
	BYTE* dataBuffer;
	unsigned char *data;
	int bytesRead;
	struct sockaddr_in client_addr;

	n = read(sockfd, dataBuffer, MSG_BUFFER_SIZE);
	if (n == 0) {
		PRINTDEBUG("TCP connection lost, Starting UDP server..");
		sockfd = startUDPserver(&udpAddrLen);
	} else {
		printf("%d\n", n);
	}

	while (1) {
		dataBuffer = calloc(MSG_BUFFER_SIZE, sizeof(BYTE));
		bytesRead = recvfrom(sockfd, (char *)dataBuffer, MSG_BUFFER_SIZE, 0,
		                     (struct sockaddr *)&client_addr, &udpAddrLen);
		// n = read(sockfd, dataBuffer, MSG_BUFFER_SIZE);


		message msg = deserializeData(dataBuffer);
		unsigned char *plaintext = malloc(msg.encrypted_msg_length);

		aes_decrypt(msg.encrypted_msg, msg.encrypted_msg_length,
		            msg.aes_tag, AESkey, nonceA, plaintext, INPUT_MAX_LEN);


		data = malloc(msg.encrypted_msg_length - UINT_LENGTH);
		splitMessage(plaintext, msg.encrypted_msg_length, data, &newCount);

		if (verify_message(plaintext, count, newCount, msg, (BYTE*)eccPubKey)) {
			count = newCount;
			PRINTDEBUG("forwarding data to CPU");
			printf("%s\n", data);

			//FORWARD DATA (TO BE ADDED)

		}
	}

postlude:
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
		return 0;
	}
}

void splitMessage (unsigned char* plaintext, int plaintext_len, unsigned char* data, unsigned int* counter) {
	memcpy(counter, plaintext, UINT_LENGTH);
	memcpy(data, plaintext + UINT_LENGTH, plaintext_len - UINT_LENGTH);
}

int establishTCP() {
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
		PRINTDEBUG("Server started\n");
	}

	listen(sockfd, 5);
	clilen = sizeof(cli_addr);
	newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
	printf("connection established\n");

	if (newsockfd < 0) {
		error("ERROR on accept");
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