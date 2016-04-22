#include "serialization.h"
#include "aes.h"

// COMMUNICATION
#define HS_BUFFER_SIZE HANDSHAKE_LENGTH
#define MSG_BUFFER_SIZE MSG_NO_DATA_LENGTH + DATA_LENGTH

int establishTCP();
void splitMessage(unsigned char* plaintext, int plaintext_len,
                  unsigned char* data, unsigned int* counter);
int verifyData(unsigned char* plaintext, int oldCount,
               int newCount, message msg, BYTE* eccPubKey);
int verifyCount(int oldCount, int newCount);


int main(int argc, char *argv[]) {
	BYTE *nonceA, *nonceB, *nonceAB;
	BYTE *hsBuffer, *dataBuffer;
	BYTE *signature;
	BYTE *boundData;
	BYTE *AESkey;
	BYTE *aesTag;
	BYTE *response;
	handshake hsMsg;
	handshake hsResp;
	int bytesRead, bytesSent;
	int responseLen;
	int serverTCP = -1;
	int serverUDP = -1;
	int clientUDP = -1;
	int udpAddrLen;
	message msg;
	struct sockaddr_in a_addr;
	struct sockaddr_in cpu_addr;
	socklen_t clilen;
	tpmArgs tpm;
	UINT32 boundDataLength;
	unsigned int count = 0;
	unsigned int newCount = 0;
	unsigned char *data;
	unsigned char *plaintext;
	unsigned char *eccPubKey;

	if (verifyCert(CERT_FILENAME, CA_CERT_FILENAME) == 0) {
		perror("ERROR: Certificate verification failed\n");
		exit(1);
	}

	tpm = preamble();
	serverTCP = establishTCP(B_SERVER_INTERFACE);

	hsBuffer = malloc(HS_BUFFER_SIZE);
	bzero(hsBuffer, HS_BUFFER_SIZE);
	PRINTDEBUG("Waiting for message...");

	bytesRead = read(serverTCP, hsBuffer, HS_BUFFER_SIZE);
	hsMsg = deserializeHandshake(hsBuffer, 1, 0, 0);

	nonceA = hsMsg.nonce;
	signature = hsMsg.signature;

	if (isVerified(tpm, signature, SIGNATURE_LENGTH, nonceA, NONCE_LENGTH)) {
		PRINTDEBUG("Nonce A Verified!");

		// Sign NonceA + NonceB
		nonceB = genNonce(tpm.hTPM, NONCE_LENGTH);
		nonceAB = malloc(NONCE_LENGTH * 2);
		memcpy(nonceAB, nonceA, NONCE_LENGTH);
		memcpy(nonceAB + NONCE_LENGTH, nonceB, NONCE_LENGTH);
		signature = sign(tpm.hContext, tpm.hSRK, nonceAB, NONCE_LENGTH * 2);

		// Generate & Bind AES KEY
		AESkey = genNonce(tpm.hTPM, AES_KEY_LENGTH);
		boundData = RSAencrypt(AESkey, AES_KEY_LENGTH, &boundDataLength);

	} else {
		perror("Error: Nonce A verification failed");
	}

	/*******************************

	    SEND MESSAGE TO A

	*******************************/
	response = calloc(HS_BUFFER_SIZE, sizeof(BYTE));
	hsResp = createHandshake(1, nonceB, 0, NULL, NULL, signature, 1, boundData);

	responseLen = serializeHandshake(hsResp, response);

	bytesSent = write(serverTCP, response, responseLen);
	if (bytesSent < 0) {
		perror("Error: Write to socket failed.");
	}

	/*******************************

	    RECEIVE DATA FROM A

	*******************************/
	bytesRead = read(serverTCP, hsBuffer, HS_BUFFER_SIZE);
	hsMsg = deserializeHandshake(hsBuffer, 0, 1, 0);

	signature = hsMsg.signature;
	aesTag = malloc(TAG_LENGTH);
	aesTag = hsMsg.tag;
	eccPubKey = malloc(ECC_PUBKEY_LENGTH);
	aes_decrypt((unsigned char*)hsMsg.ecc, ECC_PUBKEY_LENGTH,
	            (unsigned char*)aesTag, (unsigned char*)AESkey,
	            (unsigned char*)nonceA, eccPubKey, ECC_PUBKEY_LENGTH, 1);
	if (isVerified(tpm, signature, SIGNATURE_LENGTH, (BYTE*)eccPubKey,
	               ECC_PUBKEY_LENGTH)) {
		PRINTDEBUG("ECC Public Key Verified! Sending ACK to A...");

		signature = sign(tpm.hContext,
		                 tpm.hSRK,
		                 (BYTE*)eccPubKey,
		                 ECC_PUBKEY_LENGTH);
		hsResp = createHandshake(0, NULL, 0, NULL, NULL, signature, 0, NULL);

		response = calloc(HS_BUFFER_SIZE, sizeof(BYTE));
		responseLen = serializeHandshake(hsResp, response);

		bytesSent = write(serverTCP, response, responseLen);
		if (bytesSent < 0) {
			perror("Error: Write to socket failed.");
		} else {
			PRINTDEBUG("ACK sent successfully. Handshake complete.")
		}
	} else {
		perror("ECC pubkey verification failed.");
	}

	/*******************************

	    DATA TRANSMISSION

	*******************************/
	free(hsBuffer);
	free(nonceAB);
	free(response);

	dataBuffer = calloc(MSG_BUFFER_SIZE, sizeof(BYTE));
	bytesRead = read(serverTCP, dataBuffer, MSG_BUFFER_SIZE);

	if (bytesRead == 0) {  // Detect dropped TCP connection and start UDP server
		PRINTDEBUG("TCP connection lost, Starting UDP server..");
		serverUDP = startUDPserver(&udpAddrLen, B_SERVER_INTERFACE);
		clientUDP = startUDPClient(&cpu_addr, B_CLIENT_INTERFACE);
		clilen = sizeof(cpu_addr);
	} else {
		fprintf(stderr,
		        "Error: Data received before TCP connection closed. Bytes read: %d\n",
		        bytesRead);
	}

	dataBuffer = malloc(MSG_BUFFER_SIZE);
	plaintext = malloc(DATA_LENGTH + UINT_LENGTH);
	data = malloc(DATA_LENGTH);
	msg.ecc_signature.ptr = malloc(ECC_SIGNATURE_LENGTH);

	while (1) {
		bytesRead =
		    recvfrom(serverUDP, (char*)dataBuffer, MSG_BUFFER_SIZE, 0,
		             (struct sockaddr*)&a_addr, (socklen_t*)&udpAddrLen);

		if (DEBUG) {
			printf("Bytes Read: %d\n", bytesRead);
		}

		deserializeData(dataBuffer, msg);

		aes_decrypt(msg.encrypted_msg, msg.encrypted_msg_length, msg.aes_tag,
		            AESkey, nonceA, plaintext, INPUT_MAX_LEN, 0);

		splitMessage(plaintext, msg.encrypted_msg_length, data, &newCount);

		if (verifyData(plaintext, count, newCount, msg, (BYTE*)eccPubKey)) {
			count = newCount;
			PRINTDEBUG("Message verified! Forwarding data to CPU...");

			// FORWARD DATA TO CPU
			bytesSent = sendto(clientUDP, data, msg.encrypted_msg_length, 0,
			                   (const struct sockaddr*)&cpu_addr, clilen);
			if (bytesSent < 0) {
				perror("Error. Failed to forward data to CPU.");
			}
		} else {
			continue;
		}
	}

	free(dataBuffer);
	free(data);
	free(plaintext);
	free(msg.ecc_signature.ptr);
	postlude(tpm.hSRKPolicy, tpm.hContext);
	return 0;
}

int verifyData(unsigned char* plaintext, int oldCount,
               int newCount, message msg, BYTE* eccPubKey) {
	if (ecc_verify(msg.ecc_signature, plaintext, msg.encrypted_msg_length,
	               eccPubKey) == HASHLET_COMMAND_SUCCESS) {
		return verifyCount(oldCount, newCount);
	} else {
		perror("ERROR: Signature verification failed.\n");
		return 0;
	}
}

int verifyCount(int oldCount, int newCount) {
	if (oldCount < newCount) {
		PRINTDEBUG("Data verification success!");
		return 1;
	} else {
		perror("ERROR: Invalid count. Possible replay attack detected\n");
		return 0;
	}
}

void splitMessage(unsigned char* plaintext, int plaintext_len,
                  unsigned char* data, unsigned int* counter) {
	memcpy(counter, plaintext, UINT_LENGTH);
	memcpy(data, plaintext + UINT_LENGTH, plaintext_len - UINT_LENGTH);
}

int establishTCP() {
	int sockTCP, connectedSock;
	socklen_t clilen;
	struct sockaddr_in cli_addr;

	sockTCP = startTCPserver();

	if ((listen(sockTCP, 5)) < 0) {
		fprintf(stderr, "Error on listen --> %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	clilen = sizeof(cli_addr);
	connectedSock = accept(sockTCP, (struct sockaddr*)&cli_addr, &clilen);
	if (connectedSock < 0) {
		perror("ERROR on accept");
		exit(EXIT_FAILURE);
	} else {
		PRINTDEBUG("connection established");
	}

	return connectedSock;
}
