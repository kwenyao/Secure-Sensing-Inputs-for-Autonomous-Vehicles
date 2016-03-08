#include "socket.h"
#include "serialization.c"
#include "fileio.h"
#include <time.h>
//SOCKET PROGRAMMING FUNCTIONS
void waitFor (unsigned int secs);
BYTE* TCPsendAndReceive(int sockfd, BYTE* send, int send_len);
message createMessage (unsigned char* data, UINT32 dataLength, unsigned char* AESkey, BYTE* nonce);

int main(int argc, char *argv[])
{
	/* VARIABLES FOR HANDSHAKE*/
	BYTE *nonceA, *nonceB, *nonceAB;
	BYTE *signNonceA, *signNonceAB, *signECCPubKey, *signACK;
	BYTE *boundAESkey, *AESkey;
	BYTE *serialMsg;
	int serialMsgLen = 0;
	unsigned char *encECCPubKey, *AEStag;
	struct lca_octet_buffer ecc_pub_key = {0, 0};

	/* VARIABLES FOR SOCKET PROGRAMMING */
	int sockfd, portno;
	struct sockaddr_in serv_addr;
	struct hostent *server;

	// struct timeval start;

	/**********************************
	***********************************
	************ INITIATE *************
	********* TCP CONNECTION **********
	***********************************
	***********************************/
	if (argc < 3)
	{
		fprintf(stderr, "usage %s hostname port\n", argv[0]);
		exit(1);
	}
	portno = atoi(argv[2]);
	if ((server = gethostbyname(argv[1])) == NULL)
	{
		fprintf(stderr, "ERROR no such host\n");
		exit(1);
	}
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("ERROR opening socket");
		exit(1);
	}

	bzero((char *) &serv_addr, sizeof(struct sockaddr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(portno);

	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr)) < 0)
	{
		printf("ERROR connecting");
		exit(1);
	}

	/* SET TIMEOUT FOR RECEIVING */
	struct timeval tv;
	tv.tv_sec = 5;  /* 30 Secs Timeout */
	tv.tv_usec = 0;  // Not init'ing this can cause strange errors
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));	//set receive timeout

	tpmArgs tpm = preamble();

	/* NONCE A AND SIGN(NONCE A) */
	nonceA = genNonce(tpm.hTPM, NONCE_LENGTH);
	signNonceA = sign(tpm.hContext, tpm.hSRK, nonceA, NONCE_LENGTH);

	/* CREAT HANDSHAKE AND SEND */
	handshake AtoB = createHandshake(1, nonceA, 0, NULL, NULL, signNonceA, 0, NULL);

	serialMsg = calloc(HANDSHAKE_LENGTH, sizeof(BYTE));
	serialMsgLen = serializeHandshake(AtoB, serialMsg);
	serialMsg = TCPsendAndReceive(sockfd, serialMsg, serialMsgLen);

	handshake BtoA = deserializeHandshake(serialMsg, 1, 0, 1);

	/* PARSE HANDSHAKE */
	if (BtoA.has_nonce && BtoA.has_key)
	{
		nonceB = BtoA.nonce;
		boundAESkey = BtoA.key;
	}
	signNonceAB = BtoA.signature;

	/* VERIFY MESSAGE RECEIVED */
	UINT32 unBoundDataLength;
	AESkey = RSAdecrypt(tpm.hContext, tpm.hSRK, boundAESkey, BOUND_AES_LENGTH, &unBoundDataLength);	// Use the Unbinding key to decrypt the encrypted AES key
	if (unBoundDataLength != AES_KEY_LENGTH)
	{
		printf("ERROR AES key received size is not %d bytes\n", AES_KEY_LENGTH);
		goto postlude;
	}

	nonceAB = malloc(NONCE_LENGTH * 2);
	memcpy(nonceAB, nonceA, NONCE_LENGTH);
	memcpy(nonceAB + NONCE_LENGTH, nonceB, NONCE_LENGTH);

	if (!isVerified(tpm.hContext, signNonceAB, SIGNATURE_LENGTH, nonceAB, NONCE_LENGTH * 2))
	{
		printf("ERROR verification failed\n");
		goto postlude;
	}
	printf("Verification success!\n");

	/* ENCRYPT AND SIGN ECC PUBLIC KEY */
	ecc_pub_key = ecc_gen_key(0);
	AEStag = malloc(TAG_LENGTH);
	encECCPubKey = aes_encrypt(ecc_pub_key.ptr, ecc_pub_key.len, AEStag, (unsigned char *)AESkey, nonceA);	//encrypt ECC public key
	signECCPubKey = sign(tpm.hContext, tpm.hSRK, (BYTE*)ecc_pub_key.ptr, ecc_pub_key.len);					//sign ECC public key

	/* CREATE HANDSHAKE AND SEND */
	handshake reply = createHandshake(0, NULL, 1, encECCPubKey, AEStag, signECCPubKey, 0, NULL);

	serialMsg = calloc(HANDSHAKE_LENGTH, sizeof(BYTE));
	serialMsgLen = serializeHandshake(reply, serialMsg);
	serialMsg = TCPsendAndReceive(sockfd, serialMsg, serialMsgLen);

	handshake acknowledgment = deserializeHandshake(serialMsg, 0, 0, 0);

	/* VERIFY MESSAGE RECEIVED*/
	signACK = acknowledgment.signature;
	if (!isVerified(tpm.hContext, signACK, SIGNATURE_LENGTH, ecc_pub_key.ptr, ecc_pub_key.len))
	{
		fprintf(stderr, "Handshake unsuccessful\n");
		goto postlude;
	}
	printf("Handshake successful\n");
	close(sockfd);

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		printf("socket");
		exit(1);
	}

	/**********************************
	***********************************
	******** DATA TRANSMISSION ********
	***********************************
	***********************************/

	unsigned long long int i;
	// struct timeval start, end;
	// gettimeofday(&start, NULL);
	for (i = 0; i < 10; i++)
	{
		message msg = createMessage((unsigned char*)INPUT, DATA_LENGTH, (unsigned char*)AESkey, nonceA);
		serialMsg = calloc(MSG_LENGTH, sizeof(BYTE));
		serializeData(msg, serialMsg);
		sendto(sockfd, serialMsg, MSG_LENGTH, 0, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr));
	}
	// gettimeofday(&end, NULL);
	// printf ("Total time = %f seconds\n",
	//         (double) (end.tv_usec - start.tv_usec) / 1000000 +
	//         (double) (end.tv_sec - start.tv_sec));

postlude:
	free(serialMsg);
	free(nonceAB);
	free(AEStag);
	close(sockfd);
	postlude(tpm.hSRKPolicy, tpm.hContext);
	return 1;
}

void waitFor (unsigned int secs) {
	unsigned int retTime = time(0) + secs;     // Get finishing time.
	while (time(0) < retTime);    // Loop until it arrives.
}

BYTE* TCPsendAndReceive(int sockfd, BYTE* send, int send_len) {
	BYTE *recvbuf = calloc(HANDSHAKE_LENGTH, sizeof(BYTE));
send: ;//send handshake message
	int n = write(sockfd, send, send_len);
	if (n < 0)
	{
		printf("ERROR writing to socket\n");
	}

	//receive handshake reply
	n = read(sockfd, recvbuf, HANDSHAKE_LENGTH);
	if (n < 0)
	{
		printf("ERROR reading MESSAGE from socket\n");
		goto send;
	}
	return recvbuf;
}

message createMessage (unsigned char* data, UINT32 dataLength, unsigned char* AESkey, BYTE* nonce) {
	static unsigned int counter = 1;

	//concatenate counter & message
	message msg;
	unsigned char* plaintext;
	plaintext = malloc(UINT_LENGTH + dataLength);
	memcpy(plaintext, &counter, UINT_LENGTH);
	memcpy(plaintext + UINT_LENGTH, data, dataLength);

	msg.encrypted_msg_length = UINT_LENGTH + (unsigned int) dataLength;
	if (msg.encrypted_msg_length > INPUT_MAX_LEN) {
		printf("Message length is more than maximum %d bytes", INPUT_MAX_LEN);
		exit(1);
	}

	//AES encrypt message
	msg.aes_tag = malloc(TAG_LENGTH);
	msg.encrypted_msg = aes_encrypt(plaintext, msg.encrypted_msg_length, msg.aes_tag, AESkey, nonce);

	//ECDSA sign message
	msg.ecc_signature = ecc_sign(plaintext, msg.encrypted_msg_length, 0);
	//send to receiver here
	if (counter == UINT_MAX) {
		counter = 1;
	} else {
		counter++;
	}
	free(plaintext);
	// printMessage(msg);
	return msg;
}