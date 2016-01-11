#include "socket.h"
#include "serialization.c"

//SOCKET PROGRAMMING FUNCTIONS
BYTE* sendAndReceive(int sockfd, BYTE* send, int send_len);
int sending(int sockfd, BYTE* send, int send_len);

message send_message (unsigned char* data, UINT32 dataLength, unsigned char* AESkey, BYTE* nonce);

int main(int argc, char *argv[])
{
	/* VARIABLES FOR HANDSHAKE*/
	BYTE *nonceA, *nonceB, *nonceAB;
	BYTE *signNonceA, *signNonceAB, *signECCPubKey, *signACK;
	BYTE *boundAESkey, *AESkey;
	BYTE *serialMsg;
	int serialMsgLen = 0;
	unsigned char *encECCPubKey, *AEStag;

	/* VARIABLES FOR SOCKET PROGRAMMING */
	int sockfd, portno, n;
	struct sockaddr_in serv_addr;
	struct hostent *server;

	/* CONNECTING TO SERVER */
	if (argc < 3) {
		fprintf(stderr, "usage %s hostname port\n", argv[0]);
		exit(0);
	}
	portno = atoi(argv[2]);
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(argv[1]);
	if (server == NULL) {
		fprintf(stderr, "ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr,
	      (char *)&serv_addr.sin_addr.s_addr,
	      server->h_length);
	serv_addr.sin_port = htons(portno);
	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR connecting");

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
	serialMsg = sendAndReceive(sockfd, serialMsg, serialMsgLen);

	handshake BtoA = deserializeHandshake(serialMsg, 1, 0, 1);

	/* PARSE HANDSHAKE */
	if (BtoA.has_nonce)
	{
		nonceB = BtoA.nonce;
	}
	signNonceAB = BtoA.signature;
	if (BtoA.has_key)
	{
		boundAESkey = BtoA.key;
	}

	/* VERIFY MESSAGE RECEIVED */
	UINT32 unBoundDataLength;
	AESkey = RSAdecrypt(tpm.hContext, tpm.hSRK, boundAESkey, BOUND_AES_LENGTH, &unBoundDataLength);	// Use the Unbinding key to decrypt the encrypted AES key
	if (unBoundDataLength != AES_KEY_LENGTH)
	{
		printf("AES Key Error: Received key size is not %d bytes\n", AES_KEY_LENGTH);
		goto postlude;
	}

	nonceAB = malloc(NONCE_LENGTH * 2);
	memcpy(nonceAB, nonceA, NONCE_LENGTH);
	memcpy(nonceAB + NONCE_LENGTH, nonceB, NONCE_LENGTH);

	if (!isVerified(tpm.hContext, signNonceAB, SIGNATURE_LENGTH, nonceAB, NONCE_LENGTH * 2))
	{
		printf("Verification failed\n");
		goto postlude;
	}
	else
	{
		printf("Verification success!\n");
	}

	/* ENCRYPT AND SIGN ECC PUBLIC KEY */
	if (HASHLET_COMMAND_FAIL == ecc_gen_key())
	{
		goto postlude;
	}
	char*  pub_key = read_file(FILENAME_PUBLICKEY);	//read ECC public key
	struct lca_octet_buffer ecc_pub_key = lca_ascii_hex_2_bin (pub_key, 130);
	AEStag = malloc(TAG_LENGTH);
	encECCPubKey = aes_encrypt(ecc_pub_key.ptr, ecc_pub_key.len, AEStag, (unsigned char *)AESkey, nonceA);	//encrypt ECC public key
	signECCPubKey = sign(tpm.hContext, tpm.hSRK, (BYTE*)ecc_pub_key.ptr, ecc_pub_key.len);	//sign ECC public key

	/* CREATE HANDSHAKE AND SEND */
	handshake reply = createHandshake(0, NULL, 1, encECCPubKey, AEStag, signECCPubKey, 0, NULL);

	serialMsg = calloc(HANDSHAKE_LENGTH, sizeof(BYTE));
	serialMsgLen = serializeHandshake(reply, serialMsg);
	serialMsg = sendAndReceive(sockfd, serialMsg, serialMsgLen);

	handshake acknowledgment = deserializeHandshake(serialMsg, 0, 0, 0);

	/* VERIFY MESSAGE RECEIVED*/
	signACK = acknowledgment.signature;
	if (!isVerified(tpm.hContext, signACK, SIGNATURE_LENGTH, ecc_pub_key.ptr, ecc_pub_key.len))
	{
		fprintf(stderr, "Handshake unsuccessful\n");
		goto postlude;
	}
	else
	{
		printf("Handshake successful\n");
	}

	// unsigned long long int i = 0;
	// struct timeval start, end;
	// gettimeofday(&start, NULL);
	// for (i; i < 10; i++)
	// {
	message msg = send_message(INPUT, INPUTLEN, (unsigned char*)AESkey, nonceA);
	serialMsg = calloc(DATA_LENGTH, sizeof(BYTE));
	serializeData(msg, serialMsg);
	n = write(sockfd, serialMsg, DATA_LENGTH);
	if (n < 0) {
		printf("ERROR writing to socket\n");
		return 0;
	}
	// }
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

int sending(int sockfd, BYTE* send, int send_len) {
	int n = write(sockfd, send, send_len);
	if (n < 0)
	{
		printf("ERROR writing to socket\n");
		return 0;
	}
	return 1;
}

BYTE* sendAndReceive(int sockfd, BYTE* send, int send_len) {
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

message send_message (unsigned char* data, UINT32 dataLength, unsigned char* AESkey, BYTE* nonce) {
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
	msg.ecc_signature = ecc_sign(plaintext, msg.encrypted_msg_length);

	//send to receiver here
	if (counter == UINT_MAX) {
		counter = 1;
	} else {
		counter++;
	}
	free(plaintext);
	return msg;
}