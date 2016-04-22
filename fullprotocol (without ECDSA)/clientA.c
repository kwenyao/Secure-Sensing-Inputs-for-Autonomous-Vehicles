#include "serialization.h"
#include "aes.h"
#include "fileio.h"

//SOCKET PROGRAMMING FUNCTIONS
void waitFor (unsigned int secs);
BYTE* TCPsendAndReceive(int sockfd, BYTE* send, int send_len);
message createMessage (unsigned char* data, UINT32 dataLength, unsigned char* AESkey, BYTE* nonce);

int main(int argc, char *argv[])
{
	/* VARIABLES FOR HANDSHAKE*/
	BYTE *nonceA, *nonceB, *nonceAB;
	BYTE *signNonceA, *signNonceAB;
	// BYTE *signECCPubKey, *signACK;
	BYTE *boundAESkey, *AESkey = NULL;
	BYTE *serialMsg;
	int serialMsgLen = 0;
	// unsigned char *encECCPubKey, *AEStag;
	// struct lca_octet_buffer ecc_pub_key = {0, 0};

	/* VARIABLES FOR SOCKET PROGRAMMING */
	int portno;
	int server_s;	// server socket descriptor
	int client_s;	// client socket descriptor
	int sensor_s;
	struct sockaddr_in server_addr; 		// server Internet address
	struct sockaddr_in other_board_addr; 	// client Internet address
	struct sockaddr_in sensor_addr; 		// sensor Internet address
	struct hostent *server;

	// struct timeval start;

	/* VERIFY CERTIFICATE */
	if (!verifyCert(CERT_FILENAME, CA_CERT_FILENAME))
	{
		exit(1);
	}

	tpmArgs tpm = preamble();
	RSA *rsa = readPubKeyFromCert(CERT_FILENAME);

	/*********************************
	**********************************
	************ INITIATE ************
	********* TCP CONNECTION *********
	**********************************
	**********************************/
	portno = TCP_PORT_NUM;
	if ((server = gethostbyname(B_ETH0_ADDRESS)) == NULL)
	{
		PRINTDEBUG("ERROR no such host");
		exit(1);
	}
	if ((server_s = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		PRINTDEBUG("ERROR opening socket");
		exit(1);
	}
	char* interface = A_CLIENT_INTERFACE;
	setsockopt(server_s, SOL_SOCKET, SO_BINDTODEVICE, interface, 4 );

	bzero((char *) &server_addr, sizeof(struct sockaddr));
	server_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
	server_addr.sin_port = htons(portno);

	if (connect(server_s, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) < 0)
	{
		PRINTDEBUG("ERROR connecting");
		exit(1);
	}

	/* SET TIMEOUT FOR RECEIVING */
	struct timeval tv;
	tv.tv_sec = 5;  /* 30 Secs Timeout */
	tv.tv_usec = 0;  // Not init'ing this can cause strange errors
	setsockopt(server_s, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));	//set receive timeout

	

	/**********************************
	***********************************
	************ MESSAGE 1 ************
	***********************************
	***********************************/

	/* NONCE A AND SIGN(NONCE A) */
	nonceA = genNonce(tpm.hTPM, NONCE_LENGTH);
	signNonceA = sign(tpm.hContext, tpm.hSRK, nonceA, NONCE_LENGTH);

	/* CREATE HANDSHAKE AND SEND */
	handshake AtoB = createHandshake(nonceA, signNonceA, NULL, 0);

	serialMsg = calloc(HANDSHAKE_LENGTH, sizeof(BYTE));
	serialMsgLen = serializeHandshake(AtoB, serialMsg);
	serialMsg = TCPsendAndReceive(server_s, serialMsg, serialMsgLen);

	/**********************************
	***********************************
	************ MESSAGE 2 ************
	***********************************
	***********************************/
	handshake BtoA = deserializeHandshake(serialMsg, 1);

	/* PARSE HANDSHAKE */
	if (BtoA.has_key)
	{
		nonceB = BtoA.nonce;
		boundAESkey = BtoA.key;
	}
	signNonceAB = BtoA.signature;

	/* VERIFY MESSAGE RECEIVED */
	nonceAB = malloc(NONCE_LENGTH * 2);
	memcpy(nonceAB, nonceA, NONCE_LENGTH);
	memcpy(nonceAB + NONCE_LENGTH, nonceB, NONCE_LENGTH);

	if (!isVerified(signNonceAB, SIGNATURE_LENGTH, nonceAB, NONCE_LENGTH * 2, rsa))
	{
		printf("ERROR verification failed\n");
		goto postlude;
	}
	PRINTDEBUG("Signature verification success!");

	UINT32 unBoundDataLength;
	AESkey = RSAdecrypt(tpm.hContext, tpm.hSRK, boundAESkey, BOUND_AES_LENGTH, &unBoundDataLength);	// Use the Unbinding key to decrypt the encrypted AES key
	// printf("AES key is: "); printHex(AESkey, AES_KEY_LENGTH);
	if (unBoundDataLength != AES_KEY_LENGTH)
	{
		printf("ERROR AES key received size is not %d bytes\nReceived size is %d bytes.\n", AES_KEY_LENGTH, unBoundDataLength);
		goto postlude;
	}

	/**********************************
	***********************************
	************ MESSAGE 3 ************
	***********************************
	***********************************/

	// /* ENCRYPT AND SIGN ECC PUBLIC KEY */
	// ecc_pub_key = ecc_gen_key(0);
	// AEStag = malloc(TAG_LENGTH);
	// encECCPubKey = aes_encrypt(ecc_pub_key.ptr, ecc_pub_key.len, AEStag, (unsigned char *)AESkey, nonceA);	//encrypt ECC public key
	// signECCPubKey = sign(tpm.hContext, tpm.hSRK, (BYTE*)ecc_pub_key.ptr, ecc_pub_key.len);					//sign ECC public key

	// /* CREATE HANDSHAKE AND SEND */
	// handshake reply = createHandshake(0, NULL, 1, encECCPubKey, AEStag, signECCPubKey, 0, NULL);
	// serialMsg = calloc(HANDSHAKE_LENGTH, sizeof(BYTE));
	// serialMsgLen = serializeHandshake(reply, serialMsg);
	// serialMsg = TCPsendAndReceive(server_s, serialMsg, serialMsgLen);

	/**********************************
	***********************************
	************ MESSAGE 4 ************
	***********************************
	***********************************/
	// handshake acknowledgment = deserializeHandshake(serialMsg, 0, 0, 0);

	// /* VERIFY MESSAGE RECEIVED*/
	// signACK = acknowledgment.signature;
	// if (!isVerified(signACK, SIGNATURE_LENGTH, ecc_pub_key.ptr, ecc_pub_key.len, rsa))
	// {
	// 	fprintf(stderr, "Handshake unsuccessful\n");
	// 	goto postlude;
	// }
	// printf("Handshake successful\n");
	// free(serialMsg);


	/**********************************
	***********************************
	*********** UDP SET UP ************
	***********************************
	***********************************/
	close(server_s);
	setbuf(stdout, NULL);
	int sensor_addr_len = 0;
	sensor_s = startUDPserver(&sensor_addr_len, A_SERVER_INTERFACE);
	client_s = startUDPClient(&other_board_addr, A_CLIENT_INTERFACE, B_ETH0_ADDRESS);

	socklen_t clilen = sizeof(other_board_addr);

	/**********************************
	***********************************
	******** DATA TRANSMISSION ********
	***********************************
	***********************************/
	int buffer_in_len = -1, buffer_out_len = -1;
	unsigned char *buffer_in = NULL, *buffer_out = NULL;
	buffer_in = (void *) calloc(DATA_LENGTH, sizeof(unsigned char));
	buffer_out = (void *) calloc(MSG_NO_DATA_LENGTH + DATA_LENGTH, sizeof(unsigned char));
	message msg;

	while (1)
	{
		buffer_in_len = recvfrom(sensor_s, buffer_in, DATA_LENGTH, 0, (struct sockaddr *) &sensor_addr, &clilen);

		if(buffer_in_len!=DATA_LENGTH){
			printf("BUFFER NOT DATA LENGTH\n");
		}
		if (buffer_in_len < 0)
		{
			fprintf(stderr, "ERROR in recvfrom");
			goto datatrans;
		}
		else
		{
			msg = createMessage(buffer_in, buffer_in_len, (unsigned char*)AESkey, nonceA);
			serializeData(msg, (BYTE *)buffer_out);
			buffer_out_len = sendto(client_s, buffer_out, MSG_NO_DATA_LENGTH + buffer_in_len, 0, (struct sockaddr *) &other_board_addr, sizeof(struct sockaddr));
			
			
			//Bypass
			// buffer_out_len = sendto(client_s, buffer_in, buffer_in_len, 0, (struct sockaddr *) &other_board_addr, sizeof(struct sockaddr));

			if (buffer_out_len < 0)
			{
				fprintf(stderr, "ERROR in sendto");
				goto datatrans;
			}
		}
	}

datatrans:
	free(buffer_in);
	free(buffer_out);
	close(client_s);
	close(sensor_s);

postlude:
	close(server_s);
	free(nonceAB);
	postlude(tpm.hSRKPolicy, tpm.hContext);
	return 1;
}

void waitFor (unsigned int secs) {
	unsigned int retTime = time(0) + secs;		// Get finishing time.
	while (time(0) < retTime);    				// Loop until it arrives.
}

BYTE* TCPsendAndReceive(int sockfd, BYTE * send, int send_len) {
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

message createMessage (unsigned char* data, UINT32 dataLength, unsigned char* AESkey, BYTE * nonce) {
	static uint32_t counter = 1;
	if (counter % 100 == 0)
		printf("counter: %d\n", counter);

	//concatenate counter & message
	message msg;
	unsigned char* plaintext;
	plaintext = malloc(UINT_LENGTH + dataLength);
	memcpy(plaintext, &counter, UINT_LENGTH);
	memcpy(plaintext + UINT_LENGTH, data, dataLength);

	msg.encrypted_msg_length = UINT_LENGTH + (unsigned int) dataLength;
	if (msg.encrypted_msg_length != INPUT_MAX_LEN)
	{
		printf("msg.encrypted_msg_length: %d\n", msg.encrypted_msg_length);
		exit(1);
	}
	if (msg.encrypted_msg_length > INPUT_MAX_LEN) {
		printf("Message length is more than maximum %d bytes", INPUT_MAX_LEN);
		exit(1);
	}

	//AES encrypt message
	msg.aes_tag = malloc(TAG_LENGTH);//free later

	/* WITH AES ENCRYPTION */
	msg.encrypted_msg = aes_encrypt(plaintext, msg.encrypted_msg_length, msg.aes_tag, AESkey, nonce);
	// printHex(msg.encrypted_msg, msg.encrypted_msg_length);

	/* WITHOUT AES ENCRYPTION */
	// msg.encrypted_msg = malloc(msg.encrypted_msg_length);
	// memcpy(msg.encrypted_msg, plaintext, msg.encrypted_msg_length);

	/* WITH ECDSA SIGN MESSAGE */
	// msg.ecc_signature = ecc_sign(plaintext, msg.encrypted_msg_length, 0);

	/* INCREMENT COUNTER */
	if (counter == UINT_MAX) {
		counter = 1;
	} else {
		counter++;
	}

	free(plaintext);
	//free(msg.aes_tag);
	return msg;
}