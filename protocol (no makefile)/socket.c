#include "socket.h"

int startTCPserver(char* interfaceName) {
	int sockfd;
	struct sockaddr_in serv_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interfaceName, 4 );

	if (sockfd < 0) {
		fprintf(stderr, "Error creating TCP server socket --> %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(TCP_PORT_NUM);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("Error on binding socket\n");
		exit(EXIT_FAILURE);
	} else {
		PRINTDEBUG("Server started\n");
	}

	return sockfd;
}

int startUDPClient(struct sockaddr_in *client_addr, char *interfaceName) {
	int clientSock;
	int broadcastPermission = 1;
	struct ifreq client_interface;
	int reuse_addr = 1; //Variable reuse_addr is 1 to identify that we want to enable a particular option (0 will disable).

	clientSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (clientSock < 0) {
		fprintf(stderr, "Error creating UDP client socket --> %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (setsockopt(clientSock, SOL_SOCKET, SO_BROADCAST,
	               (void *)&broadcastPermission,
	               sizeof(broadcastPermission)) < 0) {
		perror("Start UDP client setsockopt error");
	}
	strncpy(client_interface.ifr_ifrn.ifrn_name, interfaceName, IFNAMSIZ);
	if (setsockopt(clientSock,
	               SOL_SOCKET,
	               SO_BINDTODEVICE,
	               (char *)&client_interface,
	               sizeof(client_interface)) < 0) {
		strncpy(client_interface.ifr_ifrn.ifrn_name, "eth2", IFNAMSIZ);
		if (setsockopt(clientSock,
		               SOL_SOCKET,
		               SO_BINDTODEVICE,
		               (char *)&client_interface,
		               sizeof(client_interface)) < 0) {
			perror("sendpacket: setting SO_BINDTODEVICE");
		}
	}

	//Set the socket reusable, The SOL_SOCKET keyword means that you want to set socket level setting/option, it will be protocol independent.
	setsockopt(clientSock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(int));

	// Fill-in my socket's address information and bind the socket - See winsock.h for a description of struct sockaddr_in
	memset(client_addr, 0, sizeof(*client_addr));
	client_addr->sin_family = AF_INET; // Address family to useinet_addr(broadcastIP);
	client_addr->sin_port = htons(UDP_PORT_NUM); // Port number to use
	client_addr->sin_addr.s_addr = inet_addr("255.255.255.255");

	return clientSock;
}

int startUDPserver(int *addr_len, char* interfaceName) {
	int serverSock;
	int reuse_addr = 1; // 1 to identify that we want to enable a particular option (0 will disable).
	struct ifreq server_interface;
	struct sockaddr_in server_addr;

	serverSock = socket(AF_INET, SOCK_DGRAM, 0);
	if (serverSock < 0) {
		fprintf(stderr, "Error creating UDP server socket --> %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	strncpy(server_interface.ifr_ifrn.ifrn_name, interfaceName, IFNAMSIZ);
	if (setsockopt(serverSock,
	               SOL_SOCKET,
	               SO_BINDTODEVICE,
	               (char *)&server_interface,
	               sizeof(server_interface)) < 0) {
		strncpy(server_interface.ifr_ifrn.ifrn_name, "eth2", IFNAMSIZ);
		if (setsockopt(serverSock,
		               SOL_SOCKET,
		               SO_BINDTODEVICE,
		               (char *)&server_interface,
		               sizeof(server_interface)) < 0) {
			perror("sendpacket: setting SO_BINDTODEVICE");
		}
	}

	setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(int));

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(UDP_PORT_NUM);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	bzero(&(server_addr.sin_zero), 8);

	if (bind(serverSock, (struct sockaddr *)&server_addr,
	         sizeof(struct sockaddr)) < 0) {
		perror("Bind");
		exit(EXIT_FAILURE);
	}

	*addr_len = sizeof(struct sockaddr);

	printf("UDPServer Waiting for client on port %d\n", UDP_PORT_NUM);
	fflush(stdout);

	return serverSock;
}

void initHandshake(handshake* hs) {
	hs->has_nonce = 0;
	hs->has_ecc = 0;
	hs->has_key = 0;
	hs->nonce = NULL;
	hs->ecc = NULL;
	hs->tag = NULL;
	hs->signature = NULL;
	hs->key = NULL;
}

void hsAddNonce(handshake *hs, BYTE *nonce) {
	hs->has_nonce = 1;
	hs->nonce = nonce;
}
void hsAddEcc(handshake *hs, BYTE *ecc, BYTE* tag) {
	hs->has_ecc = 1;
	hs->ecc = ecc;
	hs->tag = tag;
}
void hsAddSign(handshake* hs, BYTE *signature) {
	hs->signature = signature;
}
void hsAddKey(handshake* hs, BYTE *key) {
	hs->has_key = 1;
	hs->key = key;
}

handshake createHandshake(int has_nonce, BYTE* nonce, int has_ecc, BYTE* ecc, BYTE* tag, BYTE* signature, int has_key, BYTE* key) {
	handshake hs;
	initHandshake(&hs);
	hsAddSign(&hs, signature);
	if (has_nonce) {
		hsAddNonce(&hs, nonce);
	}
	if (has_ecc) {
		hsAddEcc(&hs, ecc, tag);
	}
	if (has_key) {
		hsAddKey(&hs, key);
	}
	return hs;
}
void deleteHandshake(handshake *hs) {
	free(hs->nonce);
	free(hs->ecc);
	free(hs->tag);
	free(hs->signature);
	free(hs->key);
	hs->has_nonce = 0;
	hs->has_ecc = 0;
	hs->has_key = 0;
}

void printMessage(message msg) {
	printf("encrypted message: "); printHex(msg.encrypted_msg, msg.encrypted_msg_length);
	printf("aes tag: "); printHex(msg.aes_tag, TAG_LENGTH);
	printf("encrypted message length: %d\n", msg.encrypted_msg_length);
	printf("ecc signature: "); output_hex(stdout, msg.ecc_signature);
}

void printHandshake(handshake hs) {
	printf("signature: "); printHex(hs.signature, SIGNATURE_LENGTH);
	if (hs.has_nonce) {
		printf("nonce: "); printHex(hs.nonce, NONCE_LENGTH);
	}
	if (hs.has_ecc) {
		printf("ecc pubkey: "); printHex(hs.ecc, ECC_PUBKEY_LENGTH);
		printf("tag: "); printHex(hs.tag, TAG_LENGTH);
	}
	if (hs.has_key) {
		printf("boundAESkey: "); printHex(hs.key, BOUND_AES_LENGTH);
	}
}