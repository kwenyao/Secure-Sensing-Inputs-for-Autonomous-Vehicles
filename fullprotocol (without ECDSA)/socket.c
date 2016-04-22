#include "socket.h"
#define SO_MAX_UDP_QUE          0x0010

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
		PRINTDEBUG("Server started");
	}

	return sockfd;
}

int startUDPClient(struct sockaddr_in *client_addr, char *interfaceName, char *toIPAddr) {
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
	client_addr->sin_addr.s_addr = inet_addr(toIPAddr);

	return clientSock;
}

int startUDPserver(int *addr_len, char* interfaceName) {
	int serverSock;
	int reuse_addr = 1; // 1 to identify that we want to enable a particular option (0 will disable).
	struct ifreq server_interface;
	struct sockaddr_in server_addr;
	struct timeval timeout;
	int udp_queue = 10240;

	timeout.tv_sec = CONNECTION_TIMEOUT;
	timeout.tv_usec = 0;

	serverSock = socket(AF_INET, SOCK_DGRAM, 0);
	if (serverSock < 0) {
		fprintf(stderr, "Error creating UDP server socket --> %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	setsockopt(serverSock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));	//set receive timeout
	setsockopt(serverSock, SOL_SOCKET, SO_MAX_UDP_QUE, &udp_queue, sizeof(int));
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

