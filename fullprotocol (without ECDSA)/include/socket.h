#ifndef SOCKET_H_   /* Include guard */
#define SOCKET_H_

#include "ecc.h"
#include "tpm.h"

int startTCPserver(char* interfaceName);
int startUDPClient(struct sockaddr_in *client_addr, char *interfaceName, char *toIPAddr);
int startUDPserver(int *addr_len, char *interfaceName);


// BYTE* sendAndReceive(int sockfd, handshake hs);

#endif /* SOCKET_H */
