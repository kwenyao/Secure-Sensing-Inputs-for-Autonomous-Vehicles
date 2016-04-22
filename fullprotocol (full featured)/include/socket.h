#ifndef SOCKET_H_   /* Include guard */
#define SOCKET_H_

#include "ecc.h"
#include "tpm.h"

typedef struct {
	BYTE* nonce;
	BYTE* ecc;
	BYTE* tag;
	BYTE* signature;
	BYTE* key;
	uint8_t has_nonce;
	uint8_t has_ecc;
	uint8_t has_key;
} handshake;

typedef struct {
	unsigned char* encrypted_msg;
	unsigned char* aes_tag;
	uint32_t encrypted_msg_length;
	struct lca_octet_buffer ecc_signature;
} message;

int startTCPserver(char* interfaceName);
int startUDPClient(struct sockaddr_in *client_addr, char *interfaceName);
int startUDPserver(int *addr_len, char *interfaceName);

void initHandshake(handshake* hs);
handshake createHandshake(int has_nonce, BYTE* nonce, int has_ecc, BYTE* ecc, BYTE* tag, BYTE* signature, int has_key, BYTE* key);
void deleteHandshake(handshake *hs);
void hsAddNonce(handshake* hs, BYTE* nonce);
void hsAddEcc(handshake *hs, BYTE *ecc, BYTE* tag);
void hsAddSign(handshake* hs, BYTE* signature);
void hsAddKey(handshake* hs, BYTE* key);

void printMessage(message msg);
void printHandshake(handshake hs);
// BYTE* sendAndReceive(int sockfd, handshake hs);

#endif /* SOCKET_H */
