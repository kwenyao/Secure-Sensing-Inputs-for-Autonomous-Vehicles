#include "ecc.h"
#include "tpm.h"

typedef struct {
	BYTE* nonce;
	BYTE* ecc;
	BYTE* tag;
	BYTE* signature;
	BYTE* key;
	int has_nonce;
	int has_ecc;
	int has_key;
} handshake;

typedef struct {
	unsigned char* encrypted_msg;
	unsigned char* aes_tag;
	int encrypted_msg_length;
	struct lca_octet_buffer ecc_signature;
} message;

//SOCKET PROGRAMMING
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
