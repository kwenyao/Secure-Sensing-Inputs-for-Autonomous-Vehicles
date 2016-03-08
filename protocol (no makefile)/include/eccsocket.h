#include "ecc.h"
#include "tpm.h"

typedef struct {
	BYTE* nonce;
	BYTE* ecc;
	BYTE* tag;
	BYTE* eccsignature;
	BYTE* key;
	int has_nonce;
	int has_ecc;
	int has_key;
} ecchandshake;

typedef struct {
	unsigned char* encrypted_msg;
	unsigned char* aes_tag;
	int encrypted_msg_length;
	struct lca_octet_buffer ecc_signature;
} message;

//SOCKET PROGRAMMING
void 			initEccHandshake(ecchandshake* hs);
ecchandshake 	createEccHandshake(int has_nonce, BYTE* nonce, int has_ecc, BYTE* ecc, BYTE* tag, BYTE* signature, int has_key, BYTE* key);
void 			deleteEccHandshake(ecchandshake *hs);
void 			hsAddNonce(ecchandshake* hs, BYTE* nonce);
void 			hsAddEcc(ecchandshake *hs, BYTE *ecc, BYTE* tag);
void 			hsAddEccSign(ecchandshake* hs, BYTE* signature);
void 			hsAddKey(ecchandshake* hs, BYTE* key);

// BYTE* sendAndReceive(int sockfd, handshake hs);
