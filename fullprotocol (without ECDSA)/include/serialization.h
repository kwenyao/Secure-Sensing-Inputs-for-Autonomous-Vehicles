#ifndef SERIALIZATION_H_   /* Include guard */

#include "socket.h"

typedef struct {
	BYTE* nonce;
	BYTE* signature;
	BYTE* key;
	// BYTE* ecc;
	// BYTE* tag;
	// uint8_t has_nonce;
	// uint8_t has_ecc;
	uint8_t has_key;
} handshake;

typedef struct {
	unsigned char* encrypted_msg;
	unsigned char* aes_tag;
	uint32_t encrypted_msg_length;
	// struct lca_octet_buffer ecc_signature;
} message;

void initHandshake(handshake* hs);
// handshake createHandshake(int has_nonce, BYTE* nonce, int has_ecc, BYTE* ecc, BYTE* tag, BYTE* signature, int has_key, BYTE* key);
handshake createHandshake(BYTE* nonce, BYTE* signature, BYTE* key, int has_key);
void deleteHandshake(handshake *hs);
void hsAddNonce(handshake* hs, BYTE* nonce);
// void hsAddEcc(handshake *hs, BYTE *ecc, BYTE* tag);
void hsAddSign(handshake* hs, BYTE* signature);
void hsAddKey(handshake* hs, BYTE* key);

void printMessage(message msg);
void printHandshake(handshake hs);

int serializeHandshake(handshake hs, BYTE* buffer);
// handshake deserializeHandshake(BYTE* message, int hasNonce, int hasEcc, int hasKey);
handshake deserializeHandshake(BYTE* message, int hasKey);
void serializeData(message data, BYTE* buffer);
message deserializeData(BYTE* buffer);


#endif /* serialization_H */