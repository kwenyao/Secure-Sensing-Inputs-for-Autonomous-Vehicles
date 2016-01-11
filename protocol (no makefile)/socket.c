#include "socket.h"

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

void hsPrint(handshake hs) {
	if (hs.has_nonce) {
		printf("Nonce: ");
		printHex(hs.nonce, NONCE_LENGTH);
	}
	
	if (hs.has_ecc) {
		printf("ECC: ");
		printHex(hs.ecc, ENCRYPTED_ECC_PUBKEY_LENGTH);
	}
	
	printf("Signature: ");
	printHex(hs.signature, SIGNATURE_LENGTH);
	
	if (hs.has_key) {
		printf("Key: ");
		printHex(hs.key, SIGNATURE_LENGTH);
	}
}