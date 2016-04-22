#include "serialization.h"

void initHandshake(handshake* hs) {
	// hs->has_nonce = 0;
	// hs->has_ecc = 0;
	hs->has_key = 0;
	hs->nonce = NULL;
	// hs->ecc = NULL;
	// hs->tag = NULL;
	hs->signature = NULL;
	hs->key = NULL;
}

void hsAddNonce(handshake *hs, BYTE *nonce) {
	// hs->has_nonce = 1;
	hs->nonce = nonce;
}

// void hsAddEcc(handshake *hs, BYTE *ecc, BYTE* tag) {
// 	hs->has_ecc = 1;
// 	hs->ecc = ecc;
// 	hs->tag = tag;
// }

void hsAddSign(handshake* hs, BYTE *signature) {
	hs->signature = signature;
}

void hsAddKey(handshake* hs, BYTE *key) {
	hs->has_key = 1;
	hs->key = key;
}

// handshake createHandshake(int has_nonce, BYTE* nonce, int has_ecc, BYTE* ecc, BYTE* tag, BYTE* signature, int has_key, BYTE* key) {
handshake createHandshake(BYTE* nonce, BYTE* signature, BYTE* key, int has_key) {
	handshake hs;
	initHandshake(&hs);
	hsAddSign(&hs, signature);
	hsAddNonce(&hs, nonce);
	// if (has_nonce) {
	// 	hsAddNonce(&hs, nonce);
	// }
	// if (has_ecc) {
	// 	hsAddEcc(&hs, ecc, tag);
	// }
	if (has_key) {
		hsAddKey(&hs, key);
	}
	return hs;
}

void deleteHandshake(handshake *hs) {
	free(hs->nonce);
	// free(hs->ecc);
	// free(hs->tag);
	free(hs->signature);
	free(hs->key);
	// hs->has_nonce = 0;
	// hs->has_ecc = 0;
	hs->has_key = 0;
}

void printMessage(message msg) {
	printf("encrypted message: "); printHex(msg.encrypted_msg, msg.encrypted_msg_length);
	printf("aes tag: "); printHex(msg.aes_tag, TAG_LENGTH);
	printf("encrypted message length: %d\n", msg.encrypted_msg_length);
	// printf("ecc signature: "); output_hex(stdout, msg.ecc_signature);
}

void printHandshake(handshake hs) {
	printf("signature: "); printHex(hs.signature, SIGNATURE_LENGTH);
	// if (hs.has_nonce) {
	printf("nonce: "); printHex(hs.nonce, NONCE_LENGTH);
	// }
	// if (hs.has_ecc) {
	// 	printf("ecc pubkey: "); printHex(hs.ecc, ECC_PUBKEY_LENGTH);
	// 	printf("tag: "); printHex(hs.tag, TAG_LENGTH);
	// }
	if (hs.has_key) {
		printf("boundAESkey: "); printHex(hs.key, BOUND_AES_LENGTH);
	}
}

int serializeHandshake(handshake hs, BYTE* buffer) {
	memcpy(buffer + HS_SIGNATURE_POSITION, hs.signature, SIGNATURE_LENGTH);

	//if (hs.has_nonce == 1) {
	memcpy(buffer + HS_NONCE_POSITION, hs.nonce, NONCE_LENGTH);
	//}

	if (hs.has_key == 1) {
		memcpy(buffer + HS_KEY_POSITION, hs.key, ENCRYPTED_AES_KEY_LENGTH);
	}

	// if (hs.has_ecc == 1) {
	// 	memcpy(buffer + HS_ECC_POSITION, hs.ecc, ENCRYPTED_ECC_PUBKEY_LENGTH);
	// 	memcpy(buffer + HS_TAG_POSITION, hs.tag, TAG_LENGTH);
	// }

	return HANDSHAKE_LENGTH;
}

// handshake deserializeHandshake(BYTE* message, int hasNonce, int hasEcc, int hasKey) {
handshake deserializeHandshake(BYTE* message, int hasKey) {
	handshake hs;
	// hs.has_nonce = hasNonce;
	// hs.has_ecc = hasEcc;
	hs.has_key = hasKey;
	hs.signature = malloc(SIGNATURE_LENGTH);
	memcpy(hs.signature, message + HS_SIGNATURE_POSITION, SIGNATURE_LENGTH);

	// No ECC
	hs.nonce = malloc(NONCE_LENGTH);
	memcpy(hs.nonce, message + HS_NONCE_POSITION, NONCE_LENGTH);
	if (hasKey) {
		hs.key  = malloc(ENCRYPTED_AES_KEY_LENGTH);
		memcpy(hs.key, message + HS_KEY_POSITION, ENCRYPTED_AES_KEY_LENGTH);
	}

	//With ECC
	// if (hasEcc == 1) {
	// 	hs.ecc = malloc(ENCRYPTED_ECC_PUBKEY_LENGTH);
	// 	memcpy(hs.ecc, message + HS_ECC_POSITION, ENCRYPTED_ECC_PUBKEY_LENGTH);
	// 	hs.tag = malloc(TAG_LENGTH);
	// 	memcpy(hs.tag, message + HS_TAG_POSITION, TAG_LENGTH);
	// } else {
	// 	hs.nonce = malloc(NONCE_LENGTH);
	// 	memcpy(hs.nonce, message + HS_NONCE_POSITION, NONCE_LENGTH);
	// 	if (hasKey) {
	// 		hs.key  = malloc(ENCRYPTED_AES_KEY_LENGTH);
	// 		memcpy(hs.key, message + HS_KEY_POSITION, ENCRYPTED_AES_KEY_LENGTH);
	// 	}
	// }
	return hs;
}

void serializeData(message data, BYTE* buffer) {
	// struct lca_octet_buffer signature = data.ecc_signature;
	int encryptedMsgLen = data.encrypted_msg_length;
	//char *encryptedMsgLenStr = malloc(5);
	char encryptedMsgLenStr[5];
	snprintf(encryptedMsgLenStr, MAX_INTEGER_DIGITS, "%d", encryptedMsgLen); //convert msg length to char array
	
	// sprintf(encryptedMsgLenStr, "%d", encryptedMsgLen);

	// memcpy(buffer + MSG_SIGNATURE_POSITION, (BYTE*)signature.ptr, ECC_SIGNATURE_LENGTH);
	memcpy(buffer + MSG_TAG_POSITION, (BYTE*)data.aes_tag, TAG_LENGTH);
	memcpy(buffer + MSG_ENC_MSG_LENGTH_POSITION, encryptedMsgLenStr, ENCRYPTED_MSG_LENGTH_LENGTH);
	memcpy(buffer + MSG_ENCRYPTED_MSG_POSITION, (BYTE*)data.encrypted_msg, encryptedMsgLen);

	free(data.aes_tag);//malloced in createMessage(), no more use
	//free(encryptedMsgLenStr);
}

message deserializeData(BYTE* buffer) {
	message msg;

	//ecc_signature
	// struct lca_octet_buffer temp;
	// temp.len = ECC_SIGNATURE_LENGTH;
	// temp.ptr = malloc(ECC_SIGNATURE_LENGTH);
	// memcpy(temp.ptr, buffer + MSG_SIGNATURE_POSITION, ECC_SIGNATURE_LENGTH);
	// msg.ecc_signature = temp;

	//aes_tag
	BYTE* aesTag = malloc(TAG_LENGTH);
	memcpy(aesTag, buffer + MSG_TAG_POSITION, TAG_LENGTH);
	msg.aes_tag = (unsigned char*)aesTag;
	// printf("1\n");

	//encrypted_msg_length
	BYTE* encryptedMsgLenByte = malloc(ENCRYPTED_MSG_LENGTH_LENGTH);
	memcpy(encryptedMsgLenByte, buffer + MSG_ENC_MSG_LENGTH_POSITION, ENCRYPTED_MSG_LENGTH_LENGTH);
	msg.encrypted_msg_length = atoi((char*)encryptedMsgLenByte);
	// printf("2\n");

	//encrypted message
	BYTE* encryptedMsg = malloc(msg.encrypted_msg_length);
	// BYTE* encryptedMsg = malloc(121
	memcpy(encryptedMsg, buffer + MSG_ENCRYPTED_MSG_POSITION, msg.encrypted_msg_length);
	msg.encrypted_msg = (unsigned char*)encryptedMsg;
	// printf("3\n");

	free(aesTag);
	free(encryptedMsgLenByte);
	free(encryptedMsg);

	return msg;
}