#include "tpm.h"
#include "aes.h"
#include "ecc.h"
#include "constant.h"

#define MAX_INTEGER_DIGITS 20

#define HANDSHAKE_LENGTH SIGNATURE_LENGTH + NONCE_LENGTH + ENCRYPTED_AES_KEY_LENGTH + TAG_LENGTH + ENCRYPTED_ECC_PUBKEY_LENGTH
#define HS_SIGNATURE_POSITION 0
#define HS_NONCE_POSITION HS_SIGNATURE_POSITION + SIGNATURE_LENGTH
#define HS_KEY_POSITION HS_NONCE_POSITION + NONCE_LENGTH
#define HS_TAG_POSITION HS_KEY_POSITION + ENCRYPTED_AES_KEY_LENGTH
#define HS_ECC_POSITION HS_TAG_POSITION + TAG_LENGTH

#define ECC_SIGNATURE_LENGTH 64
#define ENCRYPTED_MSG_LENGTH_LENGTH 4

#define DATA_LENGTH 1024
#define DATA_SIGNATURE_POSITION 0
#define DATA_TAG_POSITION DATA_SIGNATURE_POSITION + ECC_SIGNATURE_LENGTH
#define DATA_ENC_MSG_LENGTH_POSITION DATA_TAG_POSITION + TAG_LENGTH
#define DATA_ENCRYPTED_MSG_POSITION DATA_ENC_MSG_LENGTH_POSITION + ENCRYPTED_MSG_LENGTH_LENGTH

int serializeHandshake(handshake hs, BYTE* buffer) {
	memcpy(buffer + HS_SIGNATURE_POSITION, hs.signature, SIGNATURE_LENGTH);

	if (hs.has_nonce == 1) {
		memcpy(buffer + HS_NONCE_POSITION, hs.nonce, NONCE_LENGTH);
	}

	if (hs.has_key == 1) {
		memcpy(buffer + HS_KEY_POSITION, hs.key, ENCRYPTED_AES_KEY_LENGTH);
	}

	if (hs.has_ecc == 1) {
		memcpy(buffer + HS_ECC_POSITION, hs.ecc, ENCRYPTED_ECC_PUBKEY_LENGTH);
		memcpy(buffer + HS_TAG_POSITION, hs.tag, TAG_LENGTH);
	}

	return HANDSHAKE_LENGTH;
}

handshake deserializeHandshake(BYTE* message, int hasNonce, int hasEcc, int hasKey) {
	handshake hs;
	hs.has_nonce = hasNonce;
	hs.has_ecc = hasEcc;
	hs.has_key = hasKey;
	hs.signature = malloc(SIGNATURE_LENGTH);
	memcpy(hs.signature, message + HS_SIGNATURE_POSITION, SIGNATURE_LENGTH);
	if (hasEcc == 1) {
		hs.ecc = malloc(ENCRYPTED_ECC_PUBKEY_LENGTH);
		memcpy(hs.ecc, message + HS_ECC_POSITION, ENCRYPTED_ECC_PUBKEY_LENGTH);
		hs.tag = malloc(TAG_LENGTH);
		memcpy(hs.tag, message + HS_TAG_POSITION, TAG_LENGTH);
	} else {
		hs.nonce = malloc(NONCE_LENGTH);
		memcpy(hs.nonce, message + HS_NONCE_POSITION, NONCE_LENGTH);
		if (hasKey) {
			hs.key  = malloc(ENCRYPTED_AES_KEY_LENGTH);
			memcpy(hs.key, message + HS_KEY_POSITION, ENCRYPTED_AES_KEY_LENGTH);
		}
	}
	return hs;
}

void serializeData(message data, BYTE* buffer) {
	struct lca_octet_buffer signature = data.ecc_signature;
	unsigned int signatureLen = signature.len;
	int encryptedMsgLen = data.encrypted_msg_length;
	char *encryptedMsgLenStr = malloc(5);
	snprintf(encryptedMsgLenStr, MAX_INTEGER_DIGITS, "%d", encryptedMsgLen);
	memcpy(buffer + DATA_SIGNATURE_POSITION, (BYTE*)signature.ptr, ECC_SIGNATURE_LENGTH);
	memcpy(buffer + DATA_TAG_POSITION, (BYTE*)data.aes_tag, TAG_LENGTH);
	memcpy(buffer + DATA_ENC_MSG_LENGTH_POSITION, encryptedMsgLenStr, ENCRYPTED_MSG_LENGTH_LENGTH);
	memcpy(buffer + DATA_ENCRYPTED_MSG_POSITION, (BYTE*)data.encrypted_msg, encryptedMsgLen);
}

message deserializeData(BYTE* buffer){
	message msg;

	//ecc_signature
	struct lca_octet_buffer temp;
	temp.len = ECC_SIGNATURE_LENGTH;
	temp.ptr = malloc(ECC_SIGNATURE_LENGTH);
	memcpy(temp.ptr, buffer + DATA_SIGNATURE_POSITION, ECC_SIGNATURE_LENGTH);
	msg.ecc_signature = temp;
	
	//aes_tag
	BYTE* aesTag = malloc(TAG_LENGTH);
	memcpy(aesTag, buffer + DATA_TAG_POSITION, TAG_LENGTH);
	msg.aes_tag = (unsigned char*)aesTag;

	//encrypted_msg_length
	BYTE* encryptedMsgLenByte = malloc(ENCRYPTED_MSG_LENGTH_LENGTH);
	memcpy(encryptedMsgLenByte, buffer + DATA_ENC_MSG_LENGTH_POSITION, ENCRYPTED_MSG_LENGTH_LENGTH);
	msg.encrypted_msg_length = atoi((char*)encryptedMsgLenByte);

	//ecc_signature
	BYTE* encryptedMsg = malloc(msg.encrypted_msg_length);
	memcpy(encryptedMsg, buffer + DATA_ENCRYPTED_MSG_POSITION, msg.encrypted_msg_length);
	msg.encrypted_msg = (unsigned char*)encryptedMsg;

	return msg;
}