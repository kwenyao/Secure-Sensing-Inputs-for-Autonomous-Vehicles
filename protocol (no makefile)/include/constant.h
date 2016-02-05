#include <argp.h>
#include <assert.h>

#include <libcryptoauth.h>
#include <limits.h>

#include <netinet/in.h>
#include <netdb.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <tss/platform.h>
#include <tss/tspi.h>
#include <tss/tss_defines.h>
#include <tss/tss_error.h>
#include <tss/tss_structs.h>
#include <tss/tss_typedef.h>

#include <trousers/trousers.h>

#include <unistd.h>

#include "base64.h"

//TPM
#define SRK_PASSWORD "password123"
#define SRK_PASSWORD_LENGTH (sizeof(SRK_PASSWORD) - 1)
#define SIGN_KEY_UUID {0,0,0,0,0,{0,0,0,2,11}}
#define BACKUP_KEY_UUID {0,0,0,0,0,{0,0,0,2,10}}
#define PADDING_SCHEME TSS_SS_RSASSAPKCS1V15_SHA1
#define DEBUG 0
#define PRINTDEBUG(message) if(DEBUG){printf("Line %d) %s\n", __LINE__, message);}
#define DBG(message, tResult) if(DEBUG){printf("Line %d, %s) %s returned 0x%08x. %s.\n", __LINE__, __FUNCTION__, message, tResult, (char *)Trspi_Error_String(tResult));}
#define SIGNATURE_FILENAME "/home/debian/fullprotocol/signature.dat"
#define PUBLIC_KEY_FILENAME "/home/debian/fullprotocol/signingkey.pub"
#define OTHER_PUBLIC_KEY_FILENAME "/home/debian/fullprotocol/otherPublicKey.pub"
#define SIGNATURE_LENGTH 256
#define ENCRYPTED_AES_KEY_LENGTH 256
#define ECC_PUBKEY_LENGTH 65
#define ECC_SIGNATURE_LENGTH 64
#define ENCRYPTED_ECC_PUBKEY_LENGTH ECC_PUBKEY_LENGTH

#define MESSAGE_RECEIVED EXIT_SUCCESS

//ECC
#define NUM_ARGS 1
#define HASHLET_COMMAND_FAIL EXIT_FAILURE
#define HASHLET_COMMAND_SUCCESS EXIT_SUCCESS
#define ECC_PUBLIC_KEY_FILENAME "/home/debian/fullprotocol/eccpubkey.txt"
#define INPUT "helloFoIZHD34mnCtgf7Dy3YMo3muea24AhEAYCHc2pl0Ta5LxooEHgfxIk0K2os1ytYeTu14k3YQYVHgVaWBHrGH3V45nnT3kNR5IOUJnVi71hvlTbQG2SnK1ALMpI9z3G9OYFJJWOKlzi7yvPkIszQeSTwi8HOuZflcNEsKxHmrywEG9SgJFZiPCkfSmngoGr2YmmQ2oxIwZbmHp9gvIuIea7KNv658eSHWUotIFQEWMtZjBQUa6hQfSK2SuT9r1BRyb9YPEOifh96tboCCen09uynkFw81uiBRemL1emPjZH5tBx5rmWlYjj3T1v3N4QXHjeWQFm5qtePTAksn8zBsN55KKtfIlySuWm1p3YNNIqPw2NNaaJMCuQbBXgASGkCP97Gqt9jJ6R9MqoallaRKwZU8PWQEjn0QIORxiPt0fpWHFB00nxI4HDahR3Tgn8AEIbuL4NZzAMuEH3w4e9PpBYbRVRqyo56ZZ7uotpZBC3hDRk150TrAj1siX45lfSmg6tkJcWLf06cm81r6xxwWisP0Y8wanF8Np6qmFTScoNYK3PiKLnx97i7wKj8CYTgP4OQK5rA2Hpk07iZr3AxKjIQHXBBewBCsCYcVH1Xls895rmo6ix6V0cLRJkiBwRxk0pgVCPYx7zntMM9pFkyu12PFJh2xghhk7zYCsOhJ8YM4xrZc7Kc1XuxRKRN0iA5nHUgls9W8SfwvQqsilY1auxlUC5T3fzCyFzrHTfrU9VPQicHS2NrG3sQXiVm4bXIEYliWxI9ShlMwPNGKuEZRmXkTKnFhpNVX2bGc5IG5kmMh9GsiYsRSasNDBYCUt6KTWlcjnIvu8iFNqKEhFPEQ8WGrptUet1QEi2BiZw6GvmUGWiABpV8mptiMKkEtSN3zA7cLThAD2jc2ekUhZppmxioeVj4cjbyojVZ6xFP2UiUBwRxk0pgVCPYx7zntMM9pFkyu12PFJh2xghhk7zYCsOhJ8YM4xrZc7Kc1XuxRKRN0iA5nHUgls9W8SfwvQqsilY1auxlUC5T3fzCyFzrHTfrU9VPQicHS2NrG3sQXiVm4bXIEYliWxI9ShlMwPNGKuEZRmXkTKnFhpNVX2bGc5IG5kmMh9GsiYsRSasNDBYCUt6KTWlcjnIvu8iFNqKEhFPEQ8WGrptUet1QEi2BiZw6GvmUGWiABpV8mptiMKkEtSN3zA7cLThAD2jc2ekUhZppmxioeVj4cjbyojVZ6xFHello"
#define DATA_LENGTH 1248
#define NUM_OF_LOOPS 100

#define ACK "OK"
#define ACK_LENGTH 2

//AES
#define NONCE_LENGTH 7 //In Bytes (valid sizes: 7, 8, 9, 10, 11, 12, 13 bytes)
#define TAG_LENGTH 8   //In Bytes (valid sizes are: 4, 6, 10, 12, 14 and 16 bytes) 
#define AES_KEY_LENGTH 32  //In Bytes 
#define BOUND_AES_LENGTH 256
#define UINT_LENGTH 4

#define INPUT_MAX_LEN DATA_LENGTH + UINT_LENGTH

#define MAX_INTEGER_DIGITS 20

#define ENCRYPTED_MSG_LENGTH_LENGTH 4

//Handshake Serialization
#define HANDSHAKE_LENGTH SIGNATURE_LENGTH + NONCE_LENGTH + ENCRYPTED_AES_KEY_LENGTH + TAG_LENGTH + ENCRYPTED_ECC_PUBKEY_LENGTH
#define HS_SIGNATURE_POSITION 0
#define HS_NONCE_POSITION HS_SIGNATURE_POSITION + SIGNATURE_LENGTH
#define HS_KEY_POSITION HS_NONCE_POSITION + NONCE_LENGTH
#define HS_TAG_POSITION HS_KEY_POSITION + ENCRYPTED_AES_KEY_LENGTH
#define HS_ECC_POSITION HS_TAG_POSITION + TAG_LENGTH

//Data Transfer Serialization
#define MSG_LENGTH DATA_LENGTH + UINT_LENGTH + ECC_SIGNATURE_LENGTH + TAG_LENGTH + ENCRYPTED_MSG_LENGTH_LENGTH
#define MSG_SIGNATURE_POSITION 0
#define MSG_TAG_POSITION MSG_SIGNATURE_POSITION + ECC_SIGNATURE_LENGTH
#define MSG_ENC_MSG_LENGTH_POSITION MSG_TAG_POSITION + TAG_LENGTH
#define MSG_ENCRYPTED_MSG_POSITION MSG_ENC_MSG_LENGTH_POSITION + ENCRYPTED_MSG_LENGTH_LENGTH
