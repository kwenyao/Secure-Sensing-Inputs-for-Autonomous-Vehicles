#include <argp.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>
#include "base64.h"

#include <libcryptoauth.h>
#include <assert.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <limits.h>
#include <sys/time.h>

//TPM
#define SIGN_KEY_UUID {0,0,0,0,0,{0,0,0,2,11}}
#define BACKUP_KEY_UUID {0,0,0,0,0,{0,0,0,2,10}}
#define PADDING_SCHEME TSS_SS_RSASSAPKCS1V15_SHA1
#define DEBUG 0
#define DBG(message, tResult) if(DEBUG){printf("Line %d, %s) %s returned 0x%08x. %s.\n", __LINE__, __FUNCTION__, message, tResult, (char *)Trspi_Error_String(tResult));}
#define SIGNATURE_FILENAME "/home/debian/fullprotocol/signature.dat"
#define PUBLIC_KEY_FILENAME "/home/debian/fullprotocol/signingkey.pub"
#define SIGNATURE_LENGTH 256
#define ENCRYPTED_AES_KEY_LENGTH 256
#define ECC_PUBKEY_LENGTH 65
#define ENCRYPTED_ECC_PUBKEY_LENGTH ECC_PUBKEY_LENGTH

#define MESSAGE_RECEIVED EXIT_SUCCESS

//ECC
#define NUM_ARGS 1
#define HASHLET_COMMAND_FAIL EXIT_FAILURE
#define HASHLET_COMMAND_SUCCESS EXIT_SUCCESS
#define FILENAME_INPUT "/home/debian/EClet/Files/file.txt"
#define FILENAME_SIGNATURE "/home/debian/EClet/Files/signature.txt"
#define FILENAME_PUBLICKEY "/home/debian/EClet/Files/pubkey.txt"
#define INPUT "IqUJgFoIZHD34mnCtgf7Dy3YMo3muea24AhEAYCHc2pl0Ta5LxooEHgfxIk0K2os1ytYeTu14k3YQYVHgVaWBHrGH3V45nnT3kNR5IOUJnVi71hvlTbQG2SnK1ALMpI9z3G9OYFJJWOKlzi7yvPkIszQeSTwi8HOuZflcNEsKxHmrywEG9SgJFZiPCkfSmngoGr2YmmQ2oxIwZbmHp9gvIuIea7KNv658eSHWUotIFQEWMtZjBQUa6hQfSK2SuT9r1BRyb9YPEOifh96tboCCen09uynkFw81uiBRemL1emPjZH5tBx5rmWlYjj3T1v3N4QXHjeWQFm5qtePTAksn8zBsN55KKtfIlySuWm1p3YNNIqPw2NNaaJMCuQbBXgASGkCP97Gqt9jJ6R9MqoallaRKwZU8PWQEjn0QIORxiPt0fpWHFB00nxI4HDahR3Tgn8AEIbuL4NZzAMuEH3w4e9PpBYbRVRqyo56ZZ7uotpZBC3hDRk150TrAj1siX45lfSmg6tkJcWLf06cm81r6xxwWisP0Y8wanF8Np6qmFTScoNYK3PiKLnx97i7wKj8CYTgP4OQK5rA2Hpk07iZr3AxKjIQHXBBewBCsCYcVH1Xls895rmo6ix6V0cLRJkiBwRxk0pgVCPYx7zntMM9pFkyu12PFJh2xghhk7zYCsOhJ8YM4xrZc7Kc1XuxRKRN0iA5nHUgls9W8SfwvQqsilY1auxlUC5T3fzCyFzrHTfrU9VPQicHS2NrG3sQXiVm4bXIEYliWxI9ShlMwPNGKuEZRmXkTKnFhpNVX2bGc5IG5kmMh9GsiYsRSasNDBYCUt6KTWlcjnIvu8iFNqKEhFPEQ8WGrptUet1QEi2BiZw6GvmUGWiABpV8mptiMKkEtSN3zA7cLThAD2jc2ekUhZppmxioeVj4cjbyojVZ6xFP2UiU"
#define INPUTLEN 944
#define NUM_OF_LOOPS 100

//AES
#define NONCE_LENGTH 7 //In Bytes (valid sizes: 7, 8, 9, 10, 11, 12, 13 bytes)
#define TAG_LENGTH 8   //In Bytes (valid sizes are: 4, 6, 10, 12, 14 and 16 bytes) 
#define AES_KEY_LENGTH 32  //In Bytes 
#define BOUND_AES_LENGTH 256
#define UINT_LENGTH 4

#define INPUT_MAX_LEN 948