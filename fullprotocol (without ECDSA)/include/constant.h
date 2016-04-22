#ifndef CONSTANT_H_   /* Include guard */
#define CONSTANT_H_

#include <argp.h>
#include <arpa/inet.h> // Needed for inet_ntoa()
#include <assert.h>
#include <fcntl.h>
#include <glib.h>
#include <libcryptoauth.h>
#include <limits.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>

#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <signal.h>
#include <fcntl.h>
#include <linux/kd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sendfile.h>

#include <tss/platform.h>
#include <tss/tspi.h>
#include <tss/tss_defines.h>
#include <tss/tss_error.h>
#include <tss/tss_structs.h>
#include <tss/tss_typedef.h>
#include <trousers/trousers.h>

#include <unistd.h>

#include "base64.h"

//DEBUG
#define DEBUG 1
#define PRINTDEBUG(message) if(DEBUG){printf("%s Line %d) %s\n", __FILE__, __LINE__, message);}
#define DBG(message, tResult) if(DEBUG){printf("Line %d, %s) %s returned 0x%08x. %s.\n", __LINE__, __FUNCTION__, message, tResult, (char *)Trspi_Error_String(tResult));}

//FILES
#define CA_KEY_FILENAME "ca.key"
#define CA_CERT_FILENAME "ca.crt"
#define CERT_FILENAME "other.crt"
#define CSR_FILENAME "other.csr"
#define KEY_FILENAME "other.key"

//SOCKET
//Client = sender, Server = receiver
#define A_CLIENT_INTERFACE "eth0"
#define A_SERVER_INTERFACE "eth1"
#define A_ETH0_ADDRESS "192.168.1.50"
#define A_ETH1_ADDRESS "192.168.1.51"
#define B_CLIENT_INTERFACE "eth1"
#define B_SERVER_INTERFACE "eth0"
#define B_ETH0_ADDRESS "192.168.1.52"
#define B_ETH1_ADDRESS "192.168.1.53"
#define BROADCAST_ADDRESS "255.255.255.255"
#define TCP_PORT_NUM 9999 // Port number used at the server
#define UDP_PORT_NUM 2368

//CERTIFICATE
#define CERT_VALIDITY 3650 // Days
#define CERT_COUNTRY "SG"
#define CERT_STATE "SG"
#define CERT_LOCALITY "Singapore"
#define CERT_ORGANISATION "astar"
#define CERT_ORG_UNIT "i2r"
#define CERT_COMMON_NAME "BBB"

//TPM
#define SRK_PASSWORD "password123"
#define SRK_PASSWORD_LENGTH (sizeof(SRK_PASSWORD) - 1)
#define SIGN_KEY_UUID {0,0,0,0,0,{0,0,0,2,11}}
#define BACKUP_KEY_UUID {0,0,0,0,0,{0,0,0,2,10}}
#define PADDING_SCHEME TSS_SS_RSASSAPKCS1V15_DER //TSS_SS_RSASSAPKCS1V15_SHA1 
#define ENCRYPTION_SCHEME TSS_ES_RSAESPKCSV15 //TSS_ES_RSAESOAEP_SHA1_MGF1
#define SIGNATURE_LENGTH 256
#define ENCRYPTED_AES_KEY_LENGTH 256

//ECC
#define ECC_PUBKEY_LENGTH 65
#define ECC_SIGNATURE_LENGTH 64
#define ENCRYPTED_ECC_PUBKEY_LENGTH ECC_PUBKEY_LENGTH
#define NUM_ARGS 1
#define HASHLET_COMMAND_FAIL EXIT_FAILURE
#define HASHLET_COMMAND_SUCCESS EXIT_SUCCESS


//AES
#define AES_KEY_LENGTH 32  //In Bytes 
#define BOUND_AES_LENGTH 256
#define NONCE_LENGTH 7 //In Bytes (valid sizes: 7, 8, 9, 10, 11, 12, 13 bytes)
#define TAG_LENGTH 8   //In Bytes (valid sizes are: 4, 6, 10, 12, 14 and 16 bytes) 
#define UINT_LENGTH 4

//MESSAGE
#define ENCRYPTED_MSG_LENGTH_LENGTH 5 // size of uint32_t in bytes
//Entire message during data transmission [ecc signature, aes tag, encrypted data length, encrypted data]
#define DATA_LENGTH 1206
#define INPUT_MAX_LEN DATA_LENGTH + UINT_LENGTH //Max size of data 

//Handshake Serialization
#define HANDSHAKE_LENGTH SIGNATURE_LENGTH + NONCE_LENGTH + ENCRYPTED_AES_KEY_LENGTH //+ TAG_LENGTH + ENCRYPTED_ECC_PUBKEY_LENGTH
#define HS_SIGNATURE_POSITION 0
#define HS_NONCE_POSITION HS_SIGNATURE_POSITION + SIGNATURE_LENGTH
#define HS_KEY_POSITION HS_NONCE_POSITION + NONCE_LENGTH
#define HS_TAG_POSITION HS_KEY_POSITION + ENCRYPTED_AES_KEY_LENGTH
// #define HS_ECC_POSITION HS_TAG_POSITION + TAG_LENGTH

//Data Transfer Serialization
#define MAX_INTEGER_DIGITS 5
#define MSG_NO_DATA_LENGTH UINT_LENGTH + TAG_LENGTH + ENCRYPTED_MSG_LENGTH_LENGTH //+ ECC_SIGNATURE_LENGTH
#define MSG_SIGNATURE_POSITION 0
#define MSG_TAG_POSITION 0 //MSG_SIGNATURE_POSITION + ECC_SIGNATURE_LENGTH
#define MSG_ENC_MSG_LENGTH_POSITION MSG_TAG_POSITION + TAG_LENGTH
#define MSG_ENCRYPTED_MSG_POSITION MSG_ENC_MSG_LENGTH_POSITION + ENCRYPTED_MSG_LENGTH_LENGTH

//OTHER CONSTANTS
#define SENSOR_FREQUENCY 10 //Hz
#define CONNECTION_TIMEOUT 5 //seconds

#endif /* CONSTANT_H */
