#ifndef ECC_H
#define ECC_H

#include "constant.h"


struct arguments {
	char *args[NUM_ARGS];
	int silent, verbose;
	bool update_seed;
	char *output_file;
	char *input_file;
	unsigned int key_slot;
	bool test;
	uint8_t address;
	const char *challenge;
	const char *challenge_rsp;
	const char *signature;
	const char *pub_key;
	const char *meta;
	const char *write_data;
	const char *bus;
};

char* read_file(char* file_name);
int ecc_gen_key();
int ecc_verify(struct lca_octet_buffer signature, unsigned char* input_string, unsigned int input_length);
struct lca_octet_buffer ecc_sign(unsigned char* input_string, unsigned int input_length);
void set_defaults (struct arguments *args);
void output_hex (FILE *stream, struct lca_octet_buffer buf);

#endif /* ECC_H */