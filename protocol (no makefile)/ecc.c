#include "ecc.h"

char* read_file(char* file_name) {
	FILE *f;
	f = fopen(file_name, "r");
	fseek(f, 0, SEEK_END);
	int len = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *buffer = malloc(len);
	fread(buffer, len, 1, f);
	fclose(f);
	return buffer;
}

struct lca_octet_buffer ecc_gen_key(int isHandshake) {
	struct arguments args;
	set_defaults(&args);
	if (isHandshake != 0)
	{
		args.key_slot = 1;
	}
	// Sets up device for communication
	int fd = lca_atmel_setup(args.bus, args.address);

	struct lca_octet_buffer pub_key = {0, 0};
	struct lca_octet_buffer uncompressed = {0, 0};

	if (fd < 0)
		printf("ERROR fd < 0");
	else
	{
		pub_key = lca_gen_ecc_key (fd, args.key_slot, true);
		pub_key = lca_gen_ecc_key (fd, args.key_slot, true);

		if (NULL != pub_key.ptr)	// public key is not NULL
		{
			uncompressed = lca_add_uncompressed_point_tag (pub_key);

			assert (NULL != uncompressed.ptr);
			assert (65 == uncompressed.len);
		}
		else
		{
			fprintf (stderr, "%s\n", "Gen key command failed");
		}
	}
	// lca_free_octet_buffer(pub_key);
	lca_atmel_teardown(fd);
	return uncompressed;
}

struct lca_octet_buffer ecc_sign(unsigned char* input_string, unsigned int input_length, int handshake)
{
	struct arguments args;
	set_defaults(&args);
	// Sets up device for communication
	int fd = lca_atmel_setup(args.bus, args.address);

	// args.key_slot = handshake;

	if (handshake == 1)
	{
		printf("args.key_slot = 1\n");
		args.key_slot = 1;
	}

	struct lca_octet_buffer input;
	input.ptr = input_string;
	input.len = input_length;

	struct lca_octet_buffer signature = {0, 0};
	struct lca_octet_buffer file_digest = {0, 0};

	if (fd < 0)
		printf("ERROR fd < 0");
	else
	{
		/* Digest the file then proceed */
		file_digest = lca_sha256_buffer (input);
		
		if (NULL != file_digest.ptr)
		{
			/* Forces a seed update on the RNG */
			struct lca_octet_buffer r = lca_get_random (fd, true);

			/* Loading the nonce is the mechanism to load the SHA256 hash into the device */
			if (load_nonce (fd, file_digest))
			{
				signature = lca_ecc_sign (fd, args.key_slot);
				if (NULL == signature.ptr)
				{
					fprintf (stderr, "%s\n", "Sign Command failed.");
				}

			}
			else 
			{
				printf("load nonce failed\n");
			}
			lca_free_octet_buffer (r);
		}
	}
	lca_atmel_teardown(fd);
	return signature;
}

int ecc_verify(struct lca_octet_buffer signature,
               unsigned char* input_string,
               unsigned int input_length,
               BYTE* ecc_pub_key) {
	int result = HASHLET_COMMAND_FAIL;
	struct arguments args;
	set_defaults(&args);

	struct lca_octet_buffer input;
	input.ptr = input_string;
	input.len = input_length;

	struct lca_octet_buffer pub_key = {0, 0};
	struct lca_octet_buffer file_digest = {0, 0};

	args.pub_key = (char *)ecc_pub_key;
	pub_key = lca_make_buffer(ECC_PUBKEY_LENGTH);
	pub_key.ptr = (unsigned char *) ecc_pub_key;

	// struct timeval stopverify, startverify;
	// int i = 0;
	// gettimeofday(&startverify, NULL);
	// for (i; i < 100; i++)
	// {

	// Sets up device for communication
	int fd = lca_atmel_setup(args.bus, args.address);
	if (NULL == signature.ptr)
	{
		perror ("Signature required\n");
	}
	else if (NULL == pub_key.ptr)
	{
		perror ("Public Key required\n");
	}
	else
	{
		/* Digest the file then proceed */
		file_digest = lca_sha256_buffer (input);

		if (NULL != file_digest.ptr)
		{
			/* Loading the nonce is the mechanism to load the SHA256 hash into the device */
			if (load_nonce (fd, file_digest))
			{
				/* The ECC108 doesn't use the leading uncompressed point format tag */
				pub_key.ptr = pub_key.ptr + 1;
				pub_key.len = pub_key.len - 1;

				if (lca_ecc_verify (fd, pub_key, signature))
				{
					result = HASHLET_COMMAND_SUCCESS;
				}
				else
				{
					fprintf (stderr, "%s\n", "ECC Verify Command failed.");
				}

				/* restore pub key */
				pub_key.ptr = pub_key.ptr - 1;
				pub_key.len = pub_key.len + 1;
			}
		}
		else
		{
			/* temp_key_loaded already false */
		}

		lca_free_octet_buffer (file_digest);
	}
	lca_atmel_teardown(fd);
	// }
	// gettimeofday(&stopverify, NULL);
	// printf ("Total time for verification = %f seconds\n",
	//         (double) (stopverify.tv_usec - startverify.tv_usec) / 1000000 +
	//         (double) (stopverify.tv_sec - startverify.tv_sec));
	// free(buffer);

	return result;
}

void set_defaults (struct arguments *args) {
	assert (NULL != args);

	args->silent = 0;
	args->verbose = 0;
	args->output_file = "-";
	args->input_file = NULL;
	args->update_seed = false;
	args->key_slot = 0;

	args->signature = NULL;
	args->write_data = NULL;

	args->address = 0x60;
	args->bus = "/dev/i2c-1";
}

void output_hex (FILE *stream, struct lca_octet_buffer buf) {
	assert (NULL != stream);

	if (NULL == buf.ptr)
		printf ("Command failed\n");
	else
	{
		unsigned int i = 0;

		for (i = 0; i < buf.len; i++)
		{
			fprintf (stream, "%02X", buf.ptr[i]);
		}

		fprintf (stream, "\n");
	}
}