#include "ecc.h"

char* read_file(char* file_name) {
	FILE *f;
	f = fopen(file_name, "r");
	fseek(f, 0, SEEK_END);
	int len = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *buffer = malloc(len);
	fread(buffer, len, 1, f);
	// printf("Read: %s\n",buffer);
	fclose(f);
	return buffer;
}

int ecc_gen_key() {
	struct arguments args;
	set_defaults(&args);
	// Sets up device for communication
	int fd = lca_atmel_setup(args.bus, args.address);

	FILE* pubkeyfile;
	pubkeyfile = fopen(FILENAME_PUBLICKEY, "w");

	int result = HASHLET_COMMAND_FAIL;
	if (fd < 0)
		printf("ERROR fd < 0");
	else
	{
		struct lca_octet_buffer pub_key = lca_gen_ecc_key (fd, args.key_slot, true);

		pub_key = lca_gen_ecc_key (fd, args.key_slot, true);

		// If public key not NULL
		if (NULL != pub_key.ptr)
		{
			struct lca_octet_buffer uncompressed =
			    lca_add_uncompressed_point_tag (pub_key);

			assert (NULL != uncompressed.ptr);
			assert (65 == uncompressed.len);
			output_hex (pubkeyfile, uncompressed);

			fclose(pubkeyfile);
			lca_free_octet_buffer (uncompressed);
			result = HASHLET_COMMAND_SUCCESS;
		}
		else
		{
			fprintf (stderr, "%s\n", "Gen key command failed");
		}
	}
	lca_atmel_teardown(fd);
	return result;
}

struct lca_octet_buffer ecc_sign(unsigned char* input_string, unsigned int input_length)
{
	struct arguments args;
	set_defaults(&args);
	// Sets up device for communication
	int fd = lca_atmel_setup(args.bus, args.address);

	// unsigned char* input_string = (unsigned char*) INPUT;
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
			lca_free_octet_buffer (r);
		}
	}
	lca_atmel_teardown(fd);
	return signature;
}

int ecc_verify(struct lca_octet_buffer signature, unsigned char* input_string, unsigned int input_length) {
	int result = HASHLET_COMMAND_FAIL;

	struct arguments args;
	set_defaults(&args);
	// Sets up device for communication
	int fd = lca_atmel_setup(args.bus, args.address);

	struct lca_octet_buffer input;
	input.ptr = input_string;
	input.len = input_length;

	struct lca_octet_buffer pub_key = {0, 0};
	struct lca_octet_buffer file_digest = {0, 0};

	char* buffer = read_file(FILENAME_PUBLICKEY);
	args.pub_key = buffer;
	pub_key = lca_ascii_hex_2_bin (args.pub_key, 130);

	if (NULL == signature.ptr)
	{
		perror ("Signature required");
	}
	else if (NULL == pub_key.ptr)
	{
		perror ("Public Key required");
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
					// printf("Verify Successful\n");
					result = HASHLET_COMMAND_SUCCESS;
				}
				else
				{
					fprintf (stderr, "%s\n", "Verify Command failed.");
					printf("Verify Failed\n");
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
		lca_free_octet_buffer (pub_key);
		lca_free_octet_buffer (signature);
	}
	free(buffer);
	lca_atmel_teardown(fd);
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