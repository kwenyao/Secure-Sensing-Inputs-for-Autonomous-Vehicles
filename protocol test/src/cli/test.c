#define INPUT "Hello World"
int run()
{
	struct arguments args;
	set_defaults(&args);
	int fd = lca_atmel_setup(args.bus, args.address);

	if(fd<0)
	{
		printf("ERROR fd < 0\n");
		return 0;
	}
	else
	{
	 	/******************
	 	 ** GENERATE KEY **
	 	 ******************/

	 	 struct lca_octet_buffer pub_key = lca_gen_ecc_key (fd, args.key_slot, true);
	 	 pub_key = lca_gen_ecc_key (fd, args.key_slot, true);
	 	 struct lca_octet_buffer uncompressed;

		// If public key not NULL
	 	 if (NULL != pub_key.ptr)
	 	 {
	 	 	uncompressed = lca_add_uncompressed_point_tag (pub_key);

	 	 	assert (NULL != uncompressed.ptr);
	 	 	assert (65 == uncompressed.len);
	 	 }
	 	 else
	 	 {
	 	 	printf ("Gen key command failed\n");
	 	 }

		/******************
		 ****** SIGN ******
		 ******************/

		 /* Digest the file then proceed */
		 struct lca_octet_buffer input = {INPUT,11};
		 struct lca_octet_buffer file_digest = {0,0};
		 file_digest = lca_sha256_buffer (input);
		 lca_free_octet_buffer (input);

		 struct lca_octet_buffer rsp;

		 if (NULL != file_digest.ptr)
		 {
		    /* Forces a seed update on the RNG */
		 	struct lca_octet_buffer r = lca_get_random (fd, true);

		    /* Loading the nonce is the mechanism to load the SHA256 hash into the device */
		 	if (load_nonce (fd, file_digest))
		 	{
		 		rsp = lca_ecc_sign (fd, args.key_slot);

		 		if (NULL == rsp.ptr)
		 			printf ("Sign Command failed\n");
		 	}

		 	lca_free_octet_buffer (r);
		 }
		 else
		 {
		 	printf("ERROR Hash is NULL\n");
		 }

		 /*****************
		 ***** VERIFY *****
		 ******************/

		 struct lca_octet_buffer signature = {0,0};
		 struct lca_octet_buffer pub_key = {0,0};

		 args.signature = rsp.ptr;
		 args.pub_key = uncompressed.ptr;

		 if (NULL == args.signature)
		 	printf ("ERROR Signature required\n");
		 else if (NULL == args.pub_key)
		 	printf ("ERROR Public Key required\n");
		 else
		 {
		 	signature = lca_ascii_hex_2_bin (args.signature, 128);
		 	pub_key = lca_ascii_hex_2_bin (args.pub_key, 130);

		 	struct lca_octet_buffer input = {INPUT,11};
		 	struct lca_octet_buffer file_digest = {0,0};
		 	file_digest = lca_sha256_buffer (input);
		 	lca_free_octet_buffer (input);

		 	if (NULL != file_digest.ptr)
			{
              /* Loading the nonce is the mechanism to load the SHA256 hash into the device */
				if (load_nonce (fd, file_digest))
				{
                  /* The ECC108 doesn't use the leading uncompressed point format tag */
					pub_key.ptr = pub_key.ptr + 1;
					pub_key.len = pub_key.len - 1;
					if (lca_ecc_verify (fd, pub_key, signature))
						printf("Verify Successful\n");
					else
						printf("Verify Failed\n");

                  /* restore pub key */
					pub_key.ptr = pub_key.ptr - 1;
					pub_key.len = pub_key.len + 1;
				}
			}
			lca_free_octet_buffer (file_digest);
			lca_free_octet_buffer (pub_key);
			lca_free_octet_buffer (signature);
		 }
	}
	lca_atmel_teardown(fd);
	return 1;
}