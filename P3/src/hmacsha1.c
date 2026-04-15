#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <openssl/evp.h>

enum {
	Buffsize = 4096,
	Blocksize = 64,
	Hashsize = 20,
	Ipadvalue = 0x36,
	Opadvalue = 0x5c,
};

void
ok_args(int argc, char *argv[])
{
	if (argc < 3)
		errx(EXIT_FAILURE, "usage: %s <data> <key>", argv[0]);
}

void
create_pads(unsigned char *k_pad, unsigned char *ipad, unsigned char *opad)
{
	int i;

	for (i = 0; i < Blocksize; i++) {
		ipad[i] = k_pad[i] ^ Ipadvalue;
		opad[i] = k_pad[i] ^ Opadvalue;
	}
}

FILE *
get_fich(char *argv[])
{
	FILE *f = fopen(argv[1], "r");

	if (f == NULL)
		err(EXIT_FAILURE, "fopen failed");
	return f;
}

void
hash_init(EVP_MD_CTX *mdctx, unsigned char *pad)
{
	if (!EVP_DigestInit(mdctx, EVP_sha1()))
		errx(EXIT_FAILURE, "EVP_DigestInit failed");

	if (!EVP_DigestUpdate(mdctx, pad, Blocksize))
		errx(EXIT_FAILURE, "EVP_DigestUpdate pad failed");
}

void
hash_update(EVP_MD_CTX *mdctx, FILE *f)
{
	char buffer[Buffsize];
	size_t n;

	while ((n = fread(buffer, 1, Buffsize, f)) > 0) {
		if (!EVP_DigestUpdate(mdctx, buffer, n))
			errx(EXIT_FAILURE, "EVP_DigestUpdate failed");
	}
}

void
hash_final(EVP_MD_CTX *mdctx, unsigned char *res, unsigned int *len)
{
	if (!EVP_DigestFinal_ex(mdctx, res, len))
		errx(EXIT_FAILURE, "EVP_DigestFinal_ex failed");
}

void
get_key(unsigned char *k_pad, char *argv[])
{
	FILE *f_key = fopen(argv[2], "r");

	if (f_key == NULL)
		err(EXIT_FAILURE, "fopen failed");

	unsigned char buff_tmp[Blocksize];
	size_t n = fread(buff_tmp, 1, Blocksize, f_key);

	unsigned char next_bit;
	size_t bit_extra = fread(&next_bit, 1, 1, f_key);

	if (bit_extra == 0) {
		memcpy(k_pad, buff_tmp, n);
	} else {

		EVP_MD_CTX *mdctx_key;

		mdctx_key = EVP_MD_CTX_new();
		if (mdctx_key == NULL)
			errx(EXIT_FAILURE, "EVP_MD_CTX_new failed");

		EVP_DigestInit(mdctx_key, EVP_sha1());

		EVP_DigestUpdate(mdctx_key, buff_tmp, n);
		EVP_DigestUpdate(mdctx_key, &next_bit, 1);

		hash_update(mdctx_key, f_key);

		unsigned int key_hash_len;

		hash_final(mdctx_key, k_pad, &key_hash_len);

		EVP_MD_CTX_free(mdctx_key);
	}

	fclose(f_key);
}


int
main(int argc, char *argv[])
{
	ok_args(argc, argv);

	unsigned char k_pad[Blocksize];

	memset(k_pad, 0, Blocksize);

	get_key(k_pad, argv);

	unsigned char ipad[Blocksize];
	unsigned char opad[Blocksize];

	create_pads(k_pad, ipad, opad);

	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned char hash_intern[EVP_MAX_MD_SIZE];

	unsigned int hash_len = 0;
	unsigned int hash_len_intern = 0;

	EVP_MD_CTX *mdctx;

	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL)
		errx(EXIT_FAILURE, "EVP_MD_CTX_new failed");

	hash_init(mdctx, ipad);
	FILE *f_datos = get_fich(argv);

	hash_update(mdctx, f_datos);
	fclose(f_datos);

	hash_final(mdctx, hash_intern, &hash_len_intern);
	hash_init(mdctx, opad);

	if (!EVP_DigestUpdate(mdctx, hash_intern, hash_len_intern))
		errx(EXIT_FAILURE, "EVP_DigestUpdate failed");

	hash_final(mdctx, hash, &hash_len);

	EVP_MD_CTX_free(mdctx);

	int i;

	for (i = 0; i < hash_len; i++)
		printf("%02x", hash[i]);
	printf("\n");
	exit(EXIT_SUCCESS);
}
