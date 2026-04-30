#include "hmacsha1.h"
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <openssl/evp.h>

void
create_pads(unsigned char *k_pad, unsigned char *ipad, unsigned char *opad)
{
	int i;

	for (i = 0; i < Blocksize; i++) {
		ipad[i] = k_pad[i] ^ Ipadvalue;
		opad[i] = k_pad[i] ^ Opadvalue;
	}
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
hash_update_mem(EVP_MD_CTX *mdctx, unsigned char *datos, int len)
{
	if (!EVP_DigestUpdate(mdctx, datos, len))
		errx(EXIT_FAILURE, "EVP_DigestUpdate failed");
}

void
hash_final(EVP_MD_CTX *mdctx, unsigned char *res, unsigned int *len)
{
	if (!EVP_DigestFinal_ex(mdctx, res, len))
		errx(EXIT_FAILURE, "EVP_DigestFinal_ex failed");
}

void
get_key_mem(unsigned char *k_pad, unsigned char *key, int key_len)
{
	if (key_len <= Blocksize) {
		memcpy(k_pad, key, key_len);
	} else {
		EVP_MD_CTX *mdctx_key;

		mdctx_key = EVP_MD_CTX_new();
		if (mdctx_key == NULL)
			errx(EXIT_FAILURE, "EVP_MD_CTX_new failed");

		EVP_DigestInit(mdctx_key, EVP_sha1());
		EVP_DigestUpdate(mdctx_key, key, key_len);

		unsigned int key_hash_len;

		hash_final(mdctx_key, k_pad, &key_hash_len);

		EVP_MD_CTX_free(mdctx_key);
	}
}

void
generar_hmac(unsigned char *key, int key_len, unsigned char *datos,
	     int datos_len, unsigned char *hash_result)
{
	unsigned char k_pad[Blocksize];

	memset(k_pad, 0, Blocksize);

	get_key_mem(k_pad, key, key_len);

	unsigned char ipad[Blocksize];
	unsigned char opad[Blocksize];

	create_pads(k_pad, ipad, opad);

	unsigned char hash_intern[EVP_MAX_MD_SIZE];
	unsigned int hash_len_intern = 0;
	unsigned int hash_len = 0;

	EVP_MD_CTX *mdctx;

	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL)
		errx(EXIT_FAILURE, "EVP_MD_CTX_new failed");

	hash_init(mdctx, ipad);

	hash_update_mem(mdctx, datos, datos_len);

	hash_final(mdctx, hash_intern, &hash_len_intern);
	hash_init(mdctx, opad);

	if (!EVP_DigestUpdate(mdctx, hash_intern, hash_len_intern))
		errx(EXIT_FAILURE, "EVP_DigestUpdate failed");

	hash_final(mdctx, hash_result, &hash_len);

	EVP_MD_CTX_free(mdctx);
}
