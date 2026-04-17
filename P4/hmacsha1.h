enum {
	Buffsize = 4096,
	Blocksize = 64,
	Hashsize = 20,
	Ipadvalue = 0x36,
	Opadvalue = 0x5c,
};

void generar_hmac(unsigned char *key, int key_len, 
                  unsigned char *datos, int datos_len, 
                  unsigned char *hash_result);
