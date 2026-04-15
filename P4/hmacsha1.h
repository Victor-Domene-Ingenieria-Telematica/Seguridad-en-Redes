#ifndef HMACSHA1_H
#define HMACSHA1_H

void generar_hmac(unsigned char *key, int key_len, 
                  unsigned char *datos, int datos_len, 
                  unsigned char *hash_result);

#endif
