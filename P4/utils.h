#include <stdint.h>

int get_valid_port(char *port_str);

void parse_key(char *password, unsigned char *key_bytes, int *key_len);

void build_hash_msg(unsigned char *msg, unsigned char *nonce, uint64_t timestamp);

int find_user_in_file(char *filepath, char *login_to_find, char *out_keyhex);
