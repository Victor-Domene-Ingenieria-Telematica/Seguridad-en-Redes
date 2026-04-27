#include <stdint.h>

// Extrae y valida el puerto
int get_valid_port(char *port_str);

// Convierte la contraseña (texto o hex) a array de bytes
void parse_key(char *password, unsigned char *key_bytes, int *key_len);

// Junta el nonce, timestamp y login en un solo array de 280 bytes
void build_hash_msg(unsigned char *msg, unsigned char *nonce, uint64_t timestamp, char *login);

// Busca un usuario en el fichero y devuelve 1 si lo encuentra (y guarda su clave) o 0 si no
int find_user_in_file(char *filepath, char *login_to_find, char *out_keyhex);
