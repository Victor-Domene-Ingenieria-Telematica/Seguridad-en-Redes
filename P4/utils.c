#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include "utils.h"

int
get_valid_port(char *port_str)
{
	char *endptr;

	long long_port = strtol(port_str, &endptr, 10);

	if (*endptr != '\0' || long_port <= 0 || long_port > 65535) {
		errx(EXIT_FAILURE, "The port must be a valid port");
	}
	return (int)long_port;
}

void
parse_key(char *password, unsigned char *key_bytes, int *key_len)
{
	if (strlen(password) == 40) {
		char temp_hex[3];

		temp_hex[2] = '\0';

		for (int i = 0; i < 20; i++) {
			temp_hex[0] = password[i * 2];
			temp_hex[1] = password[i * 2 + 1];
			key_bytes[i] =
			    (unsigned char)strtol(temp_hex, NULL, 16);
		}
		*key_len = 20;
	} else {
		*key_len = strlen(password);
		if (*key_len > 20)
			*key_len = 20;
		memcpy(key_bytes, password, *key_len);
	}
}

void
build_hash_msg(unsigned char *msg, unsigned char *nonce, uint64_t timestamp)
{
	memset(msg, 0, 24);

	memcpy(msg, nonce, 16);
	memcpy(msg + 16, &timestamp, 8);
}

int
find_user_in_file(char *filepath, char *login_to_find, char *out_keyhex)
{
	FILE *f_accounts = fopen(filepath, "r");

	if (!f_accounts) {
		return 0;
	}

	char line[512];
	int found = 0;

	while (fgets(line, sizeof(line), f_accounts)) {
		int len = strlen(line);

		if (len > 0 && line[len - 1] == '\n') {
			line[len - 1] = '\0';
		}

		char *trozo_usuario = strtok(line, ":");
		char *trozo_clave = strtok(NULL, ":");

		if (trozo_usuario != NULL && trozo_clave != NULL) {
			if (strcmp(trozo_usuario, login_to_find) == 0) {
				found = 1;
				strncpy(out_keyhex, trozo_clave, 40);
				out_keyhex[40] = '\0';
				break;
			}
		}
	}

	fclose(f_accounts);
	return found;
}
