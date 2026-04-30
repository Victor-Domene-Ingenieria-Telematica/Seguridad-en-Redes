#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include "hmacsha1.h"
#include "utils.h"

uint64_t auth_counter = 0;

void
ok_args(int argc, char *argv[])
{
	if (argc < 2 || argc > 3) {
		errx(EXIT_FAILURE, "usage: %s <accounts_file> <port>", argv[0]);
	}
}

void
timeout_handler(int sig)
{
}

int
main(int argc, char *argv[])
{
	int sockfd, fd;
	struct sockaddr_in sin;
	struct sockaddr sclient;
	socklen_t addrlen;

	int port = 9999;
	char *accounts_file;

	ok_args(argc, argv);
	accounts_file = argv[1];

	if (argc == 3) {
		port = get_valid_port(argv[2]);
	}

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		err(1, "socket failed");
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = 0;
	sin.sin_port = htons(port);

	if (bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		err(1, "bind failed");
	}

	if (listen(sockfd, 100) < 0) {
		err(1, "listen failed");
	}

	signal(SIGALRM, timeout_handler);
	siginterrupt(SIGALRM, 1);

	for (;;) {
		addrlen = sizeof(sclient);
		fd = accept(sockfd, &sclient, &addrlen);
		if (fd < 0) {
			continue;
		}

		struct sockaddr_in *sclient_in = (struct sockaddr_in *)&sclient;
		char *client_ip = inet_ntoa(sclient_in->sin_addr);

		unsigned char nonce[16];
		FILE *urandom = fopen("/dev/urandom", "r");

		if (urandom == NULL) {
			err(EXIT_FAILURE, "fopen failed");
		}

		fread(nonce, 1, 8, urandom);
		fclose(urandom);

		memset(nonce + 8, 0, 8);
		memcpy(nonce + 8, &auth_counter, sizeof(uint64_t));
		auth_counter++;

		if (write(fd, nonce, 16) != 16) {
			close(fd);
			continue;
		}

		unsigned char response[284];

		alarm(10);
		int r = read(fd, response, 284);

		alarm(0);

		if (r != 284) {
			printf("FAILURE, unknown from %s\n", client_ip);
			close(fd);
			continue;
		}

		unsigned char client_hmac[20];
		uint64_t client_T;
		char client_login[256];

		memcpy(client_hmac, response, 20);
		memcpy(&client_T, response + 20, 8);
		memcpy(client_login, response + 28, 256);
		client_login[255] = '\0';

		time_t current_time = time(NULL);

		if (current_time == (time_t) - 1) {
			close(fd);
			continue;
		}

		uint64_t server_T = (uint64_t) current_time;
		uint64_t diff;

		if (server_T > client_T) {
			diff = server_T - client_T;
		} else {
			diff = client_T - server_T;
		}

		if (diff > 300) {
			printf("Timestamp failed from %s (Demasiado antiguo)\n",
			       client_ip);
			close(fd);
			continue;
		}

		char f_keyhex_guardado[41];

		if (!find_user_in_file
		    (accounts_file, client_login, f_keyhex_guardado)) {
			printf("FAILURE, %s from %s\n", client_login,
			       client_ip);
			write(fd, "FAILURE\0", 8);
			close(fd);
			continue;
		}

		unsigned char server_key[20];
		int key_len;

		parse_key(f_keyhex_guardado, server_key, &key_len);

		unsigned char server_msg_to_hash[24];

		build_hash_msg(server_msg_to_hash, nonce, client_T);

		unsigned char server_hmac[20];

		generar_hmac(server_key, 20, server_msg_to_hash, 24,
			     server_hmac);

		if (memcmp(client_hmac, server_hmac, 20) == 0) {
			printf("SUCCESS, %s from %s\n", client_login,
			       client_ip);
			write(fd, "SUCCESS\0", 8);
		} else {
			printf("FAILURE, %s from %s\n", client_login,
			       client_ip);
			write(fd, "FAILURE\0", 8);
		}

		close(fd);
	}

	close(sockfd);
	exit(EXIT_SUCCESS);
}
