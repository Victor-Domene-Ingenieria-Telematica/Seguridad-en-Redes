#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include "hmacsha1.h"
#include "utils.h"

void
handler(int sig)
{
}

void
ok_args(int argc, char *argv[])
{
	if (argc < 4 || argc > 5) {
		errx(EXIT_FAILURE,
		     "usage: %s <username> <password> <server_ip> <port>",
		     argv[0]);
	}
}

int
main(int argc, char *argv[])
{
	ok_args(argc, argv);

	char *client_login = argv[1];
	char *client_pass = argv[2];
	char *serverip = argv[3];
	int port = 9999;

	if (argc == 5) {
		port = get_valid_port(argv[4]);
	}

	struct sockaddr_in sin;

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		err(1, "socket failed");
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(serverip);
	sin.sin_port = htons(port);

	if (connect(sockfd, (struct sockaddr *)&sin, sizeof(struct sockaddr)) ==
	    -1) {
		err(1, "connect failed");
	}

	signal(SIGALRM, handler);
	siginterrupt(SIGALRM, 1);

	unsigned char nonce[16];

	alarm(10);
	int r = read(sockfd, nonce, 16);

	alarm(0);

	if (r < 0) {
		if (errno == EINTR) {
			errx(EXIT_FAILURE, "timeout");
		} else {
			err(EXIT_FAILURE, "read failed");
		}
	} else if (r != 16) {
		errx(EXIT_FAILURE, "No se han leido los 16 bytes");
	}

	time_t current_time = time(NULL);

	if (current_time == (time_t) - 1) {
		err(EXIT_FAILURE, "Time failed");
	}

	uint64_t client_T = (uint64_t) current_time;

	unsigned char msg_to_hash[24];

	build_hash_msg(msg_to_hash, nonce, client_T);

	unsigned char key_bytes[20];
	int key_len;

	parse_key(client_pass, key_bytes, &key_len);

	unsigned char hmac[20];

	memset(hmac, 0, 20);
	generar_hmac(key_bytes, key_len, msg_to_hash, 24, hmac);

	unsigned char buffer_tx[284];

	memset(buffer_tx, 0, 284);
	memcpy(buffer_tx, hmac, 20);
	memcpy(buffer_tx + 20, &client_T, 8);
	memcpy(buffer_tx + 28, client_login, strlen(client_login));

	if (write(sockfd, buffer_tx, 284) != 284) {
		err(EXIT_FAILURE, "write failed");
	}

	char veredicto[8];

	memset(veredicto, 0, 8);

	alarm(10);
	int r_ver = read(sockfd, veredicto, 8);

	alarm(0);

	if (r_ver > 0) {
		veredicto[7] = '\0';
		printf("AUTHENTICATION: %s\n", veredicto);
		close(sockfd);
		if (strcmp(veredicto, "SUCCESS") == 0) {
			exit(EXIT_SUCCESS);
		} else {
			exit(EXIT_FAILURE);
		}
	} else {
		printf("AUTHENTICATION: FAILURE\n");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
}
