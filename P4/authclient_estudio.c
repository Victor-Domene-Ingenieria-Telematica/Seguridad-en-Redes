// Hay que hacerlo con .h y en el .h no van los includes (hmacsha1.c y hmacsha1.h)

// Primero hacer un cliente que se conecte al servidor y le diga "Hola servidor" (y termine)

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    int fd;
    struct sockaddr_in sin;
    int sockfd;
    int port = 9999;
    char *serverip = "127.0.0.1"; // string (la localhost)


    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
            err(1, "socket failed");
    }
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(serverip);
    sin.sin_port = htons(port);
    if(connect(sockfd, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
            err(1, "connect failed");
    }

    // Hay que usar sockfd como si fuese un pipe full-duplex

    close(fd);
    exit(EXIT_FAILURE);
}
