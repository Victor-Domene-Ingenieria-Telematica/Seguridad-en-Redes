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

// Función vacía para interrumpir el read por el timeout
void handler(int sig) {
}

void ok_args(int argc, char *argv[])
{
    if(argc < 4 || argc > 5)
        errx(EXIT_FAILURE, "usage: %s <username> <password> <server_ip> <port>", argv[0]);
}

int get_port(int argc, char *argv[])
{
    char *endptr;
    long long_port = strtol(argv[4], &endptr, 10);
    
    if (*endptr != '\0' || long_port <= 0 || long_port > 65535)
        errx(EXIT_FAILURE, "The port must be a valid port");

    return (int)long_port;
}

int main(int argc, char *argv[])
{
    ok_args(argc, argv);

    char *client_login = argv[1];
    //char *client_pass = argv[2];
    char *serverip = argv[3];    
    int port = 9999;

    if (argc == 5) {
        port = get_port(argc, argv);
    }

    struct sockaddr_in sin;
    int sockfd;

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

    // Preparamos la señal de la alarma para proteger el socket
    signal(SIGALRM, handler);
    siginterrupt(SIGALRM, 1);

    // Recibimos el nonce
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
    
    // Vemos si tenemos el nonce
    printf("Nonce recibido\n");

    // Preparamos y enviamos la respuesta
    unsigned char buffer_tx[284];
    memset(buffer_tx, 0, 284); 

    // Obtenemos el Timestamp
    time_t current_time = time(NULL);
    if (current_time == (time_t)-1) {
        err(EXIT_FAILURE, "Time failed");
    }
    
    uint64_t client_T = (uint64_t)current_time;

    // Preparamos el login
    char temp_login[256];
    memset(temp_login, 0, 256);
    strncpy(temp_login, client_login, 255);

    // Preparaos la HMAC
    unsigned char hmac[20]; 
    memset(hmac, 0, 20);

    // Estructura del paquete
    memcpy(buffer_tx, hmac, 20);            
    memcpy(buffer_tx + 20, &client_T, 8);
    memcpy(buffer_tx + 28, temp_login, 256);        

    // Se lo enviamos al servidor
    if (write(sockfd, buffer_tx, 284) != 284) { 
        err(EXIT_FAILURE, "write failed");
    }

    // Vemos si llegamos a que se envie el paquete
    printf("Paquete enviado\n");

    close(sockfd);
    
    exit(EXIT_SUCCESS);
}

/*
POR HACER:
    - Implementar llamada a generar_hmac()
*/