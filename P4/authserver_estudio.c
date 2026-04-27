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

// Variable para el contador
int auth_counter = 0;

void ok_args(int argc, char *argv[])
{
    if(argc < 2 || argc > 3)
        errx(EXIT_FAILURE, "usage: %s <accounts_file> <port>", argv[0]);
}

int get_port(int argc, char *argv[])
{
    char *endptr;
    long long_port = strtol(argv[2], &endptr, 10);
    
    if (*endptr != '\0' || long_port <= 0 || long_port > 65535)
        err(EXIT_FAILURE, "The port must be a valid port");

    return (int)long_port;
}

void timeout_handler(int sig) {
}

int main(int argc, char *argv[])
{
    // Variables principales
    int sockfd, fd;
    struct sockaddr_in sin;
    struct sockaddr sclient;
    socklen_t addrlen;

    int port = 9999;
    char *accounts_file;

    ok_args(argc, argv);
    accounts_file = argv[1];
    
    if (argc == 3) {
        port = get_port(argc, argv);
    }

    // Creamos el socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        err(1, "socket failed");
    }

    // Configuracion de la direccion
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(port);

    // Atamos el socket
    if(bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) < 0){
        err(1, "bind failed");
    }

    // Nos ponemos a escuchar
    if(listen(sockfd, 100) < 0){
        err(1, "listen failed");
    }

    // Preparamos la señal de la alarma y que interrumpa el read
    signal(SIGALRM, timeout_handler);
    siginterrupt(SIGALRM, 1);

    for(;;){
        addrlen = sizeof(sclient);
        fd = accept(sockfd, &sclient, &addrlen);
        if(fd < 0){
            continue;
        }

        // Sacamos la IP del cliente
        struct sockaddr_in *sclient_in = (struct sockaddr_in *)&sclient;
        char *client_ip = inet_ntoa(sclient_in->sin_addr);

        // Creamos y enviamos el nonce (16 bytes)
        unsigned char nonce[16];

        FILE *urandom = fopen("/dev/urandom", "r");
        if (urandom == NULL) {
            err(EXIT_FAILURE, "fopen failed");
        }
        fread(nonce, 1, 8, urandom);
        fclose(urandom);

        memset(nonce + 8, 0, 8);
        memcpy(nonce + 8, &auth_counter, sizeof(int));
        auth_counter++;

        if (write(fd, nonce, 16) != 16) {
            close(fd);
            continue;
        }

        // Recibimos la respuesta del cliente (284 bytes)
        unsigned char response[284];
        alarm(10); 
        int r = read(fd, response, 284);
        alarm(0);

        if (r < 0) {
            if (errno == EINTR) {
                printf("timeout from client %s\n", client_ip);
            } else {
                printf("read failed from client %s\n", client_ip);
            }
            close(fd);
            continue;
        } else if (r != 284) {
            printf("No se han leido los 284 bytes del cliente %s", client_ip);
            close(fd);
            continue;
        }

        // Extraemos los datos (HMAC, Tiempo y Login)
        unsigned char client_hmac[20];
        uint64_t client_T;
        char client_login[256];

        memcpy(client_hmac, response, 20);
        memcpy(&client_T, response + 20, 8); 
        memcpy(client_login, response + 28, 256);
        client_login[255] = '\0';

        // Comprobamos el tiempo (maximo 5 minutos)
        time_t current_time = time(NULL);
        if (current_time == (time_t)-1) {
            close(fd);
            continue;
        }
        
        uint64_t server_T = (uint64_t)current_time;
        uint64_t diff;

        if (server_T > client_T) {
            diff = server_T - client_T;
        } else {
            diff = client_T - server_T;
        }

        if (diff > 300) {
            printf("Timestamp failed from %s (Demasiado antiguo)\n", client_ip);
            close(fd);
            continue;
        }

        // Buscamos al usuario en el fichero
        FILE *f_accounts = fopen(accounts_file, "r");
        if (!f_accounts) {
            close(fd);
            continue;
        }

        char line[512];
        char f_keyhex_guardado[41];
        int found = 0;
        
        while (fgets(line, sizeof(line), f_accounts)) {
            // Averiguamos cuánto mide la línea leída
            int len = strlen(line);
            
            // Cambiamos el \n por el \0
            if (len > 0 && line[len - 1] == '\n') {
                line[len - 1] = '\0';
            }

            // Cortamos por los dos puntos
            char *trozo_usuario = strtok(line, ":");
            char *trozo_clave = strtok(NULL, ":");

            if (trozo_usuario != NULL && trozo_clave != NULL) {
                if (strcmp(trozo_usuario, client_login) == 0) {
                    found = 1;
                    // Nos guardamos la clave en nuestro array para usarla luego
                    strncpy(f_keyhex_guardado, trozo_clave, 40);
                    break;
                }
            }
        }
        fclose(f_accounts);

        if (!found) {
            printf("Fail from %s\n", client_ip);
            close(fd);
            continue;
        }

        close(fd);
    }

    close(sockfd);
    exit(EXIT_SUCCESS);
}

/*
POR HACER:
    - Implementar el cambio de la clave de hexadecimal a bytes
    - Calcular el HMAC propio y comparar con el del cliente
    - Enviar el SUCCESS o FAILURE final al cliente
*/