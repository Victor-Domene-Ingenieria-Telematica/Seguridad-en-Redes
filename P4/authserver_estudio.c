#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <err.h>
#include <unistd.h>
#include <string.h> 
#include <time.h>

// Variable para el contador de autenticaciones
int auth_counter = 0;

void ok_args(int argc, char *argv[])
{
    if(argc < 2 || argc > 3)
        errx(EXIT_FAILURE, "usage: %s <accounts_file> [port]", argv[0]);
}

int get_port(int argc, char *argv[])
{
    char *endptr;
    long long_port = strtol_r(argv[2], &endptr, 10);
    
    // Comprobamos si hubo error (en socket TCP los puertos solo van del 1 al 65535)
    if (*endptr != '\0' || long_port <= 0 || long_port > 65535)
        err(EXIT_FAILURE, "The port must be a valid port");

    return (int)long_port;
}

int main(int argc, char *argv[])
{
    // Variables principales (siempre igual en servidor TCP)
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

    // Configuracion de la direccion por donde va a escuchar el servidor
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(port);

    // Atamos el socket a la configuracion de antes
    if(bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) < 0){
        err(1, "bind failed");
    }

    // El servidor se pone a escuchar como mucho 100 clientes en la cola
    if(listen(sockfd, 100) < 0){
        err(1, "listen failed");
    }

    // Bucle para que el servidor pueda atender a todos los clientes que quiera y no solo a 1
    for(;;){
        addrlen = sizeof(sclient);
        fd = accept(sockfd, &sclient, &addrlen);
        if(fd < 0){
            err(1, "accept failed");
        }
        // Hay que usar fd como si fuera un pipe normal

        // Creamos y enviamos el nonce (16 bytes)
        unsigned char nonce[16];

        // Leemos de /dev/urandom el numero aleatorio de 8 bytes
        FILE *urandom = fopen("/dev/urandom", "r");
        if (urandom == NULL) {
            err(EXIT_FAILURE, "fopen failed");
        }
        fread(nonce, 1, 8, urandom);  // Leemos de 1 byte en 1 byte hasta llenar 8 bytes
        fclose(urandom);

        // Creamos el nonce entero
        memset(nonce + 8, 0, 8);  // LLenamos con ceros a partir del octav byte
        memcpy(nonce + 8, &auth_counter, sizeof(int));  // Concatenamos el contador
        auth_counter++;

        // Enviamos el nonce de 16 bytes al cliente
        if (write(fd, nonce, 16) != 16) {
            printf("Error sending the nonce to the client\n");
            close(fd);
            continue; // Pasamos a atender al siguiente cliente
        }

        // Cuando terminemos con el cliente lo cerramos (terminamos su conexion)
        close(fd);
    }

    // Cerramos el socket del servidor
    close(sockfd);

    exit(EXIT_SUCCESS);
}


/*
IMPORTANTE
    En el servidor usar inet_ntoa para pasar de binario a texto legible
    En el cliente usar inet_aton para pasar de texto legible a binario
*/
    