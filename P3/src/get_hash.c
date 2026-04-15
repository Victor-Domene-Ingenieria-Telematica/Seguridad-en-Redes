// Programa para sacar la hash de un fichero pasado como argumento
// echo -n hola | sha1sum  --->  Para hacer la hash sin el \n

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <openssl/evp.h>  // Para usar las EVP


enum {
    Buffsize = 4096
};


void
ok_args(int argc, char *argv[])
{
    if(argc < 2)
        errx(EXIT_FAILURE, "usage: %s <fich>", argv[0]);
}


int
main(int argc, char *argv[])
{
    ok_args(argc, argv);

    // Creamos el buffer para almacenar la hash
    unsigned char hash[EVP_MAX_MD_SIZE];

    // Enteros para almacenar el valor de la longitud del hash
    unsigned int hash_len;

    // Contexto para crear el hash
    EVP_MD_CTX *mdctx;

    // Hacemos primero el new (no errno) para empezar con el hash
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
       errx(EXIT_FAILURE, "EVP_MD_CTX_new failed");

    // Hacemos el init (no errno)
    if (!EVP_DigestInit(mdctx, EVP_sha1()))
        errx(EXIT_FAILURE, "EVP_DigestInit failed");

    // Abrimos el fichero
    FILE *f_datos = fopen(argv[1], "r");
    if (f_datos == NULL)
        err(EXIT_FAILURE, "fopen failed");

    // Usamos un buffer para fread
    char buffer[Buffsize];
    size_t bytes_leidos;

    // Leemos el fichero por trozos (tamaño del buffer) y vamos actualizando el hash
    while ((bytes_leidos = fread(buffer, 1, Buffsize, f_datos)) > 0) {
        if (!EVP_DigestUpdate(mdctx, buffer, bytes_leidos))
            errx(EXIT_FAILURE, "EVP_DigestUpdate failed");
    }

    // Cerramos el fichero
    fclose(f_datos);

    // Hacemos el Final_ex (no errno)
    if (!EVP_DigestFinal_ex(mdctx, hash, &hash_len))
        errx(EXIT_FAILURE, "EVP_DigestFinal_ex failed");

    // Liberamos la creacion
    EVP_MD_CTX_free(mdctx);

    printf("Hash SHA-1 de %s --> ", argv[1]);
    int i;
    for (i = 0; i < hash_len; i++)
        printf("%02x", hash[i]);
    printf("\n");
    exit(EXIT_SUCCESS);
}