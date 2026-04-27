all: authserver authclient

authserver: authserver_estudio.o hmacsha1_estudio.o utils_estudio.o
	gcc -g -o authserver authserver_estudio.o hmacsha1_estudio.o utils_estudio.o -lcrypto

authclient: authclient_estudio.o hmacsha1_estudio.o utils_estudio.o
	gcc -g -o authclient authclient_estudio.o hmacsha1_estudio.o utils_estudio.o -lcrypto

authserver_estudio.o: authserver_estudio.c utils_estudio.h
	gcc -g -c -Wall -Wshadow -Wvla authserver_estudio.c

authclient_estudio.o: authclient_estudio.c utils_estudio.h
	gcc -g -c -Wall -Wshadow -Wvla authclient_estudio.c

utils_estudio.o: utils_estudio.c utils_estudio.h
	gcc -g -c -Wall -Wshadow -Wvla utils_estudio.c

hmacsha1_estudio.o: hmacsha1_estudio.c
	gcc -g -c -Wall -Wshadow -Wvla hmacsha1_estudio.c

clean:
	rm -f authserver authclient *.o