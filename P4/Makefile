all: authserver authclient

authserver: authserver.o hmacsha1.o utils.o
	gcc -g -o authserver authserver.o hmacsha1.o utils.o -lcrypto

authclient: authclient.o hmacsha1.o utils.o
	gcc -g -o authclient authclient.o hmacsha1.o utils.o -lcrypto

authserver.o: authserver.c utils.h
	gcc -g -c -Wall -Wshadow -Wvla authserver.c

authclient.o: authclient.c utils.h
	gcc -g -c -Wall -Wshadow -Wvla authclient.c

utils.o: utils.c utils.h
	gcc -g -c -Wall -Wshadow -Wvla utils.c

hmacsha1.o: hmacsha1.c
	gcc -g -c -Wall -Wshadow -Wvla hmacsha1.c

clean:
	rm -f authserver authclient *.o