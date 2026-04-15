#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <ctype.h>
#include <limits.h>

enum {
	Nsyms = 'Z' - 'A' + 1,
	First_mayus = 'A'
};

void
ok_args(int argc, char *argv[])
{
	if (argc != 2)
		errx(EXIT_FAILURE, "usage: %s key", argv[0]);
}

int
key_to_int(int argc, char *argv[])
{
	char *endptr;
	long key;

	key = strtol(argv[1], &endptr, 10);
	if (*endptr != '\0' || key < 0 || key > INT_MAX)
		errx(EXIT_FAILURE, "error: bad value %ld", key);
	else {
		return (int)key;
	}
}

char
encript_char(int char_int, int key)
{
	int char_mayus = 0;
	int pos = 0;
	int new_pos = 0;

	if (isalpha(char_int)) {
		char_mayus = toupper(char_int);
		pos = char_mayus - First_mayus;
		new_pos = (pos + key) % Nsyms;
		char char_encripted = First_mayus + new_pos;

		return char_encripted;
	} else
		return (char)char_int;
}

int
main(int argc, char *argv[])
{
	ok_args(argc, argv);
	int key = key_to_int(argc, argv);

	int char_int = 0;

	while ((char_int = fgetc(stdin)) != EOF) {
		char new_char = encript_char(char_int, key);

		printf("%c", new_char);
	}

	exit(EXIT_SUCCESS);
}
