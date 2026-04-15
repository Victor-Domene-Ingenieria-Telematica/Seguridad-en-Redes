#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <ctype.h>
#include <string.h>
#include <math.h>

enum {
	Buffsize = 8 * 1024,
	Nsyms = 26,
	First_mayus = 'A',
	Nkeys = 25
};

double freqs[] = {
	0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094,
	0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507,
	0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978,
	0.02360, 0.00150, 0.01974, 0.00074
};

char *digrams[] = {
	"th", "he", "in", "en", "nt", "re", "er", "an", "ti", "es", "on", "at",
	"se", "nd", "or", "ar", "al", "te", "co", "de", "to", "ra", "et",
	"ed", "it", "sa", "em", "ro", NULL
};

char *trigrams[] = {
	"the", "and", "tha", "ent", "ing", "ion", "tio", "for", "nde", "has",
	"nce", "edt", "tis", "oft", "sth", "men", NULL
};

struct Candidate {
	int key;
	double distance;
	int cand_digs;
	int cand_trigs;
	char *text;
};

typedef struct Candidate Candidate;

void
ok_args(int argc, char *argv[])
{
	if (argc != 1)
		errx(EXIT_FAILURE, "usage: %s", argv[0]);
}

char *
desencrypt_chars(char *cipher, int len, int key)
{
	char *plain = malloc(len + 1);

	if (plain == NULL)
		err(EXIT_FAILURE, "malloc failed");

	int i, pos, new_pos;

	for (i = 0; i < len; i++) {
		if (isalpha(cipher[i])) {
			pos = cipher[i] - First_mayus;
			new_pos = (pos - key + Nsyms) % Nsyms;
			plain[i] = First_mayus + new_pos;
		} else {
			plain[i] = cipher[i];
		}
	}
	plain[len] = '\0';

	return plain;
}

void
get_freqs(char *text, int len, double *freq)
{
	int count[Nsyms];

	for (int i = 0; i < Nsyms; i++) {
		count[i] = 0;
	}

	for (int i = 0; i < len; i++) {
		if (isalpha(text[i])) {
			int pos = text[i] - First_mayus;

			count[pos]++;
		}
	}

	for (int i = 0; i < Nsyms; i++) {
		freq[i] = (double)count[i] / len;
	}
}

double
get_dist(double *freq1, double *freq2)
{
	double sum = 0.0;

	for (int i = 0; i < Nsyms; i++) {
		double diff = freq1[i] - freq2[i];

		sum = sum + (diff * diff);
	}

	return sqrt(sum);
}

int
get_digs(char *text, int len)
{
	int count = 0;
	int i;

	for (i = 0; i < len - 1; i++) {
		char d[3];

		snprintf(d, 3, "%c%c", tolower(text[i]), tolower(text[i + 1]));

		for (int j = 0; digrams[j] != NULL; j++) {
			if (strcmp(d, digrams[j]) == 0) {
				count++;
				break;
			}
		}
	}

	return count;
}

int
get_trigs(char *text, int len)
{
	int count = 0;
	int i;

	for (i = 0; i < len - 2; i++) {
		char t[4];

		snprintf(t, 4, "%c%c%c", tolower(text[i]), tolower(text[i + 1]),
			 tolower(text[i + 2]));

		for (int j = 0; trigrams[j] != NULL; j++) {
			if (strcmp(t, trigrams[j]) == 0) {
				count++;
				break;
			}
		}
	}

	return count;
}

void
creat_file(int key, char *text)
{
	char filename[20];

	snprintf(filename, 20, "key-%d.txt", key);

	FILE *f = fopen(filename, "w");

	if (f == NULL)
		err(EXIT_FAILURE, "fopen failed");

	fputs(text, f);
	fclose(f);
}

void
try_keys(Candidate *candidates, char *cipher, int len)
{
	for (int i = 0; i < Nkeys; i++) {
		int key = i + 1;

		candidates[i].key = key;

		candidates[i].text = desencrypt_chars(cipher, len, key);

		double freq[Nsyms];

		get_freqs(candidates[i].text, len, freq);

		candidates[i].distance = get_dist(freq, freqs);
		candidates[i].cand_digs = get_digs(candidates[i].text, len);
		candidates[i].cand_trigs = get_trigs(candidates[i].text, len);
	}
}

void
print_best_dist(Candidate *candidates, int best_dist)
{
	printf("%d: %f, %d, %d\n", candidates[best_dist].key,
	       candidates[best_dist].distance, candidates[best_dist].cand_digs,
	       candidates[best_dist].cand_trigs);
	creat_file(candidates[best_dist].key, candidates[best_dist].text);
}

void
print_best_dig(Candidate *candidates, int best_dist, int best_dig)
{
	if (best_dig != best_dist) {
		printf("%d: %f, %d, %d\n", candidates[best_dig].key,
		       candidates[best_dig].distance,
		       candidates[best_dig].cand_digs,
		       candidates[best_dig].cand_trigs);
		creat_file(candidates[best_dig].key, candidates[best_dig].text);
	}
}

void
print_best_tri(Candidate *candidates, int best_dist, int best_dig, int best_tri)
{
	if (best_tri != best_dist && best_tri != best_dig) {
		printf("%d: %f, %d, %d\n", candidates[best_tri].key,
		       candidates[best_tri].distance,
		       candidates[best_tri].cand_digs,
		       candidates[best_tri].cand_trigs);
		creat_file(candidates[best_tri].key, candidates[best_tri].text);
	}
}

int
main(int argc, char *argv[])
{
	ok_args(argc, argv);

	int capacity = Buffsize;
	int len = 0;
	char *cipher = malloc(capacity);

	if (cipher == NULL)
		err(EXIT_FAILURE, "malloc failed");

	int char_int;

	while ((char_int = fgetc(stdin)) != EOF) {
		if (len >= capacity) {
			capacity *= 2;
			cipher = realloc(cipher, capacity);
			if (cipher == NULL)
				err(EXIT_FAILURE, "realloc failed");
		}

		if (isalpha(char_int))
			cipher[len] = toupper(char_int);
		else
			cipher[len] = char_int;
		len++;
	}

	if (len == 0) {
		free(cipher);
		exit(EXIT_SUCCESS);
	}

	Candidate *candidates = malloc(Nkeys * sizeof(Candidate));

	if (candidates == NULL)
		err(EXIT_FAILURE, "malloc failed");

	try_keys(candidates, cipher, len);

	int best_dist = 0;

	for (int i = 1; i < Nkeys; i++) {
		if (candidates[i].distance < candidates[best_dist].distance)
			best_dist = i;
	}

	int best_dig = 0;

	for (int i = 1; i < Nkeys; i++) {
		if (candidates[i].cand_digs > candidates[best_dig].cand_digs)
			best_dig = i;
	}

	int best_tri = 0;

	for (int i = 1; i < Nkeys; i++) {
		if (candidates[i].cand_trigs > candidates[best_tri].cand_trigs)
			best_tri = i;
	}

	print_best_dist(candidates, best_dist);
	print_best_dig(candidates, best_dist, best_dig);
	print_best_tri(candidates, best_dist, best_dig, best_tri);

	for (int i = 0; i < Nkeys; i++)
		free(candidates[i].text);

	free(candidates);
	free(cipher);

	exit(EXIT_SUCCESS);
}
