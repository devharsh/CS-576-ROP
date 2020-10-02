#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RECURSE  100
#define MAX_STACKLEN 24



static int complex_verify(const char *buffer)
{
	char str[64];
	
	strcpy(str, buffer);

	int i;
	for (i = 0; i < (sizeof(str) - 1); i++)
		str[i]++;
	return (i - 62);
}

static void read_input()
{
	char buffer[512];

	if (fread(buffer, 1, 512, stdin) < 0) {
		perror("Error reading input");
		return;
	}

	complex_verify(buffer);
}


static void recursive_func(int r, int sl)
{
	char buf[sl];

	if (r <= 0) {
		read_input();
		return;
	}

	recursive_func(--r, sl);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Missing argument <student_id>\n");
		fprintf(stderr, "Usage: %s <student_id>\n", argv[0]);
		return EXIT_FAILURE;
	}

	char *endptr;
	unsigned long sid = strtoul(argv[1], &endptr, 10);
	if (*endptr != '\0') {
		fprintf(stderr, "Invalid <student_id>\nUse a positive integer value!\n");
		return EXIT_FAILURE;
	}


	srand((unsigned int)sid);

	int rand_i = rand();

	int recurse = (rand_i & 0xffff) % MAX_RECURSE;
	int stacklen = (rand_i >> 16) % MAX_STACKLEN;

	recursive_func(recurse, stacklen);


	return EXIT_SUCCESS;
}

