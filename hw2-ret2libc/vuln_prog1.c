#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void name() {
	system("whoami");
}

void welcome() {
	printf("Howdy ");
	name();
}

void leave() {
	printf("See you next time\n");
	exit(0);
}

void print_argument(char* arg)
{
	char buf[256];

	strcpy(buf, arg);
	printf("Input: %s\n", buf);
}

int main(int argc, char* argv[]) 
{
	
	if (argc < 2) {
		fprintf(stderr, "Usage: %s input\n", argv[0]);
		exit(1);
	}

	print_argument(argv[1]);

	return 0;
}
