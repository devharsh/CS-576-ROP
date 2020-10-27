#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define STDIN 0

void name() {
	system("whoami");
}

void welcome() {
	printf("Howdy ");
	name();
}

void rude() {
	printf("Exiting.\n");
	exit(0);
}

void get_text() {
	char buf[256];
	read(STDIN, buf, 512);
	printf("Echo:\n%s\n",buf);
}

int main(int argc, char* argv[]) {
	setbuf(stdout, NULL);
	welcome();
	get_text();
	rude();
	return 0;
}
