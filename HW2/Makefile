CFLAGS_V=-fno-stack-protector -O0 -z noexecstack
CFLAGS=-O1 -Wall
TARGETS=vuln_prog1.bin vuln_prog2.bin
CC=gcc

all: $(TARGETS)

vuln_prog1.bin : vuln_prog1.c
	$(CC) -m32 $(CFLAGS_V) -o $@ $<

vuln_prog2.bin : vuln_prog2.c
	$(CC) -m64 $(CFLAGS_V) -o $@ $<

clean:
	rm -rf $(TARGETS)
