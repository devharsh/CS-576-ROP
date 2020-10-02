CFILES=hello.c hello-nonul.c hello-rip.c
CC=gcc
LD=ld
LDFLAGS=--omagic

.PHONY: clean

.PRECIOUS: %.sc %.o

all: $(CFILES:.c=.o) $(CFILES:.c=) $(CFILES:.c=.sc)

%.o: %.S
	$(CC) -c $<

%: %.o
	$(LD) $(LDFLAGS) -o $@ $<


%.sc: %
	objcopy -O binary --only-section=.text $< $@
	echo -n "const char shellcode[] = \"" > $<.c
	hexdump -v -e '"\\""x" 1/1 "%02x" ""' $@ >> $<.c
	echo '";' >> $<.c




clean:
	rm -rf $(CFILES:.c=) *.o *.sc *.c
