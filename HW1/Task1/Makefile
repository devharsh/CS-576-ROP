CFLAGS=-fno-stack-protector -O0 #-mpreferred-stack-boundary=2 
TARGETS=passwd-1.c
TARGETS+=passwd-1
CC=gcc
LD=ld

all: $(TARGETS)


%: %.o
	$(LD) -o $@ $<

%.o: %.S
	$(CC) -c $<

%.sc: %.o
	 objcopy -O binary --only-section=.text $< $@

%.c: %.sc
	@rm -f $@
	@echo -n "const char shellcode[] = \"" > $@
	@hexdump -v -e '"\\""x" 1/1 "%02x" ""' $< >> $@
	@echo '";' >> $@


%.o: %.c
	$(CC) $(CFLAGS) -c $< 

clean:
	rm -rf $(TARGETS) *.o
