		.global _start

		.text
_start:
		# open(/etc/passwd)
		mov		$2, %rax
		mov		$path, %rdi
		mov		$0, %rsi
		syscall

		# read(/etc/passwd)
		mov 	%rax, %rdi
		sub 	$40, %rsp
		lea 	0x08(%rsp), %rsi
		mov		$40,%rdx
		xor 	%rax, %rax
		syscall

		# write(/etc/passwd)
		mov     $1, %rax                # system call 1 is write
        mov     $1, %rdi                # file handle 1 is stdout
	    mov		%rsp, %rsi
        mov     $40, %rdx               # number of bytes
        syscall 

		
		# exit(0)
		mov		$60, %rax
		xor 	%rdi, %rdi
		syscall

path:
		.ascii	"/etc/passwd"
