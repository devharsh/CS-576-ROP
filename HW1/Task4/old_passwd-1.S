	.global _start

	.text

_start:
	# open(/etc/passwd)
	xor	%rax, %rax
	addb	$2, %al
	#lea	path, %rdi
	push	$path
	pop	%rdi
	#mov	$path, %rdi
	xor	%rsi, %rsi
	syscall

	# read(/etc/passwd)
	mov	%rax, %rdi
	sub	$40, %rsp
	lea	0x08(%rsp), %rsi
	xor	%rdx, %rdx
	addb	$40, %dl
	xor 	%rax, %rax
	syscall

	# write(/etc/passwd)
	xor	%rax, %rax
	inc	%rax			# system call 1 is write
	mov	%rax, %rdi		# file handle 1 is stdout
	mov	%rsp, %rsi
        xor	%rdx, %rdx
	addb	$40, %dl		# number of bytes
        syscall

	# exit(0)
	xor	%rax, %rax
	addb	$60, %al
	xor	%rdi, %rdi
	syscall

path:
	.ascii	"/etc/passwd"
