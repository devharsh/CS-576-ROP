		.global _start

		.text

_start:
		mov		$path, %rdi
		mov		$59, %rax

		syscall


path:
		.ascii	"/bin/bash"