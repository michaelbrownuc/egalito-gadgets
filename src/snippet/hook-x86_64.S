#ifdef ARCH_X86_64
    .text
    .global egalito_hook_function_entry
egalito_hook_function_entry:
    mov     egalito_inside_hook_code@gotpcrel(%rip), %rax
    cmpb    $0x0, (%rax)
    jne     1f
    push    %rbx
    mov     %rax, %rbx
    movb    $0x1, (%rax)
    mov     0x8(%rsp), %rdi
    mov     egalito_hook_function_entry_hook@gotpcrel(%rip), %rax
    callq   *(%rax)
    movb    $0x0, (%rbx)
    pop     %rbx
1:
    retq
    .type egalito_hook_function_entry, STT_FUNC
    .size egalito_hook_function_entry, .-egalito_hook_function_entry


    .global egalito_hook_function_exit
egalito_hook_function_exit:
    mov     egalito_inside_hook_code@gotpcrel(%rip), %rax
    cmpb    $0x0, (%rax)
    jne     1f
    push    %rbx
    mov     %rax, %rbx
    movb    $0x1, (%rax)
    mov     0x8(%rsp), %rdi
    mov     egalito_hook_function_exit_hook@gotpcrel(%rip), %rax
    callq   *(%rax)
    movb    $0x0, (%rbx)
    pop     %rbx
1:
    retq
    .type egalito_hook_function_exit, STT_FUNC
    .size egalito_hook_function_exit, .-egalito_hook_function_exit

    .global egalito_hook_instruction
egalito_hook_instruction:
    mov     egalito_inside_hook_code@gotpcrel(%rip), %rax
    cmpb    $0x0, (%rax)
    jne     1f
    push    %rbx
    mov     %rax, %rbx
    movb    $0x1, (%rax)
    mov     0x8(%rsp), %rdi
    mov     egalito_hook_instruction_hook@gotpcrel(%rip), %rax
    callq   *(%rax)
    movb    $0x0, (%rbx)
    pop     %rbx
1:
    retq
    .type egalito_hook_instruction, STT_FUNC
    .size egalito_hook_instruction, .-egalito_hook_instruction

   .global egalito_hook_jit_fixup
egalito_hook_jit_fixup:
    # mm1 = gstable offset
    sub     $0x8, %rsp
    push    %rax
    push    %rcx
    push    %rdx
    push    %rsi
    push    %rdi
    push    %r8
    push    %r9
    push    %r10
    push    %r11
#if 1
    # this guards resetting inside egalito_printf
    mov     egalito_inside_hook_code@gotpcrel(%rip), %rax
    cmpb    $0x0, (%rax)
    jne     in_code
    movb    $0x1, (%rax)
#endif

    push    %rbx
    mov     %rax, %rbx

    mov     egalito_jit_gs_fixup@gotpcrel(%rip), %rax
    movq    %mm1, %rdi
    movq    %rdi, 0x50(%rsp)

#if 1   //REWRITE_RA == 1
    pushq   $0x0                # !!! special entry
    movl    $(1f-egalito_hook_jit_fixup), 0x4(%rsp)
    jmpq    *%gs:(%rax)
1:
#else
    callq   *%gs:(%rax)
#endif

#if 1
    movb    $0x0, (%rbx)
#endif

    movq    0x50(%rsp), %r11

    pop     %rbx

    pop     %r10    # discard
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rdi
    pop     %rsi
    pop     %rdx
    pop     %rcx
    pop     %rax
    add     $0x8, %rsp
    jmpq    *%gs:(%r11) # displacement should be zero

in_code:
    movq    %mm1, %rdi  # offset
    jmp     .
#if 0
    pop     %r12
    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rdi
    pop     %rsi
    pop     %rdx
    pop     %rcx
    pop     %rax
    retq
#endif
    .type egalito_hook_jit_fixup, STT_FUNC
    .size egalito_hook_jit_fixup, .-egalito_hook_jit_fixup

    .global egalito_hook_jit_fixup_return
egalito_hook_jit_fixup_return:
    pop     %r11
1:
    movq    %gs:(%r11d), %r11
    cmpq    %gs:0x0, %r11
    je      2f
    add     -0x4(%rsp), %r11d
    jmpq    *%r11
2:
    mov     -0x8(%rsp), %r11
    test    %r11d, %r11d
    jne     3f
    movq    %gs:(%r11d), %r11
    add     -0x4(%rsp), %r11d
    jmpq    *%r11
3:
    push    %rax
    push    %rcx
    push    %rdx
    push    %rsi
    push    %rdi
    push    %r8
    push    %r9
    push    %r10
    push    %r11

#if 1
    # this guards resetting inside egalito_printf
    mov     egalito_inside_hook_code@gotpcrel(%rip), %rax
    movb    $0x1, (%rax)
#endif

    push    %rbx
    mov     %rax, %rbx

    mov     egalito_jit_gs_fixup@gotpcrel(%rip), %rax
    movl    %r11d, %edi

    pushq   $0x8                # !!! special entry
    movl    $(4f-egalito_hook_jit_fixup_return), 0x4(%rsp)
    jmpq    *%gs:(%rax)
4:
#if 1
    movb    $0x0, (%rbx)
#endif

    pop     %rbx

    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rdi
    pop     %rsi
    pop     %rdx
    pop     %rcx
    pop     %rax

    movq    %r11, -0x8(%rsp)
    jmp     1b
    .type egalito_hook_jit_fixup_return, STT_FUNC
    .size egalito_hook_jit_fixup_return, .-egalito_hook_jit_fixup_return

   .global egalito_hook_jit_reset_on_syscall
egalito_hook_jit_reset_on_syscall:
    # ok to clobber r10 & 11 (see AMD64 Linux Kernel Conventions)
    # syscall arguments(rdi, rsi, rdx, rcx, r8, r9) and return value(rax)
    # are preserved
    push    %rax
    push    %rcx
    push    %rdx
    push    %rsi
    push    %rdi
    push    %r8
    push    %r9

#if 1
    mov     egalito_inside_hook_code@gotpcrel(%rip), %rax
    cmpb    $0x0, (%rax)
    jne     2f
    movb    $0x1, (%rax)
#endif

    # REWRITE_RA == 1
    push    %rbx    # for alignment
    pushq   $0x10
    movl    $(1f-egalito_hook_jit_reset_on_syscall), 0x4(%rsp)
    mov     egalito_jit_gs_reset@gotpcrel(%rip), %rax
    jmpq    *%gs:(%rax)

1:
    pop     %rbx
#if 1
    mov     egalito_inside_hook_code@gotpcrel(%rip), %rax
    movb    $0x0, (%rax)

2:
#endif
    pop     %r9
    pop     %r8
    pop     %rdi
    pop     %rsi
    pop     %rdx
    pop     %rcx
    pop     %rax
    jmpq    *%gs:0x8
    .type egalito_hook_jit_reset_on_syscall, STT_FUNC
    .size egalito_hook_jit_reset_on_syscall, .-egalito_hook_jit_reset_on_syscall

//
// begin .bss section
//
    .bss
    .align 8
    .global egalito_inside_hook_code
egalito_inside_hook_code:
    .skip 8
    .type egalito_inside_hook_code, STT_OBJECT
    .size egalito_inside_hook_code, .-egalito_inside_hook_code

    .global egalito_hook_function_entry_hook
    .weak egalito_hook_function_entry_hook
egalito_hook_function_entry_hook:
    .skip 8
    .type egalito_hook_function_entry_hook, STT_OBJECT
    .size egalito_hook_function_entry_hook, .-egalito_hook_function_entry_hook

    .global egalito_hook_function_exit_hook
    .weak egalito_hook_function_exit_hook
egalito_hook_function_exit_hook:
    .skip 8
    .type egalito_hook_function_exit_hook, STT_OBJECT
    .size egalito_hook_function_exit_hook, .-egalito_hook_function_exit_hook

    .global egalito_hook_instruction_hook
    .weak egalito_hook_instruction_hook
egalito_hook_instruction_hook:
    .skip 8
    .type egalito_hook_instruction_hook, STT_OBJECT
    .size egalito_hook_instruction_hook, .-egalito_hook_instruction_hook
#endif