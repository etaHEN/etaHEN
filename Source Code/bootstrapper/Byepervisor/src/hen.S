.section .rodata
    .global KELF
    .type   KELF, @object
    .align  16
KELF:
    .incbin HEN_BIN_PATH
KELF_END:
    .global KELF_SZ
    .type   KELF_SZ, @object
    .align  16
KELF_SZ:
    .quad    KELF_END - KELF
