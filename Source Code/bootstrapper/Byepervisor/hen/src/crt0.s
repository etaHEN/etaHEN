.intel_syntax noprefix
.text

.section .text.prologue
.global _start
_start:
    jmp		kernel_main
