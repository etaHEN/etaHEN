#pragma once

#include <stdint.h>
#include <unistd.h>

#define PROC_UCRED_OFFSET 0x40

extern const uintptr_t kernel_base; // NOLINT

void kernel_copyin(void *src, uint64_t kdest, size_t length);
void kernel_copyout(uint64_t ksrc, void *dest, size_t length);
