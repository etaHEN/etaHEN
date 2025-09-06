#pragma once
#ifndef KEXEC_H
#define KEXEC_H

struct sysent {
    uint32_t n_arg;             // 0x00
    uint32_t pad_04h;           // 0x04
    uint64_t sy_call;           // 0x08
    uint64_t sy_auevent;        // 0x10
    uint64_t sy_systrace_args;  // 0x18
    uint32_t sy_entry;          // 0x20
    uint32_t sy_return;         // 0x24
    uint32_t sy_flags;          // 0x28
    uint32_t sy_thrcnt;         // 0x2C
};

struct kexec_args {
    uint64_t fptr;              // 0x00
    uint64_t fw;                // 0x08
    uint64_t kernel_base;       // 0x10
};

void install_custom_syscall(int sysc, uint32_t num_args, uint64_t gadget);
void install_kexec();
int kexec(uint64_t fptr);

#endif // KEXEC_H