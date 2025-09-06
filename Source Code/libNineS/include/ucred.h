#pragma once

#include <stdint.h>
#include <unistd.h>
#define _KERNEL
#include <sys/ucred.h>
#undef _KERNEL

#include "proc.h"

#define DEBUG_AUTHID 0x4800000000000006
#define PTRACE_AUTHID    0x4800000000010003
#define UCRED_AUTHID_KERNEL_OFFSET

// uintptr_t get_current_ucred();
void set_ucred_to_debugger();
uint8_t* jailbreak_process(pid_t pid);
void jail_process(pid_t pid, uint8_t* ucred);
