#ifndef PATCHES_2_20_H
#define PATCHES_2_20_H

#include "patch_common.h"

struct hook g_kernel_hooks_220[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        "sys_is_development_mode() -> isDevelopmentMode()",
        0x44000,
        0x929c2b
    },
};

struct patch g_kernel_patches_220[] = {
    {
        /*
            mov qword ptr [rdi + 0x408], 0xc0ffee;
            xor eax, eax;
            ret
        */
        "sys_getgid()", 
        0x2A69F0, 
        "\x48\xC7\x87\x08\x04\x00\x00\xEE\xFF\xC0\x00\x31\xC0\xC3",
        14 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrHasMmapSelfCapability()", 
        0x5809D0, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrIsAllowedToMmapSelf()", 
        0x5809E0, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6
    }, 
    {
        // xor eax, eax; 3x nop
        "vm_mmap sceSblAuthMgrIsLoadable() call", 
        0x9A6409, 
        "\x31\xC0\x90\x90\x90", 
        5
    }, 
    {
        // xor eax, eax; ret
        "cfi_check_fail()",
        0x41FCB0,
        "\xC3",
        1
    }, 
    {
        // jmp qword ptr [rsi]
        "kexec trampoline gadget",
        0x0042000,
        "\xFF\x26",
        2
    }, 
    {
        "sysveri flag",
        0x411CD70,
        "\x00",
        1
    }, 
    {
        "panic patch 1",
        0x71E3A0,
        "\xC3",
        1
    }, 
    {
        "panic patch 2",
        0x3C7A26,
        "\xEB\xFE",
        2
    }, 
    {
        "panic patch 3",
        0x71EBF0,
        "\xC3",
        1
    }, 
    {
        "panic patch 4",
        0x71EC90,
        "\xC3",
        1
    }, 
    {
        "panic patch 5",
        0x71ED40,
        "\xC3",
        1
    }, 
    {
        "panic patch 6",
        0x71EE90,
        "\xC3",
        1
    }, 
    {
        "panic patch 7",
        0x71F010,
        "\xC3",
        1
    }, 
    {
        "panic patch 8",
        0x71F190,
        "\xC3",
        1
    }, 
    {
        "panic patch 9",
        0x71F250,
        "\xC3",
        1
    }, 
    {
        "panic patch 10",
        0x71F310,
        "\xC3",
        1
    }, 
    {
        "panic patch 11",
        0x71F3E0,
        "\xC3",
        1
    }, 
    {
        "panic patch 12",
        0x71F4B0,
        "\xC3",
        1
    }, 
    {
        "panic patch 13",
        0x71F590,
        "\xC3",
        1
    }, 
    {
        "panic patch 14",
        0x718D5A,
        "\xB8\x00\x00\x00\x00",
        5
    }, 
    {
        "panic patch 15",
        0x718D87,
        "\xB8\x00\x00\x00\x00",
        5
    },	
	{
        "MMAP_RWX_PATCH_1",
        0x9A4C63,
        "\xF7",
        1
    },
	{
        "MMAP_RWX_PATCH_1",
        0x9A4CE6,
        "\xF7",
        1
    },
	{
        "MPTROTECT_PATCH",
        0x2C8FD1,
        "\x00\x00\x00\x00",
        4
    }
};

#endif // PATCHES_2_20_H