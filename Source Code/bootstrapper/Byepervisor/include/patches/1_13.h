#ifndef PATCHES_1_13_H
#define PATCHES_1_13_H

#include "patch_common.h"

struct hook g_kernel_hooks_113[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        "sys_is_development_mode() -> isDevelopmentMode()",
        0x44000,
        0x907c2b
    },
};

struct patch g_kernel_patches_113[] = {
    {
        /*
            mov qword ptr [rdi + 0x408], 0xc0ffee;
            xor eax, eax;
            ret
        */
        "sys_getgid()", 
        0x2F1810, 
        "\x48\xC7\x87\x08\x04\x00\x00\xEE\xFF\xC0\x00\x31\xC0\xC3",
        14 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrHasMmapSelfCapability()", 
        0x5A9CF0, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrIsAllowedToMmapSelf()", 
        0x5A9D00, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6
    }, 
    {
        // xor eax, eax; 3x nop
        "vm_mmap sceSblAuthMgrIsLoadable() call", 
        0x981B89, 
        "\x31\xC0\x90\x90\x90", 
        5
    }, 
    {
        // xor eax, eax; ret
        "cfi_check_fail()",
        0x458D70,
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
        0x40B0DA0,
        "\x00",
        1
    }, 
    {
        "panic patch 1",
        0x7224E0,
        "\xC3",
        1
    }, 
    {
        "panic patch 2",
        0x4056B6,
        "\xEB\xFE",
        2
    }, 
    {
        "panic patch 3",
        0x722B50,
        "\xC3",
        1
    }, 
    {
        "panic patch 4",
        0x723040,
        "\xC3",
        1
    }, 
    {
        "panic patch 5",
        0x722BF0,
        "\xC3",
        1
    }, 
    {
        "panic patch 6",
        0x722D40,
        "\xC3",
        1
    }, 
    {
        "panic patch 7",
        0x722EC0,
        "\xC3",
        1
    }, 
    {
        "panic patch 8",
        0x7230F0,
        "\xC3",
        1
    }, 
    {
        "panic patch 9",
        0x7231B0,
        "\xC3",
        1
    }, 
    {
        "panic patch 10",
        0x723270,
        "\xC3",
        1
    }, 
    {
        "panic patch 11",
        0x723340,
        "\xC3",
        1
    }, 
    {
        "panic patch 12",
        0x723410,
        "\xC3",
        1
    }, 
    {
        "panic patch 13",
        0x7234F0,
        "\xC3",
        1
    }, 
    {
        "panic patch 14",
        0x71D8CE,
        "\xB8\x00\x00\x00\x00",
        5
    }, 
    {
        "panic patch 15",
        0x71D8FB,
        "\xB8\x00\x00\x00\x00",
        5
    },	
	{
        "MMAP_RWX_PATCH_1",
        0x980404,
        "\xF7",
        1
    },
	{
        "MMAP_RWX_PATCH_1",
        0x980487,
        "\xF7",
        1
    },
	{
        "MPTROTECT_PATCH",
        0x312B81,
        "\x00\x00\x00\x00",
        4
    }
};

#endif // PATCHES_1_13_H