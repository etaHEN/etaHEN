#ifndef PATCHES_1_14_H
#define PATCHES_1_14_H

#include "patch_common.h"

struct hook g_kernel_hooks_114[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        "sys_is_development_mode() -> isDevelopmentMode()",
        0x44000,
        0x9081db
    },
};

struct patch g_kernel_patches_114[] = {
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
        0x5A9D10, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrIsAllowedToMmapSelf()", 
        0x5A9D20, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6
    }, 
    {
        // xor eax, eax; 3x nop
        "vm_mmap sceSblAuthMgrIsLoadable() call", 
        0x982139, 
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
        0x722550,
        "\xC3",
        1
    }, 
    {
        "panic patch 2",
        0x4056BB,
        "\xEB\xFE",
        2
    }, 
    {
        "panic patch 3",
        0x722BC0,
        "\xC3",
        1
    }, 
    {
        "panic patch 4",
        0x7230B0,
        "\xC3",
        1
    }, 
    {
        "panic patch 5",
        0x722C60,
        "\xC3",
        1
    }, 
    {
        "panic patch 6",
        0x722DB0,
        "\xC3",
        1
    }, 
    {
        "panic patch 7",
        0x722F30,
        "\xC3",
        1
    }, 
    {
        "panic patch 8",
        0x723160,
        "\xC3",
        1
    }, 
    {
        "panic patch 9",
        0x723220,
        "\xC3",
        1
    }, 
    {
        "panic patch 10",
        0x7232E0,
        "\xC3",
        1
    }, 
    {
        "panic patch 11",
        0x7233B0,
        "\xC3",
        1
    }, 
    {
        "panic patch 12",
        0x723480,
        "\xC3",
        1
    }, 
    {
        "panic patch 13",
        0x723560,
        "\xC3",
        1
    }, 
    {
        "panic patch 14",
        0x71D93E,
        "\xB8\x00\x00\x00\x00",
        5
    }, 
    {
        "panic patch 15",
        0x71D96B,
        "\xB8\x00\x00\x00\x00",
        5
    },	
	{
        "MMAP_RWX_PATCH_1",
        0x9809B4,
        "\xF7",
        1
    },
	{
        "MMAP_RWX_PATCH_1",
        0x980A37,
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

#endif // PATCHES_1_14_H