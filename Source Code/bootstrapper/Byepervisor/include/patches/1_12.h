#ifndef PATCHES_1_12_H
#define PATCHES_1_12_H

#include "patch_common.h"

struct hook g_kernel_hooks_112[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        "sys_is_development_mode() -> isDevelopmentMode()",
        0x44000,
        0x907c5b
    },
};

struct patch g_kernel_patches_112[] = {
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
        0x981BB9, 
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
        0x722530,
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
        0x722BA0,
        "\xC3",
        1
    }, 
    {
        "panic patch 4",
        0x723090,
        "\xC3",
        1
    }, 
    {
        "panic patch 5",
        0x722C40,
        "\xC3",
        1
    }, 
    {
        "panic patch 6",
        0x722D90,
        "\xC3",
        1
    }, 
    {
        "panic patch 7",
        0x722F10,
        "\xC3",
        1
    }, 
    {
        "panic patch 8",
        0x723140,
        "\xC3",
        1
    }, 
    {
        "panic patch 9",
        0x723200,
        "\xC3",
        1
    }, 
    {
        "panic patch 10",
        0x7232C0,
        "\xC3",
        1
    }, 
    {
        "panic patch 11",
        0x723390,
        "\xC3",
        1
    }, 
    {
        "panic patch 12",
        0x723460,
        "\xC3",
        1
    }, 
    {
        "panic patch 13",
        0x723540,
        "\xC3",
        1
    }, 
    {
        "panic patch 14",
        0x71D91E,
        "\xB8\x00\x00\x00\x00",
        5
    }, 
    {
        "panic patch 15",
        0x71D94B,
        "\xB8\x00\x00\x00\x00",
        5
    },	
	{
        "MMAP_RWX_PATCH_1",
        0x980434,
        "\xF7",
        1
    },
	{
        "MMAP_RWX_PATCH_1",
        0x9804B7,
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

#endif // PATCHES_1_12_H