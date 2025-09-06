#ifndef PATCHES_2_26_H
#define PATCHES_2_26_H

#include "patch_common.h"

struct hook g_kernel_hooks_226[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        "sys_is_development_mode() -> isDevelopmentMode()",
        0x44000,
        0x929d0b
    },
};

struct patch g_kernel_patches_226[] = {
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
        0x580A80, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrIsAllowedToMmapSelf()", 
        0x580A90, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6
    }, 
    {
        // xor eax, eax; 3x nop
        "vm_mmap sceSblAuthMgrIsLoadable() call", 
        0x9A64E9, 
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
        0x71E450,
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
        0x71ECA0,
        "\xC3",
        1
    }, 
    {
        "panic patch 4",
        0x71ED40,
        "\xC3",
        1
    }, 
    {
        "panic patch 5",
        0x71EDF0,
        "\xC3",
        1
    }, 
    {
        "panic patch 6",
        0x71EF40,
        "\xC3",
        1
    }, 
    {
        "panic patch 7",
        0x71F0C0,
        "\xC3",
        1
    }, 
    {
        "panic patch 8",
        0x71F240,
        "\xC3",
        1
    }, 
    {
        "panic patch 9",
        0x71F300,
        "\xC3",
        1
    }, 
    {
        "panic patch 10",
        0x71F3C0,
        "\xC3",
        1
    }, 
    {
        "panic patch 11",
        0x71F490,
        "\xC3",
        1
    }, 
    {
        "panic patch 12",
        0x71F560,
        "\xC3",
        1
    }, 
    {
        "panic patch 13",
        0x71F640,
        "\xC3",
        1
    }, 
    {
        "panic patch 14",
        0x718E0A,
        "\xB8\x00\x00\x00\x00",
        5
    }, 
    {
        "panic patch 15",
        0x718E37,
        "\xB8\x00\x00\x00\x00",
        5
    },	
	{
        "MMAP_RWX_PATCH_1",
        0x9A4D43,
        "\xF7",
        1
    },
	{
        "MMAP_RWX_PATCH_1",
        0x9A4DC6,
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



#endif // PATCHES_2_26_H