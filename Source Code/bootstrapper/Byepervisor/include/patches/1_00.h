#ifndef PATCHES_1_00_H
#define PATCHES_1_00_H

#include "patch_common.h"

struct hook g_kernel_hooks_100[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        "sys_is_development_mode() -> isDevelopmentMode()",
        0x44000,
        0x9071AB
    },
};

struct patch g_kernel_patches_100[] = {
    {
        /*
            mov qword ptr [rdi + 0x408], 0xc0ffee;
            xor eax, eax;
            ret
        */
        "sys_getgid()", 
        0x2f17a0, 
        "\x48\xC7\x87\x08\x04\x00\x00\xEE\xFF\xC0\x00\x31\xC0\xC3",
        14 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrHasMmapSelfCapability()", 
        0x5a9710, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrIsAllowedToMmapSelf()", 
        0x5a9720, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6
    }, 
    {
        // xor eax, eax; 3x nop
        "vm_mmap sceSblAuthMgrIsLoadable() call", 
        0x981099, 
        "\x31\xC0\x90\x90\x90", 
        5
    }, 
    {
        // xor eax, eax; ret
        "cfi_check_fail()",
        0x4587e0,
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
        0x40b0d20,
        "\x00",
        1
    }, 
    {
        "panic patch 1",
        0x721d40,
        "\xC3",
        1
    }, 
    {
        "panic patch 2",
        0x40514b,
        "\xEB\xFE",
        2
    }, 
    {
        "panic patch 3",
        0x7223b0,
        "\xC3",
        1
    }, 
    {
        "panic patch 4",
        0x7228a0,
        "\xC3",
        1
    }, 
    {
        "panic patch 5",
        0x722450,
        "\xC3",
        1
    }, 
    {
        "panic patch 6",
        0x7225a0,
        "\xC3",
        1
    }, 
    {
        "panic patch 7",
        0x722720,
        "\xC3",
        1
    }, 
    {
        "panic patch 8",
        0x722950,
        "\xC3",
        1
    }, 
    {
        "panic patch 9",
        0x722a10,
        "\xC3",
        1
    }, 
    {
        "panic patch 10",
        0x722ad0,
        "\xC3",
        1
    }, 
    {
        "panic patch 11",
        0x722ba0,
        "\xC3",
        1
    }, 
    {
        "panic patch 12",
        0x722c70,
        "\xC3",
        1
    }, 
    {
        "panic patch 13",
        0x722d50,
        "\xC3",
        1
    }, 
    {
        "panic patch 14",
        0x71d12e,
        "\xB8\x00\x00\x00\x00",
        5
    }, 
    {
        "panic patch 15",
        0x71d15b,
        "\xB8\x00\x00\x00\x00",
        5
    },	
	{
        "MMAP_RWX_PATCH_1",
        0x97F914,
        "\xF7",
        1
    },
	{
        "MMAP_RWX_PATCH_1",
        0x97F997,
        "\xF7",
        1
    },
	{
        "MPTROTECT_PATCH",
        0x312A01,
        "\x00\x00\x00\x00",
        4
    }
};

#endif // PATCHES_1_00_H
