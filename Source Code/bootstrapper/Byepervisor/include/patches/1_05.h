#ifndef PATCHES_1_05_H
#define PATCHES_1_05_H

#include "patch_common.h"

struct hook g_kernel_hooks_105[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        "sys_is_development_mode() -> isDevelopmentMode()",
        0x44000,
        0x9079BB
    },
};

struct patch g_kernel_patches_105[] = {
    {
        /*
            mov qword ptr [rdi + 0x408], 0xc0ffee;
            xor eax, eax;
            ret
        */
        "sys_getgid()", 
        0x02f17d0, 
        "\x48\xC7\x87\x08\x04\x00\x00\xEE\xFF\xC0\x00\x31\xC0\xC3",
        14 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrHasMmapSelfCapability()", 
        0x5a9c20, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrIsAllowedToMmapSelf()", 
        0x5a9c30, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6
    }, 
    {
        // xor eax, eax; 3x nop
        "vm_mmap sceSblAuthMgrIsLoadable() call", 
        0x981909, 
        "\x31\xC0\x90\x90\x90", 
        5
    }, 
    {
        // xor eax, eax; ret
        "cfi_check_fail()",
        0x458c10,
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
        0x40b0da0,
        "\x00",
        1
    }, 
    {
        "panic patch 1",
        0x7222e0,
        "\xC3",
        1
    }, 
    {
        "panic patch 2",
        0x40561b,
        "\xEB\xFE",
        2
    }, 
    {
        "panic patch 3",
        0x722950,
        "\xC3",
        1
    }, 
    {
        "panic patch 4",
        0x722e40,
        "\xC3",
        1
    }, 
    {
        "panic patch 5",
        0x7229f0,
        "\xC3",
        1
    }, 
    {
        "panic patch 6",
        0x722b40,
        "\xC3",
        1
    }, 
    {
        "panic patch 7",
        0x722cc0,
        "\xC3",
        1
    }, 
    {
        "panic patch 8",
        0x722ef0,
        "\xC3",
        1
    }, 
    {
        "panic patch 9",
        0x722fb0,
        "\xC3",
        1
    }, 
    {
        "panic patch 10",
        0x723070,
        "\xC3",
        1
    }, 
    {
        "panic patch 11",
        0x723140,
        "\xC3",
        1
    }, 
    {
        "panic patch 12",
        0x723210,
        "\xC3",
        1
    }, 
    {
        "panic patch 13",
        0x7232f0,
        "\xC3",
        1
    }, 
    {
        "panic patch 14",
        0x71d6ce,
        "\xB8\x00\x00\x00\x00",
        5
    }, 
    {
        "panic patch 15",
        0x71d6fb,
        "\xB8\x00\x00\x00\x00",
        5
    },	
	{
        "MMAP_RWX_PATCH_1",
        0x980184,
        "\xF7",
        1
    },
	{
        "MMAP_RWX_PATCH_1",
        0x980207,
        "\xF7",
        1
    },
	{
        "MPTROTECT_PATCH",
        0x312B41,
        "\x00\x00\x00\x00",
        4
    }
};

#endif // PATCHES_1_05_H