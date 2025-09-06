#ifndef PATCHES_2_00_H
#define PATCHES_2_00_H

#include "patch_common.h"

struct hook g_kernel_hooks_200[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        "sys_is_development_mode() -> isDevelopmentMode()",
        0x44000,
        0x92976b
    },
};

struct patch g_kernel_patches_200[] = {
    {
        /*
            mov qword ptr [rdi + 0x408], 0xc0ffee;
            xor eax, eax;
            ret
        */
        "sys_getgid()", 
        0x2A69B0, 
        "\x48\xC7\x87\x08\x04\x00\x00\xEE\xFF\xC0\x00\x31\xC0\xC3",
        14 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrHasMmapSelfCapability()", 
        0x580860, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrIsAllowedToMmapSelf()", 
        0x580870, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6
    }, 
    {
        // xor eax, eax; 3x nop
        "vm_mmap sceSblAuthMgrIsLoadable() call", 
        0x9A5F49, 
        "\x31\xC0\x90\x90\x90", 
        5
    }, 
    {
        // xor eax, eax; ret
        "cfi_check_fail()",
        0x41FC60,
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
        0x71DEE0,
        "\xC3",
        1
    }, 
    {
        "panic patch 2",
        0x3C79D6,
        "\xEB\xFE",
        2
    }, 
    {
        "panic patch 3",
        0x71E730,
        "\xC3",
        1
    }, 
    {
        "panic patch 4",
        0x71E7D0,
        "\xC3",
        1
    }, 
    {
        "panic patch 5",
        0x71E880,
        "\xC3",
        1
    }, 
    {
        "panic patch 6",
        0x71E9D0,
        "\xC3",
        1
    }, 
    {
        "panic patch 7",
        0x71EB50,
        "\xC3",
        1
    }, 
    {
        "panic patch 8",
        0x71ECD0,
        "\xC3",
        1
    }, 
    {
        "panic patch 9",
        0x71ED90,
        "\xC3",
        1
    }, 
    {
        "panic patch 10",
        0x71EE50,
        "\xC3",
        1
    }, 
    {
        "panic patch 11",
        0x71EF20,
        "\xC3",
        1
    }, 
    {
        "panic patch 12",
        0x71EFF0,
        "\xC3",
        1
    }, 
    {
        "panic patch 13",
        0x71F0D0,
        "\xC3",
        1
    }, 
    {
        "panic patch 14",
        0x71889A,
        "\xB8\x00\x00\x00\x00",
        5
    }, 
    {
        "panic patch 15",
        0x7188C7,
        "\xB8\x00\x00\x00\x00",
        5
    },	
	{
        "MMAP_RWX_PATCH_1",
        0x9A47A3,
        "\xF7",
        1
    },
	{
        "MMAP_RWX_PATCH_1",
        0x9A4826,
        "\xF7",
        1
    },
	{
        "MPTROTECT_PATCH",
        0x2C8F91,
        "\x00\x00\x00\x00",
        4
    }
};


#endif // PATCHES_2_00_H