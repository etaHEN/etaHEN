#ifndef PATCHES_2_50_H
#define PATCHES_2_50_H

#include "patch_common.h"

struct hook g_kernel_hooks_250[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        "sys_is_development_mode() -> isDevelopmentMode()",
        0x44000,
        0x92A1EB
    },
};

struct patch g_kernel_patches_250[] = {
    {
        /*
            mov qword ptr [rdi + 0x408], 0xc0ffee;
            xor eax, eax;
            ret
        */
        "sys_getgid()", 
        0x02A67D0, 
        "\x48\xC7\x87\x08\x04\x00\x00\xEE\xFF\xC0\x00\x31\xC0\xC3",
        14 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrHasMmapSelfCapability()", 
        0x0580EB0, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrIsAllowedToMmapSelf()", 
        0x0580EC0, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6
    }, 
    {
        // xor eax, eax; 3x nop
        "vm_mmap sceSblAuthMgrIsLoadable() call", 
        0x09A6A59, 
        "\x31\xC0\x90\x90\x90", 
        5
    }, 
    {
        // xor eax, eax; ret
        "cfi_check_fail()",
        0x041FCA0,
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
        0x71E7A0,
        "\xC3",
        1
    }, 
    {
        "panic patch 2",
        0x3C7846,
        "\xEB\xFE",
        2
    }, 
    {
        "panic patch 3",
        0x71EFF0,
        "\xC3",
        1
    }, 
    {
        "panic patch 4",
        0x71F090,
        "\xC3",
        1
    }, 
    {
        "panic patch 5",
        0x71F140,
        "\xC3",
        1
    }, 
    {
        "panic patch 6",
        0x71F290,
        "\xC3",
        1
    }, 
    {
        "panic patch 7",
        0x71F410,
        "\xC3",
        1
    }, 
    {
        "panic patch 8",
        0x71F590,
        "\xC3",
        1
    }, 
    {
        "panic patch 9",
        0x71F650,
        "\xC3",
        1
    }, 
    {
        "panic patch 10",
        0x71F710,
        "\xC3",
        1
    }, 
    {
        "panic patch 11",
        0x71F7E0,
        "\xC3",
        1
    }, 
    {
        "panic patch 12",
        0x71F8B0,
        "\xC3",
        1
    }, 
    {
        "panic patch 13",
        0x71F990,
        "\xC3",
        1
    }, 
    {
        "panic patch 14",
        0x71915A,
        "\xB8\x00\x00\x00\x00",
        5
    }, 
    {
        "panic patch 15",
        0x719187,
        "\xB8\x00\x00\x00\x00",
        5
    },
    	
	    {
        "MMAP_RWX_PATCH_1",
        0x9A52B3,
        "\xF7",
        1
    },
	
	   {
        "MMAP_RWX_PATCH_1",
        0x9A5336,
        "\xF7",
        1
    },
	
	 {
        "MPTROTECT_PATCH",
        0x2C8DB1,
        "\x00\x00\x00\x00",
        4
    }
};

#endif // PATCHES_2_50_H