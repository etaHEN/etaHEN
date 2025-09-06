#ifndef PATCHES_2_30_H
#define PATCHES_2_30_H

#include "patch_common.h"

struct hook g_kernel_hooks_230[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        "sys_is_development_mode() -> isDevelopmentMode()",
        0x44000,
        0x929fdb
    },
};

struct patch g_kernel_patches_230[] = {
    {
        /*
            mov qword ptr [rdi + 0x408], 0xc0ffee;
            xor eax, eax;
            ret
        */
        "sys_getgid()", 
        0x2A66D0, 
        "\x48\xC7\x87\x08\x04\x00\x00\xEE\xFF\xC0\x00\x31\xC0\xC3",
        14 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrHasMmapSelfCapability()", 
        0x580D50, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrIsAllowedToMmapSelf()", 
        0x580D60, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6
    }, 
    {
        // xor eax, eax; 3x nop
        "vm_mmap sceSblAuthMgrIsLoadable() call", 
        0x9A67B9, 
        "\x31\xC0\x90\x90\x90", 
        5
    }, 
    {
        // xor eax, eax; ret
        "cfi_check_fail()",
        0x41FB70,
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
        0x71E720,
        "\xC3",
        1
    }, 
    {
        "panic patch 2",
        0x3C7726,
        "\xEB\xFE",
        2
    }, 
    {
        "panic patch 3",
        0x71EF70,
        "\xC3",
        1
    }, 
    {
        "panic patch 4",
        0x71F010,
        "\xC3",
        1
    }, 
    {
        "panic patch 5",
        0x71F0C0,
        "\xC3",
        1
    }, 
    {
        "panic patch 6",
        0x71F210,
        "\xC3",
        1
    }, 
    {
        "panic patch 7",
        0x71F390,
        "\xC3",
        1
    }, 
    {
        "panic patch 8",
        0x71F510,
        "\xC3",
        1
    }, 
    {
        "panic patch 9",
        0x71F5D0,
        "\xC3",
        1
    }, 
    {
        "panic patch 10",
        0x71F690,
        "\xC3",
        1
    }, 
    {
        "panic patch 11",
        0x71F760,
        "\xC3",
        1
    }, 
    {
        "panic patch 12",
        0x71F830,
        "\xC3",
        1
    }, 
    {
        "panic patch 13",
        0x71F910,
        "\xC3",
        1
    }, 
    {
        "panic patch 14",
        0x7190DA,
        "\xB8\x00\x00\x00\x00",
        5
    }, 
    {
        "panic patch 15",
        0x719107,
        "\xB8\x00\x00\x00\x00",
        5
    },

	
	    {
        "MMAP_RWX_PATCH_1",
        0x9A5013,
        "\xF7",
        1
    },
	
	   {
        "MMAP_RWX_PATCH_1",
        0x9A5096,
        "\xF7",
        1
    },
	
	 {
        "MPTROTECT_PATCH",
        0x2C8CB1,
        "\x00\x00\x00\x00",
        4
    }
};


#endif // PATCHES_2_30_H