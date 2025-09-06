#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

extern "C"
{
#include <ps5/kernel.h>
}

#include "debug_log.h"
#include "kdlsym.h"
#include "patching.h"

#include "patches/1_00.h"
#include "patches/1_01.h"
#include "patches/1_02.h"
#include "patches/1_05.h"
#include "patches/1_10.h"
#include "patches/1_11.h"
#include "patches/1_12.h"
#include "patches/1_13.h"
#include "patches/1_14.h"
#include "patches/2_00.h"
#include "patches/2_20.h"
#include "patches/2_25.h"
#include "patches/2_26.h"
#include "patches/2_30.h"
#include "patches/2_50.h"

int apply_kernel_patches()
{
    uint64_t fw_ver;
    uint64_t kernel_base; 
    uint64_t patch_addr;
    struct patch *patches;
    struct patch *cur_patch;
    int num_patches;

    fw_ver = kernel_get_fw_version() & 0xFFFF0000;
    kernel_base = ktext(0);

    //SOCK_LOG("apply_kernel_patches: fw_ver=0x%lx\n", fw_ver);

    switch (fw_ver) {
    case 0x1000000:
        patches = (struct patch *) &g_kernel_patches_100;
        num_patches = sizeof(g_kernel_patches_100) / sizeof(struct patch);
        break;
    case 0x1010000:
        patches = (struct patch *) &g_kernel_patches_101;
        num_patches = sizeof(g_kernel_patches_101) / sizeof(struct patch);
        break;
    case 0x1020000:
        patches = (struct patch *) &g_kernel_patches_102;
        num_patches = sizeof(g_kernel_patches_102) / sizeof(struct patch);
        break;
    case 0x1050000:
        patches = (struct patch *) &g_kernel_patches_105;
        num_patches = sizeof(g_kernel_patches_105) / sizeof(struct patch);
        break;
    case 0x1100000:
        patches = (struct patch *) &g_kernel_patches_110;
        num_patches = sizeof(g_kernel_patches_110) / sizeof(struct patch);
        break;
    case 0x1110000:
        patches = (struct patch *) &g_kernel_patches_111;
        num_patches = sizeof(g_kernel_patches_111) / sizeof(struct patch);
        break;
    case 0x1120000:
        patches = (struct patch *) &g_kernel_patches_112;
        num_patches = sizeof(g_kernel_patches_112) / sizeof(struct patch);
        break;
    case 0x1130000:
        patches = (struct patch *) &g_kernel_patches_113;
        num_patches = sizeof(g_kernel_patches_113) / sizeof(struct patch);
        break;
    case 0x1140000:
        patches = (struct patch *) &g_kernel_patches_114;
        num_patches = sizeof(g_kernel_patches_114) / sizeof(struct patch);
        break;
    case 0x2000000:
        patches = (struct patch *) &g_kernel_patches_200;
        num_patches = sizeof(g_kernel_patches_200) / sizeof(struct patch);
        break;
    case 0x2200000:
        patches = (struct patch *) &g_kernel_patches_220;
        num_patches = sizeof(g_kernel_patches_220) / sizeof(struct patch);
        break;
    case 0x2250000:
        patches = (struct patch *) &g_kernel_patches_225;
        num_patches = sizeof(g_kernel_patches_225) / sizeof(struct patch);
        break;
    case 0x2260000:
        patches = (struct patch *) &g_kernel_patches_226;
        num_patches = sizeof(g_kernel_patches_226) / sizeof(struct patch);
        break;
    case 0x2300000:
        patches = (struct patch *) &g_kernel_patches_230;
        num_patches = sizeof(g_kernel_patches_230) / sizeof(struct patch);
        break;
    case 0x2500000:
    case 0x2700000:
        patches = (struct patch *) &g_kernel_patches_250;
        num_patches = sizeof(g_kernel_patches_250) / sizeof(struct patch);
        break;
    default:
        return -ENOENT;
    }

    //SOCK_LOG("[+] Applying kernel patches...\n");
    for (int i = 0; i < num_patches; i++) {
        cur_patch  = &patches[i];
        patch_addr = kernel_base + cur_patch->offset;
        //SOCK_LOG("  [+] %s (offset=0x%lx, size=0x%x)\n", cur_patch->purpose, cur_patch->offset, cur_patch->size);

        kernel_copyin(cur_patch->data, patch_addr, cur_patch->size);
    }

    return 0;
}

// struct hook *find_hook(hook_id id)
// {
//     uint64_t fw_ver;
//     struct hook *hooks;
//     struct hook *cur_hook;
//     int num_hooks;

//     fw_ver = kernel_get_fw_version() & 0xFFFF0000;

//     switch (fw_ver) {
//     // case 0x1050000:
//     //     hooks = (struct hook *) &g_kernel_hooks_105;
//     //     num_hooks = sizeof(g_kernel_hooks_105) / sizeof(struct hook);
//     //     break;
//     case 0x2500000:
//         hooks = (struct hook *) &g_kernel_hooks_250;
//         num_hooks = sizeof(g_kernel_hooks_250) / sizeof(struct hook);
//         break;
//     default:
//         return NULL;
//     }

//     for (int i = 0; i < num_hooks; i++) {
//         cur_hook = &hooks[i];
//         if (cur_hook->id == id) {
//             return cur_hook;
//         }
//     }

//     return NULL;
// }

// int install_hook(hook_id id, void *func)
// {
//     struct hook *hook_info;
//     uint64_t kernel_cave_addr;
//     uint64_t call_addr;
//     int32_t call_rel32;
//     char dump_buf[0x10];

//     // Find info for this hook
//     hook_info = find_hook(id);
//     if (hook_info == NULL)
//         return -ENOENT;

//     //SOCK_LOG("hook_func_call: found hook (%s)\n", hook_info->purpose);

//     // Copy hook into kernel code cave
//     kernel_cave_addr = ktext(hook_info->func_offset);
//     //SOCK_LOG("hook_func_call: copying hook to 0x%lx\n", kernel_cave_addr);

//     kernel_copyin(func, kernel_cave_addr, 0x1000);
//     kernel_copyout(kernel_cave_addr, &dump_buf, 0x10);
//     DumpHex(&dump_buf, 0x10);

//     // Calculate rel32
//     call_addr = ktext(hook_info->call_offset);
//     call_rel32 = (int32_t) (kernel_cave_addr - call_addr) - 5; // Subtract 5 for call opcodes

//     // Install hook
//     //SOCK_LOG("hook_func_call: installing hook to 0x%lx (rel32=0x%x)\n", call_addr, call_rel32);

//     kernel_copyin(&call_rel32, call_addr + 1, sizeof(call_rel32));
//     return 0;
// }

// int hook_is_development_mode()
// {
//     return 0xc001;
// }

// int apply_test_hook()
// {
//     return install_hook(HOOK_TEST_SYS_IS_DEVELOPMENT_MODE, (void *) &hook_is_development_mode);
// }

// int apply_fself_hooks()
// {
//     if (install_hook(HOOK_SCE_SBL_AUTHMGR_IS_LOADABLE_2, (void *) &OnSceSblAuthMgrIsLoadable2) != 0)
//      if (install_hook(HOOK_SCE_SBL_AUTHMGR_IS_LOADABLE__GET_PATH_ID, (void *) &
//     if (install_hook(HOOK_SCE_SBL_AUTHMGR_SM_LOAD_SELF_BLOCK__MAILBOX, (void *) &
//     if (install_hook(HOOK_SCE_SBL_AUTHMGR_SM_LOAD_SELF_SEGMENT__MAILBOX, (void *) &
//     if (install_hook(HOOK_SCE_SBL_AUTHMGR_VERIFY_HEADER_A, (void *) &
//     if (install_hook(HOOK_SCE_SBL_AUTHMGR_VERIFY_HEADER_B, (void *) &
// }
