#include <errno.h>
#include <stdint.h>
#include <sys/types.h>

#include "hook.h"
#include "kdlsym.h"

#include "hooks/1_00.h"
#include "hooks/1_01.h"
#include "hooks/1_02.h"
#include "hooks/1_05.h"
#include "hooks/1_10.h"
#include "hooks/1_11.h"
#include "hooks/1_12.h"
#include "hooks/1_13.h"
#include "hooks/1_14.h"
#include "hooks/2_00.h"
#include "hooks/2_20.h"
#include "hooks/2_25.h"
#include "hooks/2_26.h"
#include "hooks/2_30.h"
#include "hooks/2_50.h"

struct hook *find_hook(hook_id id)
{
    uint64_t fw_ver;
    struct hook *hooks;
    struct hook *cur_hook;
    int num_hooks;

    fw_ver = get_fw_version();
    auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);

    switch (fw_ver) {
    case 0x1000000:
         hooks = (struct hook *) &g_kernel_hooks_100;
         num_hooks = sizeof(g_kernel_hooks_100) / sizeof(struct hook);
         break;
    case 0x1010000:
    case 0x1020000:
         hooks = (struct hook *) &g_kernel_hooks_102;
         num_hooks = sizeof(g_kernel_hooks_102) / sizeof(struct hook);
         break;
    case 0x1050000:
         hooks = (struct hook *) &g_kernel_hooks_105;
         num_hooks = sizeof(g_kernel_hooks_105) / sizeof(struct hook);
         break;
    case 0x1100000:
        hooks = (struct hook *) &g_kernel_hooks_110;
        num_hooks = sizeof(g_kernel_hooks_110) / sizeof(struct hook);
        break;
    case 0x1110000:
        hooks = (struct hook *) &g_kernel_hooks_111;
        num_hooks = sizeof(g_kernel_hooks_111) / sizeof(struct hook);
        break;
    case 0x1120000:
        hooks = (struct hook *) &g_kernel_hooks_112;
        num_hooks = sizeof(g_kernel_hooks_112) / sizeof(struct hook);
        break;
    case 0x1130000:
        hooks = (struct hook *) &g_kernel_hooks_113;
        num_hooks = sizeof(g_kernel_hooks_113) / sizeof(struct hook);
        break;
    case 0x1140000:
        hooks = (struct hook *) &g_kernel_hooks_114;
        num_hooks = sizeof(g_kernel_hooks_114) / sizeof(struct hook);
        break;
    case 0x2000000:
        hooks = (struct hook *) &g_kernel_hooks_200;
        num_hooks = sizeof(g_kernel_hooks_200) / sizeof(struct hook);
        break;
    case 0x2200000:
        hooks = (struct hook *) &g_kernel_hooks_220;
        num_hooks = sizeof(g_kernel_hooks_220) / sizeof(struct hook);
        break;
    case 0x2250000:
        hooks = (struct hook *) &g_kernel_hooks_225;
        num_hooks = sizeof(g_kernel_hooks_225) / sizeof(struct hook);
        break;
    case 0x2260000:
        hooks = (struct hook *) &g_kernel_hooks_226;
        num_hooks = sizeof(g_kernel_hooks_226) / sizeof(struct hook);
        break;
    case 0x2300000:
        hooks = (struct hook *) &g_kernel_hooks_230;
        num_hooks = sizeof(g_kernel_hooks_230) / sizeof(struct hook);
        break;
    case 0x2500000:
    case 0x2700000:
        hooks = (struct hook *) &g_kernel_hooks_250;
        num_hooks = sizeof(g_kernel_hooks_250) / sizeof(struct hook);
        break;
    default:
        return 0;
    }

    printf("find_hook: num_hooks = %d\n", num_hooks);

    for (int i = 0; i < num_hooks; i++) {
        cur_hook = &hooks[i];
        printf("hook_func_call: hook->id = %d\n", cur_hook->id);
        if (cur_hook->id == id) {
            return cur_hook;
        }
    }

    return 0;
}

int install_raw_hook(uint64_t call_addr, void *func)
{
    uint64_t call_install;
    int32_t call_rel32;

    auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);

    printf("install_raw_hook: call_addr = 0x%llx, func = %p\n", call_addr, func);

    // Calculate rel32
    call_rel32  = (int32_t) ((uint64_t) (func) - call_addr) - 5; // Subtract 5 for call opcodes

    printf("install_raw_hook: call_rel32=0x%x\n", call_rel32);

    // Install hook
    printf("hook_func_call: installing hook to 0x%lx (rel32=0x%x)\n", call_addr, call_rel32);

    call_install = call_addr + 1;
    *(uint32_t *) (call_install) = call_rel32;
    return 0;
}

int install_hook(hook_id id, void *func)
{
    struct hook *hook_info;
    uint64_t call_addr;
    uint64_t call_install;
    int32_t call_rel32;

    auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);
    printf("hook_func_call: hook id = %d\n", id);

    // Find info for this hook
    hook_info = find_hook(id);
    if (hook_info == 0)
        return -ENOENT;

    printf("hook_func_call: found hook\n");

    // Calculate rel32
    call_addr   = ktext(hook_info->call_offset);
    call_rel32  = (int32_t) ((uint64_t) (func) - call_addr) - 5; // Subtract 5 for call opcodes

    printf("hook_func_call: call_addr=0x%llx (call_rel32=0x%x)\n", call_addr, call_rel32);

    // Install hook
    printf("hook_func_call: installing hook to 0x%lx (rel32=0x%x)\n", call_addr, call_rel32);

    call_install = call_addr + 1;
    *(uint32_t *) (call_install) = call_rel32;
    return 0;
}

void reset_hook(hook_id id)
{
    struct hook *hook_info;
    uint64_t call_addr;
    uint64_t call_install;
    int32_t call_rel32;
    void *func;

    auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);
    printf("reset_hook: hook id = %d\n", id);

    // Find info for this hook
    hook_info = find_hook(id);
    if (hook_info == 0)
        return;

    printf("reset_hook: found hook\n");

    // Calculate rel32
    func        = (void *) ktext(hook_info->orig_func_offset);
    call_addr   = ktext(hook_info->call_offset);
    call_rel32  = (int32_t) ((uint64_t) (func) - call_addr) - 5; // Subtract 5 for call opcodes

    printf("reset_hook: call_addr=0x%llx (call_rel32=0x%x)\n", call_addr, call_rel32);

    printf("reset_hook: orig func_offset=0x%llx, call_addr=0=%llx\n", hook_info->orig_func_offset, hook_info->call_offset);

    // Install hook
    printf("reset_hook: installing hook to 0x%lx (rel32=0x%x)\n", call_addr, call_rel32);

    call_install = call_addr + 1;
    *(uint32_t *) (call_install) = call_rel32;
}

int hook_is_development_mode()
{
    return 0xc001;
}

int apply_test_hook()
{
    auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);

    printf("sys_is_development_mode() -> isDevelopmentMode()\n");
    return install_hook(HOOK_TEST_SYS_IS_DEVELOPMENT_MODE, (void *) &hook_is_development_mode);
}
