#ifndef HOOKS_2_30_H
#define HOOKS_2_30_H

#include "hook.h"

struct hook g_kernel_hooks_230[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        0x929fdb,
        0x9b80b0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_IS_LOADABLE,
        0x2912c1,
        0x8c35f0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_AUTH_HEADER,
        0x291a49,
        0x8c3650
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_RESUME,
        0x29286b,
        0x8c3650
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_SEGMENT,
        0x32c635,
        0x5340c0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_BLOCK,
        0x32cb1f,
        0x5340c0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_MULTIPLE_SELF_BLOCKS,
        0x32d0c5,
        0x5340c0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_GET_PATHID,
        0x2911ad,
        0x580d80
    },
    {
        HOOK_FPKG_NPDRM_IOCTL_CMD_5_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x87de5c,
        0x5340c0
    },
    {
        HOOK_FPKG_NPDRM_IOCTL_CMD_6_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x87e101,
        0x5340c0
    },
    {
        HOOK_FPKG_PFS_VERIFY_SUPER_BLOCK_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x289e36,
        0x5340c0
    },
    {
        HOOK_FPKG_SCE_SBL_PFS_CLEAR_KEY_1_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x28985f,
        0x5340c0
    },
    {
        HOOK_FPKG_SCE_SBL_PFS_CLEAR_KEY_2_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x2898cb,
        0x5340c0
    },
    {
        HOOK_FPKG_SCE_SBL_SERVICE_CRYPT_ASYNC_CALL_CCP_MSG_ENQUEUE,
        0x2e559d,
        0x726680
    },
    {
        HOOK_CHECK_DIR_DEPTH,
        0x5728CE,
        0xB4D890

    },
    {
        HOOK_DEVACT_IOCTL,
        0x2679D8,
        0x93BA40         //devact_ioctl,
    }
};

#endif // HOOKS_2_30_H
