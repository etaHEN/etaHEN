#ifndef HOOKS_2_20_H
#define HOOKS_2_20_H

#include "hook.h"

struct hook g_kernel_hooks_220[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        0x929c2b,
        0x9b7d00
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_IS_LOADABLE,
        0x2915e1,
        0x8c3250
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_AUTH_HEADER,
        0x291d69,
        0x8c32a0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_RESUME,
        0x292b8b,
        0x8c32a0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_SEGMENT,
        0x32c955,
        0x5340b0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_BLOCK,
        0x32ce3f,
        0x5340b0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_MULTIPLE_SELF_BLOCKS,
        0x32d3e5,
        0x5340b0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_GET_PATHID,
        0x2914cd,
        0x580a00
    },
    {
        HOOK_FPKG_NPDRM_IOCTL_CMD_5_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x87daac,
        0x5340b0
    },
    {
        HOOK_FPKG_NPDRM_IOCTL_CMD_6_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x87dd51,
        0x5340b0
    },
    {
        HOOK_FPKG_PFS_VERIFY_SUPER_BLOCK_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x28a156,
        0x5340b0
    },
    {
        HOOK_FPKG_SCE_SBL_PFS_CLEAR_KEY_1_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x289b7f,
        0x5340b0
    },
    {
        HOOK_FPKG_SCE_SBL_PFS_CLEAR_KEY_2_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x289beb,
        0x5340b0
    },
    {
        HOOK_FPKG_SCE_SBL_SERVICE_CRYPT_ASYNC_CALL_CCP_MSG_ENQUEUE,
        0x2e58bd,
        0x726300
    },
    {
        HOOK_CHECK_DIR_DEPTH,
        0x57254E,
        0xB4D2B0
    },
};

#endif // HOOKS_2_20_H