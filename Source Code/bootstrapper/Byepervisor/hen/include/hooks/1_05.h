#ifndef HOOKS_1_05_H
#define HOOKS_1_05_H

#include "hook.h"

struct hook g_kernel_hooks_105[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        0x9079ab,
        0x9915f0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_IS_LOADABLE,
        0x2dcda1,
        0x8a6960
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_AUTH_HEADER,
        0x2dd51e,
        0x8a69c0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_RESUME,
        0x2de369,
        0x8a69c0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_SEGMENT,
        0x371295,
        0x563f60
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_BLOCK,
        0x37179f,
        0x563f60
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_MULTIPLE_SELF_BLOCKS,
        0x371d45,
        0x563f60
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_GET_PATHID,
        0x2dcc8d,
        0x5a9c50
    },
    {
        HOOK_FPKG_NPDRM_IOCTL_CMD_5_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x8675fc,
        0x563f60
    },
    {
        HOOK_FPKG_NPDRM_IOCTL_CMD_6_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x8678a1,
        0x563f60
    },
    {
        HOOK_FPKG_PFS_VERIFY_SUPER_BLOCK_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x2d5676,
        0x563f60
    },
    {
        HOOK_FPKG_SCE_SBL_PFS_CLEAR_KEY_1_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x2d509f,
        0x563f60
    },
    {
        HOOK_FPKG_SCE_SBL_PFS_CLEAR_KEY_2_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x2d510b,
        0x563f60
    },
    {
        HOOK_FPKG_SCE_SBL_SERVICE_CRYPT_ASYNC_CALL_CCP_MSG_ENQUEUE,
        0x32e2fd,
        0x729f30
    },
    {
        HOOK_CHECK_DIR_DEPTH,
        0x59C95E,
        0xB0F120
    },
};

#endif // HOOKS_1_05_H
