#ifndef HOOKS_1_02_H
#define HOOKS_1_02_H

#include "hook.h"

struct hook g_kernel_hooks_102[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        0x9071cb,
        0x990db0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_IS_LOADABLE,
        0x2dcd71,
        0x8a5850
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_AUTH_HEADER,
        0x2dd4ee,
        0x8a58b0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_RESUME,
        0x2de339,
        0x8a58b0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_SEGMENT,
        0x371075,
        0x563a80
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_BLOCK,
        0x37157f,
        0x563a80
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_MULTIPLE_SELF_BLOCKS,
        0x371b25,
        0x563a80
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_GET_PATHID,
        0x2dcc5d,
        0x5a9770
    },
    {
        HOOK_FPKG_NPDRM_IOCTL_CMD_5_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x8664ec,
        0x563a80
    },
    {
        HOOK_FPKG_NPDRM_IOCTL_CMD_6_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x866791,
        0x563a80
    },
    {
        HOOK_FPKG_PFS_VERIFY_SUPER_BLOCK_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x2d5646,
        0x563a80
    },
    {
        HOOK_FPKG_SCE_SBL_PFS_CLEAR_KEY_1_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x2d506f,
        0x563a80
    },
    {
        HOOK_FPKG_SCE_SBL_PFS_CLEAR_KEY_2_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x2d50db,
        0x563a80
    },
    {
        HOOK_FPKG_SCE_SBL_SERVICE_CRYPT_ASYNC_CALL_CCP_MSG_ENQUEUE,
        0x32e0dd,
        0x7299c0
    },
    {
        HOOK_CHECK_DIR_DEPTH,
        0x59C47E,
        0xB0E760
    },
};

#endif // HOOKS_1_02_H
