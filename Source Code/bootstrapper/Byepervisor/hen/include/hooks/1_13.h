#ifndef HOOKS_1_13_H
#define HOOKS_1_13_H

#include "hook.h"

struct hook g_kernel_hooks_113[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        0x907c2b,
        0x991880
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_IS_LOADABLE,
        0x2dcde1,
        0x8a6b70
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_AUTH_HEADER,
        0x2dd55e,
        0x8a6bd0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_RESUME,
        0x2de3a9,
        0x8a6bd0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_SEGMENT,
        0x371305,
        0x564030
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_BLOCK,
        0x37180f,
        0x564030
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_MULTIPLE_SELF_BLOCKS,
        0x371db5,
        0x564030
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_GET_PATHID,
        0x2dcccd,
        0x5a9d20
    },
    {
        HOOK_FPKG_NPDRM_IOCTL_CMD_5_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x86780c,
        0x564030
    },
    {
        HOOK_FPKG_NPDRM_IOCTL_CMD_6_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x867ab1,
        0x564030
    },
    {
        HOOK_FPKG_PFS_VERIFY_SUPER_BLOCK_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x2d56b6,
        0x564030
    },
    {
        HOOK_FPKG_SCE_SBL_PFS_CLEAR_KEY_1_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x2d50df,
        0x564030
    },
    {
        HOOK_FPKG_SCE_SBL_PFS_CLEAR_KEY_2_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x2d514b,
        0x564030
    },
    {
        HOOK_FPKG_SCE_SBL_SERVICE_CRYPT_ASYNC_CALL_CCP_MSG_ENQUEUE,
        0x32e33d,
        0x72a130
    },
    {
        HOOK_CHECK_DIR_DEPTH,
        0x59CA2E,
        0xB0F330
    },
};

#endif // HOOKS_1_13_H
