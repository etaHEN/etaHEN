#ifndef HOOKS_2_50_H
#define HOOKS_2_50_H

#include "hook.h"

struct hook g_kernel_hooks_250[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        0x92A1EB,
        0x9B8350
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_IS_LOADABLE,
        0x2913C1,
        0x8C3800
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_AUTH_HEADER,
        0x291B49,
        0x8C3860
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_RESUME,
        0x29296B,
        0x8C3860
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_SEGMENT,
        0x32C735,
        0x534220
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_BLOCK,
        0x32CC1F,
        0x534220
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_MULTIPLE_SELF_BLOCKS,
        0x32D1C5,
        0x534220
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_GET_PATHID,
        0x2912AD,
        0x580EE0
    },
    {
        HOOK_FPKG_NPDRM_IOCTL_CMD_5_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x87E06C,
        0x534220
    },
    {
        HOOK_FPKG_NPDRM_IOCTL_CMD_6_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x87E311,
        0x534220
    },
    {
        HOOK_FPKG_PFS_VERIFY_SUPER_BLOCK_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x289F36,
        0x534220
    },
    {
        HOOK_FPKG_SCE_SBL_PFS_CLEAR_KEY_1_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x28995F,
        0x534220
    },
    {
        HOOK_FPKG_SCE_SBL_PFS_CLEAR_KEY_2_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x2899CB,
        0x534220
    },
    {
        HOOK_FPKG_SCE_SBL_SERVICE_CRYPT_ASYNC_CALL_CCP_MSG_ENQUEUE,
        0x2E569D,
        0x726700
    },
    {
        HOOK_CHECK_DIR_DEPTH,
        0x572A2E,
        0xB4DB30

    },

  {
        HOOK_DEVACT_IOCTL,
        0x268D28,
        0x93BCC0
    }
};

#endif // HOOKS_2_50_H