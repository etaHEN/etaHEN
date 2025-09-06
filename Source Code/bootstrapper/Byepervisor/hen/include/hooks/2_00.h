#ifndef HOOKS_2_00_H
#define HOOKS_2_00_H

#include "hook.h"

struct hook g_kernel_hooks_200[] = {
    {
        HOOK_TEST_SYS_IS_DEVELOPMENT_MODE,
        0x92976b,
        0x9b7840
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_IS_LOADABLE,
        0x2915a1,
        0x8c2da0
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_AUTH_HEADER,
        0x291d29,
        0x8c2e00
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_RESUME,
        0x292b4b,
        0x8c2e00
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_SEGMENT,
        0x32c915,
        0x534060
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_BLOCK,
        0x32cdff,
        0x534060
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_MULTIPLE_SELF_BLOCKS,
        0x32d3a5,
        0x534060
    },
    {
        HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_GET_PATHID,
        0x29148d,
        0x580890
    },
    {
        HOOK_FPKG_NPDRM_IOCTL_CMD_5_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x87d60c,
        0x534060
    },
    {
        HOOK_FPKG_NPDRM_IOCTL_CMD_6_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x87d8b1,
        0x534060
    },
    {
        HOOK_FPKG_PFS_VERIFY_SUPER_BLOCK_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x28a116,
        0x534060
    },
    {
        HOOK_FPKG_SCE_SBL_PFS_CLEAR_KEY_1_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x289b3f,
        0x534060
    },
    {
        HOOK_FPKG_SCE_SBL_PFS_CLEAR_KEY_2_CALL_SCE_SBL_SERVICE_MAILBOX,
        0x289bab,
        0x534060
    },
    {
        HOOK_FPKG_SCE_SBL_SERVICE_CRYPT_ASYNC_CALL_CCP_MSG_ENQUEUE,
        0x2e587d,
        0x725e40
    },
    {
        HOOK_CHECK_DIR_DEPTH,
        0x5723DE,
        0xB4C940
    },
};

#endif // HOOKS_2_00_H
