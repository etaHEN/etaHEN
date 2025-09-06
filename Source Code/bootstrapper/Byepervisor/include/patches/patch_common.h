#ifndef PATCH_COMMON_H
#define PATCH_COMMON_H

struct patch
{
    const char *purpose;
    uint64_t offset;
    const char *data;
    int size;
};

enum hook_id
{
    HOOK_TEST_SYS_IS_DEVELOPMENT_MODE = 0,
    HOOK_SCE_SBL_AUTHMGR_IS_LOADABLE_2,
    HOOK_SCE_SBL_AUTHMGR_IS_LOADABLE__GET_PATH_ID,
    HOOK_SCE_SBL_AUTHMGR_SM_LOAD_SELF_BLOCK__MAILBOX,
    HOOK_SCE_SBL_AUTHMGR_SM_LOAD_SELF_SEGMENT__MAILBOX,
    HOOK_SCE_SBL_AUTHMGR_VERIFY_HEADER_A,
    HOOK_SCE_SBL_AUTHMGR_VERIFY_HEADER_B
};

struct hook
{
    enum hook_id id;
    const char *purpose;
    uint64_t func_offset;
    uint64_t call_offset;
};

#endif // PATCH_COMMON_H