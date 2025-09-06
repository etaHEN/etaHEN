#include "fself.h"
#include "hook.h"
#include "kdlsym.h"
#include "util.h"

extern "C" {
    #include <sys/types.h>
    #include <sys/param.h>
}

constexpr uint8_t orbisExecAuthInfo[] {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x80, 0x03, 0x00, 0x20,
        0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x00, 0x40,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
        0x00, 0x40, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

constexpr uint8_t orbisPrxAuthInfo[] {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x00, 0x30,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
        0x00, 0x40, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

extern "C" {
    static volatile int enableHook1 = 1;
    static volatile int enableHook2 = 1;
    static volatile int enableHook3 = 1;
    static volatile int enableHook4 = 1;
    static volatile int enableHook5 = 1;
    static volatile int enableHook6 = 1;
}

struct mtx {
    uint8_t dontcare[0x18];
    volatile uintptr_t mtx_lock;
};

SelfContext* getSelfContextByServiceId(uint32_t serviceId) {
    auto ctxTable       = (SelfContext *) kdlsym(KERNEL_SYM_CTXTABLE);
    auto ctxStatus       = (int*) kdlsym(KERNEL_SYM_CTXSTATUS);
    auto ctxTableMtx    = (mtx*) kdlsym(KERNEL_SYM_CTXTABLE_MTX);
    auto __mtx_lock_flags = (void(*)(volatile uintptr_t*, int, const char*, int)) kdlsym(KERNEL_SYM_MTX_LOCK_FLAGS);
    auto __mtx_unlock_flags = (void(*)(volatile uintptr_t*, int, const char*, int)) kdlsym(KERNEL_SYM_MTX_UNLOCK_FLAGS);

    __mtx_lock_flags(&ctxTableMtx->mtx_lock, 0, nullptr, 0);
    for(int i = 0; i < 4; i++) {
        if(ctxStatus[i] != 3 && ctxStatus[i] != 4) { continue; }
        auto ctx = &ctxTable[i];
        if(ctx->unk1C == serviceId) {
            __mtx_unlock_flags(&ctxTableMtx->mtx_lock, 0, nullptr, 0);
            return ctx;
        }
    }
    __mtx_unlock_flags(&ctxTableMtx->mtx_lock, 0, nullptr, 0);
    return nullptr;
}

bool isFakeSelf(SelfContext* ctx) {
    if(ctx) {
        if(ctx->format == SelfFormat::ELF) {
            return true;
        }
        return ctx->selfHeader && ctx->selfHeader->program_type == 0x1;
    }
    return false;
}

int sceSblAuthMgrIsLoadable__sceSblAuthMgrCheckSelfIsLoadable_hook(SelfContext* ctx, SelfAuthInfo* parentAuth, int pathid, SelfAuthInfo* selfAuth) {
    //auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);
    auto _sceSblAuthMgrCheckSelfIsLoadable = (int (*)(SelfContext *ctx, SelfAuthInfo *parentAuthInfo, int pathId, SelfAuthInfo *selfAuthInfo)) kdlsym(KERNEL_SYM_SCESBLAUTHMGRISLOADABLE2);

   // printf("sceSblAuthMgrIsLoadable__sceSblAuthMgrCheckSelfIsLoadable_hook: 0x%016lX 0x%016lX 0x%016lX 0x%016lX\n", ctx, parentAuth, pathid, selfAuth);
    if(enableHook1 && ctx && parentAuth && selfAuth && isFakeSelf(ctx)) {
        uint32_t type;

        if(ctx->format == SelfFormat::ELF) {
            auto hdr = ctx->elfHeader;
            type = hdr->e_type;
            //printf("sceSblAuthMgrIsLoadable__sceSblAuthMgrCheckSelfIsLoadable_hook: is Fake ELF %i\n", type);
        }
        else {
            auto info = reinterpret_cast<SelfFakeAuthInfo*>(reinterpret_cast<uint8_t*>(ctx->selfHeader) + ctx->selfHeader->header_size + ctx->selfHeader->metadata_size - 0x100);
            if(info->size == sizeof(SelfAuthInfo)) {
                //printf("sceSblAuthMgrIsLoadable__sceSblAuthMgrCheckSelfIsLoadable_hook: is Fake SELF with own auth info\n");
                memcpy(selfAuth, &info->info, sizeof(SelfAuthInfo));
                return 0;
            }
            auto hdr = reinterpret_cast<ElfHeader*>(ctx->selfHeader + (ctx->selfHeader->entry_num + 1));
            type = hdr->e_type;
            //printf("sceSblAuthMgrIsLoadable__sceSblAuthMgrCheckSelfIsLoadable_hook: is Fake SELF %i\n", type);
        }

        switch (type) {
            case ET_EXEC:
            case ET_SCE_EXEC:
            case ET_SCE_DYNEXEC: {
                //printf("sceSblAuthMgrIsLoadable__sceSblAuthMgrCheckSelfIsLoadable_hook: is EXEC AUTH\n");
                memcpy(selfAuth, orbisExecAuthInfo, sizeof(SelfAuthInfo));
                break;
            }
            case ET_SCE_DYNAMIC: {
                //printf("sceSblAuthMgrIsLoadable__sceSblAuthMgrCheckSelfIsLoadable_hook: is PRX AUTH\n");
                memcpy(selfAuth, orbisPrxAuthInfo, sizeof(SelfAuthInfo));
                break;
            }
        }
        return 0;
    }
    return _sceSblAuthMgrCheckSelfIsLoadable(ctx, parentAuth, pathid, selfAuth);
}
//condtionally check them
int _sceSblAuthMgrVerifySelfHeader_hook(SelfContext* ctx) {
    //auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);
    auto M_TEMP = (void *) kdlsym(KERNEL_SYM_M_TEMP);
    auto malloc = (void*(*)(unsigned long size, void* type, int flags)) kdlsym(KERNEL_SYM_MALLOC);
    auto free   = (void(*)(void* addr, void* type)) kdlsym(KERNEL_SYM_FREE);
    auto mini_syscore = (SelfHeader *) kdlsym(KERNEL_SYM_MINI_SYSCORE_BIN);
    auto _sceSblAuthMgrVerifySelfHeader = (int(*)(SelfContext *context)) kdlsym(KERNEL_SYM_SCESBLAUTHMGRVERIFYHEADER);

    //printf("_sceSblAuthMgrVerifySelfHeader_hook: 0x%016lX\n", ctx);
    if(!ctx) {
        return -1;
    }
    if(!enableHook2 || !isFakeSelf(ctx)) {
        return _sceSblAuthMgrVerifySelfHeader(ctx);
    }
    //printf("_sceSblAuthMgrVerifySelfHeader_hook: fake self\n");

    auto backup = malloc(0x1000, M_TEMP, 0x102);
    auto ogSize = ctx->headerSize;
    auto ogFormat = ctx->format;
    auto newSize = mini_syscore->header_size + mini_syscore->metadata_size;
    //printf("_sceSblAuthMgrVerifySelfHeader_hook: memcpy: %lx\n", ogSize);
    memcpy(backup, ctx->selfHeader, ogSize);

    //printf("_sceSblAuthMgrVerifySelfHeader_hook: memcpy2: %lx\n", newSize);
    memcpy(ctx->selfHeader, mini_syscore, newSize);
    ctx->headerSize = newSize;
    ctx->format = SelfFormat::SELF;

    ////printf("_sceSblAuthMgrVerifySelfHeader_hook: before _sceSblAuthMgrVerifySelfHeader\n");
    auto res = _sceSblAuthMgrVerifySelfHeader(ctx);
    ////printf("_sceSblAuthMgrVerifySelfHeader_hook: _sceSblAuthMgrVerifySelfHeader %i\n", res);

    ctx->format = ogFormat;
    ctx->headerSize = ogSize;
    ////printf("_sceSblAuthMgrVerifySelfHeader_hook: memcpy3: %lx\n", ogSize);
    memcpy(ctx->selfHeader, backup, ogSize);
    free(backup, M_TEMP);

    return res;
}

int _sceSblAuthMgrSmLoadSelfSegment_sceSblServiceMailbox(uint64_t handle, MailboxLoadSelfSegmentMessage* input, MailboxLoadSelfSegmentMessage* output) {
    //auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);
    auto sceSblServiceMailbox = (int (*)(uint64_t handle, void *input, void *output)) kdlsym(KERNEL_SYM_SCESBLSERVICEMAILBOX);

    //printf("_sceSblAuthMgrSmLoadSelfSegment_sceSblServiceMailbox: 0x%016lX 0x%016lX 0x%016lX\n", handle, input, output);
    //hexdump(input, 0x80, NULL, 0x0);
    if(enableHook3 && input && output) {
        auto ctx = getSelfContextByServiceId(input->serviceId);
        if(ctx && isFakeSelf(ctx)) {
            //printf("_sceSblAuthMgrSmLoadSelfSegment_sceSblServiceMailbox: fake self ctx: %016lX\n", ctx);
            output->res = 0;
            return 0;
        }
    }
    return sceSblServiceMailbox(handle, input, output);
}

int _sceSblAuthMgrSmLoadSelfBlock_sceSblServiceMailbox(uint64_t handle, MailboxLoadSelfBlockMessage* input, MailboxLoadSelfBlockMessage* output) {
    //auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);
    auto sceSblServiceMailbox = (int (*)(uint64_t handle, void *input, void *output)) kdlsym(KERNEL_SYM_SCESBLSERVICEMAILBOX);

    //printf("_sceSblAuthMgrSmLoadSelfBlock_sceSblServiceMailbox: ctx: %016lX input: %016lX output: %016lX\n", handle, input, output);
    //hexdump(input, 0x80, NULL, 0x0);
    if(enableHook4 && input && output) {
        auto ctx = getSelfContextByServiceId(input->serviceId);
        if(ctx && isFakeSelf(ctx)) {
            //printf("_sceSblAuthMgrSmLoadSelfBlock_sceSblServiceMailbox: fake self ctx: %016lX\n", ctx);
            auto destBlock = get_dmap_addr(input->unk08);
            auto srcBlock =  get_dmap_addr(input->unk10);
            auto lenBlock =  input->unk30;
            //printf("_sceSblAuthMgrSmLoadSelfBlock_sceSblServiceMailbox: d %016lX s %016lX l %016lX\n", destBlock, srcBlock, lenBlock);
            memcpy((void *) destBlock, (const void *) srcBlock, lenBlock);
            output->res = 0;
            return 0;
        }
    }
    return sceSblServiceMailbox(handle, input, output);
}

int _sceSblAuthMgrSmLoadMultipleSelfBlocks_sceSblServiceMailbox(uint64_t handle, MailboxLoadMultipleSelfBlocksMessage* input, MailboxLoadMultipleSelfBlocksMessage* output) {
    //auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);
    auto sceSblServiceMailbox = (int (*)(uint64_t handle, void *input, void *output)) kdlsym(KERNEL_SYM_SCESBLSERVICEMAILBOX);

    //printf("_sceSblAuthMgrSmLoadMultipleSelfBlocks_sceSblServiceMailbox: 0x%016lX 0x%016lX 0x%016lX\n", handle, input, output);
    //hexdump(input, 0x80, NULL, 0x0);
    if(enableHook5 && input && output) {
        auto ctx = getSelfContextByServiceId(input->serviceId);
        if(ctx && isFakeSelf(ctx)) {
            //printf("_sceSblAuthMgrSmLoadMultipleSelfBlocks_sceSblServiceMailbox: fake self ctx: %016lX\n", ctx);
            auto inputPa = (uint64_t*)get_dmap_addr(input->unk08);
            auto outputPa = (uint64_t*)get_dmap_addr(input->unk10);

            for(int i = 0; i < 8; i++) {
                auto sPa = inputPa[i];
                auto dPa = outputPa[i];
                if(!sPa || !dPa) {continue;}
                auto src = get_dmap_addr(sPa);
                auto dst = get_dmap_addr(dPa);
                //printf("_sceSblAuthMgrSmLoadMultipleSelfBlocks %016X -> %016X\n", src, dst);
                memcpy((void *) dst, (const void *) src, 0x4000);
            }
            output->res = 0;
            return 0;
        }
    }
    return sceSblServiceMailbox(handle, input, output);
}

int sceSblACMgrGetPathId_hook(const char* path) {
    //auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);
    auto sceSblACMgrGetPathId = (int(*)(const char *path)) kdlsym(KERNEL_SYM_SCESBLACMGRGETPATHID);

    //printf("sceSblACMgrGetPathId_hook: %s\n", path);
    if(enableHook6) {
        constexpr const char *selfDir = "/data/self";
        constexpr const char *hostappDir = "/hostapp";

        if (strstr(path, selfDir) == path) {
            path = path + strlen(selfDir);
            //printf("sceSblACMgrGetPathId_hook: new path %s\n", path);
        } else if (strstr(path, hostappDir) == path) {
            path = path + strlen(hostappDir);
            //printf("sceSblACMgrGetPathId_hook: new path %s\n", path);
        }
    }

    return sceSblACMgrGetPathId(path);
}

void apply_fself_hooks()
{
    //auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);
    auto _sceSblAuthMgrVerifySelfHeader = (int(*)(SelfContext *context)) kdlsym(KERNEL_SYM_SCESBLAUTHMGRVERIFYHEADER);

    //printf("[HEN] [FSELF] sceSblAuthMgrIsLoadable() -> sceSblAuthMgrCheckSelfIsLoadable()\n");
    install_hook(HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_IS_LOADABLE, (void *) &sceSblAuthMgrIsLoadable__sceSblAuthMgrCheckSelfIsLoadable_hook);

    //printf("[HEN] [FSELF] sceSblAuthMgrAuthHeader() -> sceSblAuthMgrVerifySelfHeader()()\n");
    install_hook(HOOK_FSELF_SCE_SBL_AUTHMGR_AUTH_HEADER, (void *) &_sceSblAuthMgrVerifySelfHeader_hook);

    //printf("[HEN] [FSELF] resumeAuthMgr() -> sceSblAuthMgrVerifySelfHeader()\n");
    install_hook(HOOK_FSELF_SCE_SBL_AUTHMGR_RESUME, (void *) &_sceSblAuthMgrVerifySelfHeader);

    //printf("[HEN] [FSELF] sceSblAuthMgrLoadSelfSegment() -> sceSblServiceMailbox()\n");
    install_hook(HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_SEGMENT, (void *) &_sceSblAuthMgrSmLoadSelfSegment_sceSblServiceMailbox);

    //printf("[HEN] [FSELF] sceSblAuthMgrLoadSelfBlock() -> sceSblServiceMailbox()\n");
    install_hook(HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_SELF_BLOCK, (void *) &_sceSblAuthMgrSmLoadSelfBlock_sceSblServiceMailbox);

    //printf("[HEN] [FSELF] sceSblAuthMgrLoadMultipleSelfBlocks() -> sceSblServiceMailbox()\n");
    install_hook(HOOK_FSELF_SCE_SBL_AUTHMGR_LOAD_MULTIPLE_SELF_BLOCKS, (void *) &_sceSblAuthMgrSmLoadMultipleSelfBlocks_sceSblServiceMailbox);

    //printf("[HEN] [FSELF] sceSblAuthMgrIsLoadable() -> sceSblACMgrGetPathId()\n");
    install_hook(HOOK_FSELF_SCE_SBL_AUTHMGR_IS_LOADABLE_CALL_GET_PATHID, (void *) &sceSblACMgrGetPathId_hook);
}
