#ifndef FSELF_H
#define FSELF_H

#define ET_EXEC             0x0002
#define ET_SCE_EXEC         0xFE00
#define ET_SCE_DYNEXEC      0xFE10
#define ET_SCE_DYNAMIC      0xFE18

extern "C" {
    #include <stdint.h>
    #include <sys/types.h>
    #include <sys/param.h>
}

enum SelfFormat {
    NONE,
    ELF,
    SELF
};

struct ElfHeader {
    uint8_t e_ident[0x10];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct SelfHeader {
    uint32_t magic;
    uint32_t unk04;
    union {
        uint32_t raw;
        struct {
            uint8_t content_type;
            uint8_t program_type : 4;
            uint8_t key_revision : 4;
        };
    };
    uint16_t header_size;
    uint16_t metadata_size;
    uint64_t file_size;
    uint16_t entry_num;
    uint16_t flags;
    uint8_t padding[0x4];
};

struct SelfContext {
    SelfFormat format;
    uint32_t authType;
    uint64_t headerSize;
    uint64_t currentSegmentTable;
    uint32_t currentSegmentTableIndex;
    uint32_t unk1C;
    uint64_t unk20;
    uint64_t sizeInPages; //smth like that
    uint32_t serviceId;
    uint32_t unk34;
    union {
        SelfHeader* selfHeader;
        ElfHeader* elfHeader;
    };
    uint8_t mtx[0x20];
};

struct SelfAuthInfo {
    uint64_t cr_paid;
    uint64_t cr_capability[4];
    uint64_t cr_attribute[4];
    uint64_t cr_sharedSecret[8];
};
struct SelfFakeAuthInfo {
    uint64_t size;
    SelfAuthInfo info;
};

struct MailboxVerifyHeaderMessage {
    uint32_t cmd;
    uint32_t res;
    uint64_t headerPa;
    uint64_t headerSize;
    uint32_t unk18;
    uint32_t serviceId;
    uint64_t paid;
};

struct MailboxLoadSelfSegmentMessage {
    uint32_t cmd;
    uint32_t res;
    uint64_t pa;
    uint32_t segmentIndex;
    uint16_t unk14;
    uint16_t unk16;
    uint8_t unk18[0x18];
    uint32_t serviceId;
};

struct MailboxLoadSelfBlockMessage {
    uint32_t cmd;
    uint32_t res;
    uint64_t unk08;
    uint64_t unk10;
    uint64_t unk18;
    uint64_t unk20;
    uint64_t unk28;
    uint32_t unk30;
    uint32_t unk34;
    uint32_t unk38;
    uint32_t segmentIndex;
    uint32_t blockIndex;
    uint32_t serviceId;
    uint8_t digest[0x20];
    uint8_t ext_info[0x8];
    uint16_t unk70;
    uint16_t unk72;
    uint16_t unk74;
};

struct MailboxLoadMultipleSelfBlocksMessage {
    uint32_t cmd;
    uint32_t res;
    uint64_t unk08; //pa to 8 pa's of input
    uint64_t unk10; //pa to 8 pa's of output (right after the above)
    uint64_t unk18; //pa to digests
    uint32_t segmentIndex;
    uint32_t firstBlockIndex;
    uint32_t nBlocks;
    uint32_t serviceId;
};

int sceSblAuthMgrIsLoadable__sceSblAuthMgrCheckSelfIsLoadable_hook(SelfContext* ctx, SelfAuthInfo* parentAuth, int pathid, SelfAuthInfo* selfAuth);
int _sceSblAuthMgrVerifySelfHeader_hook(SelfContext* ctx);
int _sceSblAuthMgrSmLoadSelfSegment_sceSblServiceMailbox(uint64_t handle, MailboxLoadSelfSegmentMessage* input, MailboxLoadSelfSegmentMessage* output);
int _sceSblAuthMgrSmLoadSelfBlock_sceSblServiceMailbox(uint64_t handle, MailboxLoadSelfBlockMessage* input, MailboxLoadSelfBlockMessage* output);
int _sceSblAuthMgrSmLoadMultipleSelfBlocks_sceSblServiceMailbox(uint64_t handle, MailboxLoadMultipleSelfBlocksMessage* input, MailboxLoadMultipleSelfBlocksMessage* output);
int sceSblACMgrGetPathId_hook(const char* path);
void apply_fself_hooks();

#endif // FSELF_H