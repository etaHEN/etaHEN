#ifndef FPKG_H
#define FPKG_H

#include <stdint.h>

struct NpDrmCmd5 {
    uint32_t cmd;
    uint32_t res;
    uint64_t rif_pa;
    uint32_t unk10;
};

struct NpDrmCmd6 {
    uint32_t cmd;
    uint32_t res;
    uint64_t rif_pa;
    uint8_t unk10[0x10];
    uint8_t unk20[0x10];
    uint32_t unk30; // 0 or 1
};

struct ClearKey {
    uint32_t cmd;
    uint32_t res;
    uint64_t keyHandle;
};

struct Rif {
    uint32_t magic;
    uint16_t version;
    uint16_t unk06;
    uint64_t psnid;
    uint64_t startTimestamp;
    uint64_t endTimestamp;
    uint8_t contentId[0x30];
    uint16_t type;
    uint16_t drmType;
    uint16_t contentType;
    uint16_t skuFlag;
    uint64_t extraFlags;
    uint32_t unk60;
    uint32_t unk64;
    uint32_t unk68;
    uint32_t unk6C;
    uint32_t unk70;
    uint32_t unk74;
    uint32_t unk78;
    uint32_t unk7C;
    uint8_t unk80[0x10];
    uint8_t unk90[0x1B0];
    uint8_t discKey[0x20];
    uint8_t rifIv[0x10];
    uint8_t rifSecret[0x90];
    uint8_t rifSignature[0x100];
};

struct RifOutput {
    /* 0x00 */ uint32_t version;
    /* 0x04 */ uint32_t unk04;
    /* 0x08 */ uint64_t psnid;
    /* 0x10 */ uint64_t startTimestamp;
    /* 0x18 */ uint64_t endTimestamp;
    /* 0x20 */ uint64_t extraFlags;
    /* 0x28 */ uint32_t type;
    /* 0x2C */ uint32_t contentType;
    /* 0x30 */ uint32_t skuFlag;
    /* 0x34 */ uint32_t unk34;
    /* 0x38 */ uint32_t unk38;
    /* 0x3C */ uint32_t unk3C; //not set
    /* 0x40 */ uint32_t unk40; //not set
    /* 0x44 */ uint32_t unk44; //not set
    /* 0x48 */ uint8_t contentId[0x30];
    /* 0x78 */ uint8_t rifIv[0x10];
    /* 0x88 */ uint32_t unk88;
    /* 0x8C */ uint32_t unk8C;
    /* 0x90 */ uint32_t unk90;
    /* 0x94 */ uint32_t unk94;
    /* 0x98 */ uint8_t unk98[0x10];
};

struct RifCmd5MemoryLayout {
    Rif rif;
    RifOutput output;
};

struct PfsmgrCmd11 {
    uint32_t cmd;
    uint32_t res;
    uint32_t keyHandle0;
    uint32_t keyHandle1; //also pubkey_ver
    uint64_t tablePa;
    uint64_t headerPa;
    uint64_t headerCapacity;
    uint64_t unk28;
    uint64_t unk30;
    uint64_t unk38;
    uint64_t unk40;
    uint64_t unk48;
    uint32_t unk50;
    uint8_t contentId[0x24];
};

struct sbl_chunk_table_entry
{
    uint64_t pa;
    uint64_t size;
};
struct sbl_chunk_table_header
{
    uint64_t first_pa;
    uint64_t data_size;
    uint64_t used_entries;
    uint64_t unk18;
    sbl_chunk_table_entry entries[];
};

struct RsaBuffer {
    uint8_t* ptr;
    uint32_t size;
};

struct RsaKey {
    const uint8_t _pad00[0x20];
    const uint8_t* p;
    const uint8_t* q;
    const uint8_t* dmp1;
    const uint8_t* dmq1;
    const uint8_t* iqmp;
};

void apply_fpkg_hooks();

#endif /* FPKG_H */