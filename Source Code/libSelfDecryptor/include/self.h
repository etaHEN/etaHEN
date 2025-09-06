#pragma once
#ifndef SELF_H
#define SELF_H

#include <sys/types.h>

#define PAGE_SHIFT                          0x0000000C

#define SELF_ORBIS_MAGIC        0x1D3D154F
#define SELF_PROSPERO_MAGIC     0xEEF51454

#define SELF_SEGMENT_ID(x)                  (x->flags >> 20)
#define SELF_SEGMENT_IS_ENCRYPTED(x)        ((x->flags & (1 << 1)) != 0)
#define SELF_SEGMENT_IS_SIGNED(x)           ((x->flags & (1 << 2)) != 0)
#define SELF_SEGMENT_IS_COMPRESSED(x)       ((x->flags & (1 << 3)) != 0)
#define SELF_SEGMENT_HAS_BLOCKS(x)          ((x->flags & (1 << 11)) != 0)
#define SELF_SEGMENT_HAS_DIGESTS(x)         ((x->flags & (1 << 16)) != 0)
#define SELF_SEGMENT_HAS_BLOCKINFO(x)       ((x->flags & (1 << 17)) != 0)
#define SELF_SEGMENT_BLOCK_SIZE(x)          (1 << (((x->flags >> 12) & 0xF) + PAGE_SHIFT))

struct sce_self_header
{
    uint32_t magic;             // 0x00
    uint8_t version;            // 0x04
    uint8_t mode;               // 0x05
    uint8_t endian;             // 0x06
    uint8_t attributes;         // 0x07
    uint32_t key_type;          // 0x08
    uint16_t header_size;       // 0x0C
    uint16_t metadata_size;     // 0x0E
    uint64_t file_size;         // 0x10
    uint16_t segment_count;     // 0x18
    uint16_t flags;             // 0x1A
    char pad_2[0x4];            // 0x1C
}; // Size: 0x20

struct sce_self_segment_header {
    uint64_t flags;             // 0x00
    uint64_t offset;            // 0x08
    uint64_t compressed_size;   // 0x10
    uint64_t uncompressed_size; // 0x18
}; // Size: 0x20

struct sce_self_block_info {
    uint32_t offset;            // 0x00
    uint32_t len;               // 0x04
}; // Size: 0x08

#endif // SELF_H