#ifndef AUTHMGR_H
#define AUTHMGR_H

#include <sys/types.h>
#include "self.h"

#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))

#define SBL_FUNC_AUTHMGR_VERIFY_HEADER      0x01
#define SBL_FUNC_AUTHMGR_LOAD_SELF_SEGMENT  0x02
#define SBL_FUNC_AUTHMGR_FINALIZE           0x05
#define SBL_FUNC_AUTHMGR_LOAD_SELF_BLOCK    0x06

struct self_block_segment
{
    void *data;
    uint64_t size;
    struct sce_self_block_info **extents;
    void **digests;
    uint64_t block_count;
};

struct sbl_authmgr_verify_header
{
    uint32_t function;        // 0x00
    uint32_t res;             // 0x04
    uint64_t self_header_pa;  // 0x08
    uint32_t self_header_size;// 0x10
    uint8_t unk14[0x8];       // 0x14
    uint32_t service_id;      // 0x1C
    uint64_t auth_id;         // 0x20
    uint8_t unk28[0x10];      // 0x28
    uint16_t unk38;           // 0x38
    uint8_t pad[0x80 - 0x3A]; // 0x3A
}; // size: 0x80

struct sbl_authmgr_load_segment
{
    uint32_t function;        // 0x00
    uint32_t res;             // 0x04
    uint64_t chunk_table_pa;  // 0x08
    uint32_t segment_index;   // 0x10
    uint16_t is_block_table;  // 0x14
    uint16_t unk16;           // 0x16
    uint8_t unk18[0x18];      // 0x18
    uint32_t service_id;      // 0x30
    uint8_t pad[0x80 - 0x34]; // 0x34
}; // size: 0x80

struct sbl_authmgr_load_block
{
    uint32_t function;        // 0x00
    uint32_t res;             // 0x04
    uint64_t out_pa;          // 0x08
    uint64_t in_pa;           // 0x10
    uint64_t unk18;           // 0x18
    uint64_t unk20;           // 0x20
    uint64_t unk28;           // 0x28
    uint32_t aligned_size;    // 0x30
    uint32_t size;            // 0x34
    uint32_t unk38;           // 0x38
    uint32_t segment_index;   // 0x3C
    uint32_t block_index;     // 0x40
    uint32_t service_id;      // 0x44
    uint8_t digest[0x20];     // 0x48
    uint8_t ext_info[0x8];    // 0x68
    uint16_t is_compressed;   // 0x70
    uint16_t unk72;           // 0x72
    uint16_t is_plain_elf;    // 0x74
    uint8_t pad[0x80 - 0x76]; // 0x76
}; // size: 0x80

struct sbl_authmgr_finalize_ctx
{
    uint32_t function;        // 0x00
    uint32_t res;             // 0x04
    uint32_t context_id;      // 0x08
    uint8_t pad[0x80 - 0x0C]; // 0x0C
}; // size: 0x80

struct sbl_chunk_table_header
{
    uint64_t first_pa;        // 0x00
    uint64_t data_size;       // 0x08
    uint64_t used_entries;    // 0x10
    uint64_t unk18;           // 0x18
}; // size: 0x20

struct sbl_chunk_table_entry
{
    uint64_t pa;              // 0x00
    uint64_t size;            // 0x08
}; // size: 0x10

// Finalizes a context and allows a fresh SELF to be loaded
int _sceSblAuthMgrSmFinalize(int sock, int authmgr_handle, int context_id);

// Verifies SELF header and initializes context for future operations
int _sceSblAuthMgrVerifyHeader(int sock, int authmgr_handle, uint64_t header_pa, uint64_t header_len);

// Decrypts a SELF segment
int _sceSblAuthMgrSmLoadSelfSegment(int sock, int authmgr_handle, int service_id, uint64_t chunk_table_pa, uint32_t segment_index);

// Decrypts a SELF block
int _sceSblAuthMgrSmLoadSelfBlock(
        int sock,
        int authmgr_handle,
        int service_id,
        uint64_t in_pa,
        uint64_t out_pa,
        struct sce_self_segment_header *segment,
        int segment_idx,
        struct self_block_segment *block_segment,
        int block_idx);

#endif // AUTHMGR_H