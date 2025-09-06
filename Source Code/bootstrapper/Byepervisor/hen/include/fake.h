/**
 * Credits:
 *      Inital Structures: flat_z
 *      Structs and asserts: mira-vnext/kiwidog
*/
#ifndef FAKE_H
#define FAKE_H

#include <stdint.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>

#include <sys/stdint.h>
#include <sys/elf.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>

/**
 * @brief This is just here to prevent errors, too lazy to remove logging
 * 
 */
#define WriteLog(x, y, ...)

/**
 * C++ to C fixes
*/
#define false 0
#define true 1

/**
 * Fake Self
*/
#pragma region FAKE SELF

// Forward declarations
struct self_auth_info_t;
struct self_context_t;
struct self_ex_info_t;
struct self_header_t;
enum self_format_t : int;
struct self_fake_auth_info_t;
struct self_entry_t;

/**
 * SELF authentication information
*/
typedef struct self_auth_info_t 
{
    uint64_t paid;
    uint64_t caps[4];
    uint64_t attrs[4];
    uint8_t unk[0x40];
}self_auth_info_t, SelfAuthInfo;

/**
 * SELF kernel context
*/
typedef struct self_context_t 
{
    uint32_t format;
    uint32_t elf_auth_type;
    uint32_t total_header_size;
    uint32_t unk_0C;
    void *segment;
    uint32_t unk_18;
    uint32_t ctx_id;
    uint64_t svc_id;
    uint64_t unk_28;
    uint32_t buf_id;
    uint32_t unk_34;
    struct self_header_t *header;
    uint8_t mtx_struct[0x20];
} self_context_t, SelfContext;

/**
 * SELF extra information
*/
typedef struct self_ex_info_t
{
    uint64_t paid;
    uint64_t ptype;
    uint64_t app_version;
    uint64_t firmware_version;
    uint8_t digest[0x20];
} self_ex_info_t, SelfExInfo;

/**
 * SELF entry
*/
typedef struct self_entry_t 
{
    uint32_t props;
    uint32_t reserved;
    uint64_t offset;
    uint64_t filesz;
    uint64_t memsz;
} self_entry_t, SelfEntry;

/**
 * SELF header
*/
typedef struct self_header_t 
{
    uint32_t magic;
    uint8_t version;
    uint8_t mode;
    uint8_t endian;
    uint8_t attr;
    uint32_t key_type;
    uint16_t header_size;
    uint16_t meta_size;
    uint64_t file_size;
    uint16_t num_entries;
    uint16_t flags;
    uint32_t reserved;
    struct self_entry_t entries[0];
} self_header_t, SelfHeader;

/**
 * SELF fake authentication information
*/
typedef struct self_fake_auth_info_t
{
    uint64_t size;
    SelfAuthInfo info;
} self_fake_auth_info_t, SelfFakeAuthInfo;

/**
 * SELF formats
*/
enum self_format_t : int
{
    /**
     * No Specified format
    */
    SF_None,

    /**
     * RAW elf format
    */
    SF_Elf,

    /**
     * SELF format
    */
    SF_Self,

    /**
     * Count of formats
    */
    SF_Count
};

enum
{
    LoadSelfSegment = 2,
    LoadSelfBlock = 6,

    SelfMagic = 0x1D3D154F,
    ElfMagic = 0x464C457F,

    SelfPtypeFake = 1,

    AuthInfoSize = 136,
};

struct mailbox_authmgr_verify_header_msg {
    uint32_t cmd;
    uint32_t res;
    uint64_t headerPa;
    uint64_t headerSize;
    uint32_t unk18;
    uint32_t serviceId;
    uint64_t paid;
};

struct mailbox_authmgr_load_self_segment_msg {
    uint32_t cmd;
    uint32_t res;
    uint64_t pa;
    uint32_t segmentIndex;
    uint16_t unk14;
    uint16_t unk16;
    uint8_t unk18[0x18];
    uint32_t serviceId;
};

struct mailbox_authmgr_load_self_block_msg {
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

struct mailbox_authmgr_load_multiple_self_blocks_msg {
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

#pragma endregion

#endif /* FAKE_H */