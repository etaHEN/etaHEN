#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include <ps5/kernel.h>

#include "sbl.h"
#include "self.h"
#include "authmgr.h"

int _sceSblAuthMgrSmFinalize(int sock, int authmgr_handle, int context_id)
{
    struct sbl_msg_header msg = {};
    struct sbl_authmgr_finalize_ctx finalize = {};

    msg.cmd           = 6;
    msg.query_len     = 0x80;
    msg.recv_len      = 0x80;
    msg.message_id    = 0;
    msg.to_ret        = authmgr_handle;

    finalize.function = SBL_FUNC_AUTHMGR_FINALIZE;
    finalize.context_id = 0;

    return sceSblServiceRequest(sock, &msg, &finalize, &finalize);
}

int _sceSblAuthMgrVerifyHeader(int sock, int authmgr_handle, uint64_t header_pa, uint64_t header_len)
{
    int err;
    struct sbl_msg_header msg = {};
    struct sbl_authmgr_verify_header verify = {};

    msg.cmd                 = 6;
    msg.query_len           = 0x80;
    msg.recv_len            = 0x80;
    msg.message_id          = 0;
    msg.to_ret              = authmgr_handle;

    verify.function         = SBL_FUNC_AUTHMGR_VERIFY_HEADER;
    verify.self_header_pa   = header_pa;
    verify.self_header_size = header_len;
    verify.auth_id          = 0;

    err = sceSblServiceRequest(sock, &msg, &verify, &verify);
    if (err != 0)
        return err;

    return (int) verify.service_id;
}

int _sceSblAuthMgrSmLoadSelfSegment(int sock, int authmgr_handle, int service_id, uint64_t chunk_table_pa, uint32_t segment_index)
{
    struct sbl_msg_header msg = {};
    struct sbl_authmgr_load_segment load = {};

    msg.cmd                 = 6;
    msg.query_len           = 0x80;
    msg.recv_len            = 0x80;
    msg.message_id          = 0;
    msg.to_ret              = authmgr_handle;

    load.function           = SBL_FUNC_AUTHMGR_LOAD_SELF_SEGMENT;
    load.chunk_table_pa     = chunk_table_pa;
    load.segment_index      = segment_index;
    load.is_block_table     = 0x01;
    load.service_id         = service_id;

    return sceSblServiceRequest(sock, &msg, &load, &load);
}

int _sceSblAuthMgrSmLoadSelfBlock(
        int sock,
        int authmgr_handle,
        int service_id,
        uint64_t in_pa,
        uint64_t out_pa,
        struct sce_self_segment_header *segment,
        int segment_idx,
        struct self_block_segment *block_segment,
        int block_idx)
{
    struct sbl_msg_header msg = {};
    struct sbl_authmgr_load_block load = {};
    uint64_t size_one;
    uint64_t size_two;

    msg.cmd                 = 6;
    msg.query_len           = 0x80;
    msg.recv_len            = 0x80;
    msg.message_id          = 0;
    msg.to_ret              = authmgr_handle;

    memcpy(&load.digest, block_segment->digests[block_idx], 0x20);
    memcpy(&load.ext_info, block_segment->extents[block_idx], sizeof(struct sce_self_block_info));

    load.function           = SBL_FUNC_AUTHMGR_LOAD_SELF_BLOCK;
    load.out_pa             = out_pa;
    load.in_pa              = in_pa;
    load.unk18              = in_pa;

    if (SELF_SEGMENT_IS_COMPRESSED(segment)) {
        size_one = block_segment->extents[block_idx]->len & ~0xF;
        size_two = size_one - (block_segment->extents[block_idx]->len & 0xF);
    } else {
        // size_one = size_two = SELF_SEGMENT_BLOCK_SIZE(segment);
        // if (segment->uncompressed_size - SELF_SEGMENT_BLOCK_SIZE(segment) < SELF_SEGMENT_BLOCK_SIZE(segment)) {
        //     size_one = size_two = segment->uncompressed_size - SELF_SEGMENT_BLOCK_SIZE(segment);
        // }

        size_one = size_two = block_segment->extents[block_idx]->len;
    }

    load.aligned_size       = size_two;
    load.size               = size_one;

    load.unk38              = 0;
    load.segment_index      = segment_idx;
    load.block_index        = block_idx;
    load.service_id         = service_id;
    load.is_compressed      = SELF_SEGMENT_IS_COMPRESSED(segment);
    load.is_plain_elf       = 0;
    load.res                = -1;

    int res = sceSblServiceRequest(sock, &msg, (char *) &load, (char *) &load);
    
    if (res == 0 && load.res != 0) {
        res = load.res;
    }

    return res;
}