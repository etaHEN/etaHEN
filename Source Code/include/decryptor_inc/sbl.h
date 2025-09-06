#pragma once
#ifndef SBL_H
#define SBL_H


#include <sys/types.h>

struct OrbisKernelSwVersion {
    uint64_t pad0;
    char version_str[0x1C];
    uint32_t version;
    uint64_t pad1;
};

#define //SOCK_LOG(sock, format, ...)                                          \
{                                                                            \
    char _macro_printfbuf[512];                                              \
    int _macro_size = sprintf(_macro_printfbuf, format, ##__VA_ARGS__);      \
    _write(sock, _macro_printfbuf, _macro_size);                             \
} while(0);

struct sbl_msg_header
{
    uint32_t cmd;        // 0x00
    uint16_t query_len;  // 0x04
    uint16_t recv_len;   // 0x06
    uint64_t message_id; // 0x08
    uint64_t to_ret;     // 0x10
}; // size: 0x18

struct sbl_spawn
{
    uint64_t unk_00h;    // 0x00
    uint64_t unk_08h;    // 0x08
    uint64_t unk_10h;    // 0x10
    char sm_code[0x8];   // 0x18
    uint64_t unk_20h;    // 0x20
}; // size: 0x28

struct sbl_unload
{
    uint64_t function;   // 0x00
}; // size: 0x8

struct sbl_waitforunload
{
    uint64_t function;   // 0x00
    uint64_t handle;     // 0x08
}; // size: 0x10

void sock_print( char *str);
void DumpHex( const void* data, size_t size);
uint64_t pmap_kextract( uint64_t va);

// Must be called before using other functions
void init_sbl(
    uint64_t dmpml4i_offset,
    uint64_t dmpdpi_offset,
    uint64_t pml4pml4i_offset,
    uint64_t mailbox_base_offset,
    uint64_t mailbox_flags_offset,
    uint64_t mailbox_meta_offset,
    uint64_t mailbox_mtx_offset
);

int _sceSblServiceRequest( struct sbl_msg_header *msg_header, void *in_buf, void *out_buf, int request_type);
int sceSblDriverSendMsgAnytime( struct sbl_msg_header *msg_header, void *in_buf, void *out_buf);
int sceSblDriverSendMsgPol( struct sbl_msg_header *msg_header, void *in_buf, void *out_buf);
int sceSblServiceRequest( struct sbl_msg_header *msg_header, void *in_buf, void *out_buf);
int sceSblDriverSendMsg( struct sbl_msg_header *msg_header, void *in_buf);

#endif