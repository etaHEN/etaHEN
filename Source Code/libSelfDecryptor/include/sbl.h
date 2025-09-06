#pragma once
#ifndef SBL_H
#define SBL_H


#include <sys/types.h>

#ifdef LOG_TO_SOCKET
#define SOCK_LOG(sock, format, ...)                                          \
{                                                                            \
    char _macro_printfbuf[512];                                              \
    int _macro_size = sprintf(_macro_printfbuf, format, ##__VA_ARGS__);      \
    write(sock, _macro_printfbuf, _macro_size);                             \
} while(0);
#else
#define SOCK_LOG(sock, format, ...) \
    do { printf(format, ##__VA_ARGS__); } while(0);
#endif

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

void sock_print(int sock, char *str);
void DumpHex(int sock, const void* data, size_t size);
uint64_t pmap_kextract(int sock, uint64_t va);

// Must be called before using other functions
void init_sbl(
    uint64_t kernel_data_base,
    uint64_t dmpml4i_offset,
    uint64_t dmpdpi_offset,
    uint64_t pml4pml4i_offset,
    uint64_t mailbox_base_offset,
    uint64_t mailbox_flags_offset,
    uint64_t mailbox_meta_offset,
    uint64_t mailbox_mtx_offset,
    uint64_t g_message_id_offset
);

int _sceSblServiceRequest(int sock, struct sbl_msg_header *msg_header, void *in_buf, void *out_buf, int request_type);
int sceSblDriverSendMsgAnytime(int sock, struct sbl_msg_header *msg_header, void *in_buf, void *out_buf);
int sceSblDriverSendMsgPol(int sock, struct sbl_msg_header *msg_header, void *in_buf, void *out_buf);
int sceSblServiceRequest(int sock, struct sbl_msg_header *msg_header, void *in_buf, void *out_buf);
int sceSblDriverSendMsg(int sock, struct sbl_msg_header *msg_header, void *in_buf);

#endif