#pragma once
#ifndef SELF_H
#define SELF_H

#define SELF_PROSPERO_MAGIC     0xEEF51454

/*
 * RPC stuff
 */

#define SELF_RPC_MAX_BUF_SIZE                       1024

struct self_rpc_ctrl_header {
    uint32_t cmd;
    uint32_t len;
    uint64_t status;
};

// Ping is a simple command with no request or response data.
#define SELF_CMD_PING                               1

// Die command kills the server, no request/response data.
#define SELF_CMD_DIE                                2

// Get firmware command. No request/response data, fw is returned in status.
#define SELF_CMD_GET_FW                             3

// Get dir selfs command gets a list of self files in a dir. Request is dir path, response is list of null-terminated strings.
#define SELF_CMD_GET_DIR_SELFS                      4

// Decrypt self command. Request is file path, response is file data.
#define SELF_CMD_DECRYPT_SELF                       5

// Copy file command. Request is file paths, no response data.
#define SELF_CMD_COPY_FILE                          6

int run_self_server(int port);

/*
 * SELF stuff
 */

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

int decrypt_self(char *path, char **out_data, int *out_size);
int get_self_list(char *dir, char **out_buf, int *out_size);
int copy_file(char *paths);

#endif // SELF_H