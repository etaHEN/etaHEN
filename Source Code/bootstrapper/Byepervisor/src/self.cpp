#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

extern "C"
{
#include <ps5/kernel.h>
}

#include "config.h"
#include "debug_log.h"
#include "spec_elf.h"
#include "kdlsym.h"
#include "paging.h"
#include "self.h"
#include "util.h"

extern "C"
{
    int sceKernelOpen(const char *, int, int);
    int sceKernelClose(int);
    int sceKernelGetdents(int, char *, int);
}

int g_die;

int decrypt_self(char *path, char **out_data, int *out_size)
{
    int self_fd;
    uint64_t final_file_size;
    struct elf64_hdr *elf_header;
    struct elf64_phdr *start_phdrs;
    struct elf64_phdr *cur_phdr;
    struct sce_self_header *header;
    char *self_file_data;
    char *out_file_data;
    void *segment_data;
    char note_buf[0x1000];

     flash_notification("decrypt_self: path=[%s]\n", path);

    // Open SELF file
    self_fd = open(path, O_RDONLY);
    if (self_fd < 0)
        return self_fd;

    self_file_data = (char *) mmap(NULL, 0x1000, PROT_READ, MAP_SHARED, self_fd, 0);
    if (self_file_data == MAP_FAILED) {
        close(self_fd);
        return -ENOMEM;
    }

    header = (struct sce_self_header *) self_file_data;

    // Get ELF headers
    elf_header  = (struct elf64_hdr *) (self_file_data + sizeof(struct sce_self_header) +
                    (sizeof(struct sce_self_segment_header) * header->segment_count));
    start_phdrs = (struct elf64_phdr *) ((char *) (elf_header) + sizeof(struct elf64_hdr));

    // Allocate backing buffer for output file data. We'll get size by finding the NOTE program header which should be
    // in most SELFs
    cur_phdr = start_phdrs;
    final_file_size = 0;
    for (int i = 0; i < elf_header->e_phnum; i++) {
        final_file_size = MAX(final_file_size, cur_phdr->p_offset + cur_phdr->p_filesz);
        cur_phdr++;
    }

    if (final_file_size == 0) {
        munmap(self_file_data, 0x1000);
        close(self_fd);
        return -EINVAL;
    }

    // Map buffer for output data
    out_file_data = (char *) mmap(NULL, final_file_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (out_file_data == MAP_FAILED) {
        munmap(self_file_data, 0x1000);
        close(self_fd);
        return -12;
    }

    // Copy ELF headers over
    memcpy(out_file_data, elf_header, sizeof(struct elf64_hdr));
    memcpy(out_file_data + sizeof(struct elf64_hdr), start_phdrs, elf_header->e_phnum * sizeof(struct elf64_phdr));

    // Decrypt and copy segments
    cur_phdr = start_phdrs;
    for (uint64_t i = 0; i < elf_header->e_phnum; i++) {
        if (cur_phdr->p_type == PT_LOAD || cur_phdr->p_type == 0x61000000) {
             flash_notification("decrypt_self: seg=0x%lx\n", i);
            segment_data = mmap(NULL, cur_phdr->p_filesz, PROT_READ, MAP_SHARED | 0x80000, self_fd, (i << 32));
             flash_notification("decrypt_self: segment_data = %p\n", segment_data);
            if (segment_data == MAP_FAILED) {
                munmap(self_file_data, 0x1000);
                close(self_fd);
                return -EIO;
            }

             flash_notification("decrypt_self: copying %p (size = 0x%lx)\n", segment_data, cur_phdr->p_filesz);
            DumpHex(segment_data, 0x100);
            memcpy(out_file_data + cur_phdr->p_offset, segment_data, cur_phdr->p_filesz);
             flash_notification("decrypt_self: unmap %p\n", segment_data);
            munmap(segment_data, cur_phdr->p_filesz);
             flash_notification("decrypt_self: done\n");
        }

        if (cur_phdr->p_type == 0x6FFFFF00) {
            lseek(self_fd, cur_phdr->p_offset, SEEK_SET);
            read(self_fd, &note_buf, cur_phdr->p_filesz);
            memcpy(out_file_data + cur_phdr->p_offset, note_buf, cur_phdr->p_filesz);
        }
        cur_phdr++;
    }

    munmap(self_file_data, 0x1000);
    close(self_fd);

    *out_data = (char *) out_file_data;
    *out_size = (int) final_file_size;
    return 0;
}

int get_self_list(char *dir, char **out_buf, int *out_size)
{
    int ret;
    int dir_fd;
    int file_fd;
    int magic;
    char file_path[0x100];
    int file_name_size;
    char *dirent_buf;
    struct dirent *entry;
    char *out_buf_cur;
    int out_buf_size;

    // flash_notification("get_self_list: dir=[%s]\n", dir);

    // Open directory
    dir_fd = sceKernelOpen(dir, O_RDONLY, 0);
    if (dir_fd < 0)
        return dir_fd;

    // Map buffer for dirents
    dirent_buf = (char *) mmap(NULL, 0x40000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (dirent_buf == MAP_FAILED) {
        sceKernelClose(dir_fd);
        return -ENOMEM;
    }

    // Get dirents
    ret = sceKernelGetdents(dir_fd, dirent_buf, 0x40000);
    if (ret < 0) {
        sceKernelClose(dir_fd);
        return ret;
    }

    // Map buffer for output
    *out_buf = (char *) mmap(NULL, 0x40000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (*out_buf == MAP_FAILED) {
        sceKernelClose(dir_fd);
        return -ENOMEM;
    }

    out_buf_cur  = (char *) (*out_buf);
    out_buf_size = 0;

    // Iterate dirents and find selfs
    entry = (struct dirent *) (dirent_buf);
    while (entry->d_fileno) {
        if (entry->d_type == DT_REG) {
            // Open file
            file_name_size = strlen(entry->d_name) + 1;
            sprintf((char *) &file_path, "%s/%s", dir, entry->d_name);
            file_fd = open(file_path, O_RDONLY, 0);
            if (file_fd < 0) {
                continue;
            }

            // Check if it's a Prospero SELF
            read(file_fd, (void *) &magic, sizeof(magic));
            if (magic == SELF_PROSPERO_MAGIC) {
                // Copy into the list and advance cursor
                strcpy(out_buf_cur, entry->d_name);
                out_buf_cur  += file_name_size;
                out_buf_size += file_name_size;
            }

            close(file_fd);
        }

        entry = (struct dirent *) ((char *) entry + entry->d_reclen);
    }

    // Unmap dirent buf we don't need it anymore
    munmap(dirent_buf, 0x40000);

    // Set output size
    *out_size = out_buf_size;

    // flash_notification("test, out = %p, out_size = 0x%x\n", *out_buf, *out_size);
    DumpHex(*out_buf, 0x200);

    // Close directory
    sceKernelClose(dir_fd);
    return 0;
}

int copy_file(char *paths)
{
    int in_fd;
    int out_fd;
    ssize_t read_bytes;
    ssize_t written_bytes;
    char *in_path;
    char *out_path;
    char buf[0x1000];

    in_path = paths;
    out_path = paths + (strlen(paths) + 1);

     flash_notification("[+] copy_file(%s, %s)\n", in_path, out_path);

    in_fd = open(in_path, O_RDONLY);
    if (in_fd < 0)
        return in_fd;

    remove(out_path);

    out_fd = open(out_path, O_RDWR | O_CREAT);
         flash_notification("tst2 = 0x%x (%s)\n", out_fd, strerror(errno));
        if (out_fd < 0)
            return out_fd;

     flash_notification("  [+] in_fd = 0x%x, out_fd = 0x%x\n", in_fd, out_fd);

    while ((read_bytes = read(in_fd, buf, sizeof(buf))) > 0) {
        written_bytes = write(out_fd, buf, read_bytes);
        if (written_bytes != read_bytes) {
             flash_notification("[!] failed to copy file (%ld != %ld) (%s)\n", written_bytes, read_bytes, strerror(errno));
            break;
        }
    }

    close(in_fd);
    close(out_fd);

    return 0;
}

int read_verify_request_header(int client, struct self_rpc_ctrl_header *out_header)
{
    int ret;

    // Read in the header and ensure we received exactly enough data for it
     flash_notification("[SRV] [SELF] [%d] waiting on request\n", client);
    ret = read(client, (void *) out_header, sizeof(struct self_rpc_ctrl_header));
    if (ret != sizeof(struct self_rpc_ctrl_header)) {
         flash_notification("[SRV] [SELF] [%d] failed to read header, expected %lu bytes got %d\n",
                 client, sizeof(struct self_rpc_ctrl_header), ret);
        if (ret <= 0)
            return -EBADF;
        return -EIO;
    }

    // Verify length
    if (out_header->len >= SELF_RPC_MAX_BUF_SIZE) {
         flash_notification("[SRV] [SELF] [%d] packet too large (0x%x)\n", client, out_header->len);
        return -EINVAL;
    }

     flash_notification("[SRV] [SELF] [%d] received header\n", client);
    return 0;
}

int read_request_data(int client, struct self_rpc_ctrl_header *req, char *req_data)
{
    char *req_data_cur;
    int received_bytes = 0;
    int ret;

    // Continue to read to receive all the data
    req_data_cur = req_data;
    while (received_bytes < req->len) {
         flash_notification("[SRV] [%d] need an additional 0x%x bytes\n", client, (req->len - received_bytes));
        ret = read(client, req_data_cur, (req->len - received_bytes));
        if (ret < 0) {
            return ret;
        }

        if (ret == 0) {
             flash_notification("[SRV] [%d] received zero-size data\n", client);
            return -EIO;
        }

        // Advance cursor
        req_data_cur += ret;
        received_bytes += ret;
    }

    if (received_bytes != req->len) {
         flash_notification("[SRV] [%d] failed to read all request data, expected %d bytes got %d\n",
                 client, req->len, received_bytes);
        return -EIO;
    }

     flash_notification("[SRV] [%d] received data (%d bytes)\n", client, received_bytes);
    return received_bytes;
}

int send_response(int client, int cmd, int status, int len, char *data)
{
    int ret;
    struct self_rpc_ctrl_header resp_ctrl;

    // Setup response header
    resp_ctrl.cmd       = cmd;
    resp_ctrl.status    = status;
    resp_ctrl.len       = len;

    // Write header
    ret = write(client, (void *) &resp_ctrl, sizeof(struct self_rpc_ctrl_header));
    if (ret <= 0) {
         flash_notification("[SRV] [SELF] [%d] failed to write response header\n", client);
        return -EIO;
    }

    // Write data
     flash_notification("[SRV] [SELF] [%d] writing data (len=0x%x)\n", client, len);
    return write(client, (void *) data, len);
}

int handle_self_cmd(int client, int cmd, char *in_data, char **out_data_ptr, int *out_len)
{
    int status;
    int resp_len;

    switch (cmd) {
    case SELF_CMD_PING:
         flash_notification("[SRV] [SELF] [%d] received ping request\n", client);
        status   = flash_notification("Self server\nPong!");
        resp_len = 0;
        break;
    case SELF_CMD_DIE:
         flash_notification("[SRV] [SELF] [%d] received die request\n", client);
        status   = 0;
        resp_len = 0;
        g_die    = 1;
        break;
    case SELF_CMD_GET_FW:
         flash_notification("[SRV] [SELF] [%d] received get fw request\n", client);
        status   = kernel_get_fw_version() & 0xFFFF0000;
        resp_len = 0;
        break;
    case SELF_CMD_GET_DIR_SELFS:
         flash_notification("[SRV] [SELF] [%d] received get dir selfs request\n", client);
        status   = get_self_list(in_data, out_data_ptr, &resp_len);
        break;
    case SELF_CMD_DECRYPT_SELF:
         flash_notification("[SRV] [SELF] [%d] received decrypt self request\n", client);
        status   = decrypt_self(in_data, out_data_ptr, &resp_len);
        break;
    case SELF_CMD_COPY_FILE:
         flash_notification("[SRV] [SELF] [%d] received copy file request\n", client);
        status   = copy_file(in_data);
        resp_len = 0;
        break;
    }

    *out_len = resp_len;
    return status;
}

void handle_self_client(int client)
{
    int status;
    int resp_len;
    struct self_rpc_ctrl_header req_ctrl;
    char req_data[SELF_RPC_MAX_BUF_SIZE];
    char *resp_data_ptr;

    // Infinite loop on handling the client until they terminate connection or error occurs
    for (;;) {
        // Clear info for fresh state
        bzero(&req_ctrl, sizeof(struct self_rpc_ctrl_header));

        // Read header and data
        if (read_verify_request_header(client, &req_ctrl) != 0) {
             flash_notification("[SRV] [SELF] [%d] received bad header\n", client);
            break;
        }

        if (req_ctrl.len > 0) {
            if (read_request_data(client, &req_ctrl, (char *) &req_data) <= 0) {
                 flash_notification("[SRV] [SELF] [%d] received bad data\n", client);
                break;
            }
        }

        // Dispatch command handling
        status = handle_self_cmd(client, req_ctrl.cmd, (char *) &req_data, &resp_data_ptr, &resp_len);

        // Send response
        if (send_response(client, req_ctrl.cmd, status, resp_len, resp_data_ptr) < 0) {
             flash_notification("[SRV] [SELF] [%d] failed to write response (%s)\n", client, strerror(errno));
            break;
        }

        // If data was mapped, unmap it
        if (resp_data_ptr != NULL)
            munmap(resp_data_ptr, resp_len);

        // On die command, exit out as server will be shutting down...
        if (req_ctrl.cmd == SELF_CMD_DIE) {
             flash_notification("[SRV] [SELF] [%d] received die command\n", client);
            break;
        }
    }

    close(client);
     flash_notification("[SRV] [SELF] [%d] dropped client\n", client);
}

int run_self_server(int port)
{
    int s;
    int client;
    struct sockaddr_in sockaddr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&sockaddr, sizeof(sockaddr));

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(port);
    sockaddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (const struct sockaddr *) &sockaddr, sizeof(sockaddr)) < 0) {
         flash_notification("[!] failed to bind server\n");
        return -1;
    }

    if (listen(s, 5) < 0) {
         flash_notification("[!] failed to listen on server\n");
        return -1;
    }

     flash_notification("[SRV] [SELF] self dump server is now running (port: %d)...\n", port);

    // Accept clients
    for (;;) {
        if (g_die) {
             flash_notification("[SRV] [SELF] rpc server is shutting down...\n");
            close(s);
            break;
        }

        client = accept(s, 0, 0);
         flash_notification("[SRV] [SELF] accepted a client = %d\n", client);

        if (client > 0) {
            handle_self_client(client);
        }
    }

    return 0;
}
