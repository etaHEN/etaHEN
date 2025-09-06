#include <ps5/kernel.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "sbl.h"

struct sbl_mailbox_metadata
{
    uint64_t message_id;
    uint64_t unk_08h;
    uint32_t unk_10h;
};

uint64_t g_sbl_kernel_data_base;
uint64_t g_sbl_dmap_base;
uint64_t g_sbl_kernel_offset_dmpml4i;
uint64_t g_sbl_kernel_offset_dmpdpi;
uint64_t g_sbl_kernel_offset_pml4pml4i;
uint64_t g_sbl_kernel_offset_mailbox_base;
uint64_t g_sbl_kernel_offset_mailbox_flags;
uint64_t g_sbl_kernel_offset_mailbox_meta;
uint64_t g_sbl_kernel_offset_mailbox_mtx;
uint64_t g_sbl_kernel_offset_g_message_id;
int g_sbl_mailbox_marked_inuse = 0;

void DumpHex(int sock, const void* data, size_t size) {
#if DEBUG
    char hexbuf[0x4000];
    (void)memset(hexbuf, 0, sizeof(hexbuf));
    char *cur = hexbuf;

    sprintf(cur, "hex:\n");
    cur += strlen(cur);

    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        sprintf(cur, "%02X ", ((unsigned char*)data)[i]);
        cur += strlen(cur);

        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            sprintf(cur, " ");
            cur += strlen(cur);

            if ((i+1) % 16 == 0) {
                sprintf(cur, "|  %s \n", ascii);
                cur += strlen(cur);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    sprintf(cur, " ");
                    cur += strlen(cur);
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    sprintf(cur, "   ");
                    cur += strlen(cur);
                }
                sprintf(cur, "|  %s \n", ascii);
                cur += strlen(cur);
            }
        }
    }

    sock_print(sock, hexbuf);
#endif
}

void init_sbl(
    uint64_t kernel_data_base,
    uint64_t dmpml4i_offset,
    uint64_t dmpdpi_offset,
    uint64_t pml4pml4i_offset,
    uint64_t mailbox_base_offset,
    uint64_t mailbox_flags_offset,
    uint64_t mailbox_meta_offset,
    uint64_t mailbox_mtx_offset,
    uint64_t g_message_id_offset)
{
    uint64_t DMPML4I = 0;
    uint64_t DMPDPI = 0;
    uint64_t PML4PML4I = 0;

    g_sbl_kernel_data_base            = kernel_data_base;
    g_sbl_kernel_offset_dmpml4i       = dmpml4i_offset;
    g_sbl_kernel_offset_dmpdpi        = dmpdpi_offset;
    g_sbl_kernel_offset_pml4pml4i     = pml4pml4i_offset;
    g_sbl_kernel_offset_mailbox_base  = mailbox_base_offset;
    g_sbl_kernel_offset_mailbox_flags = mailbox_flags_offset;
    g_sbl_kernel_offset_mailbox_meta  = mailbox_meta_offset;
    g_sbl_kernel_offset_mailbox_mtx   = mailbox_mtx_offset;
    g_sbl_kernel_offset_g_message_id  = g_message_id_offset;

    kernel_copyout(g_sbl_kernel_data_base + g_sbl_kernel_offset_dmpml4i, &DMPML4I, sizeof(int));
    kernel_copyout(g_sbl_kernel_data_base + g_sbl_kernel_offset_dmpdpi, &DMPDPI, sizeof(int));
    kernel_copyout(g_sbl_kernel_data_base + g_sbl_kernel_offset_pml4pml4i, &PML4PML4I, sizeof(int));

    g_sbl_dmap_base = (DMPDPI << 30) | (DMPML4I << 39) | 0xFFFF800000000000;
}

int _sceSblServiceRequest(int sock, struct sbl_msg_header *msg_header, void *in_buf, void *out_buf, int request_type)
{
    switch (request_type) {
    case 2:
        return sceSblDriverSendMsgAnytime(sock, msg_header, in_buf, out_buf);
    case 1:
        return sceSblDriverSendMsgPol(sock, msg_header, in_buf, out_buf);
    case 0:
        return sceSblServiceRequest(sock, msg_header, in_buf, out_buf);
    }

    return -37;
}

#define MAILBOX_NUM 0xE

int sceSblServiceRequest(int sock, struct sbl_msg_header *msg_header, void *in_buf, void *out_buf)
{
    int err;
    uint32_t mailbox_to_bitmap;
    uint64_t message_id;
    struct sbl_mailbox_metadata mailbox_metadata;

    // Get mailbox base for reply
    uint64_t mailbox_base;
    uint64_t mailbox_addr;

    kernel_copyout(g_sbl_kernel_data_base + g_sbl_kernel_offset_mailbox_base, &mailbox_base, sizeof(mailbox_base));
    mailbox_addr = mailbox_base + (0x800 * (0x10 + MAILBOX_NUM));

    // at offset 0x4 of out_buf, the res is stored
    int res_before = -69;
    kernel_copyin(&res_before, mailbox_addr + 0x18 + 0x4, sizeof(res_before));

#if DEBUG
    SOCK_LOG(sock, "sceSblServiceRequest: mailbox = %p\n", mailbox_addr);
    SOCK_LOG(sock, "sceSblServiceRequest: mailbox flags offset = %p (addr = %p)\n", g_sbl_kernel_offset_mailbox_flags, g_sbl_kernel_data_base + g_sbl_kernel_offset_mailbox_flags);
#endif

    // Get message ID and update global count
    kernel_copyout(g_sbl_kernel_data_base + g_sbl_kernel_offset_g_message_id, &message_id, sizeof(message_id));

    if (message_id == 0) {
        message_id = 0x414100;
    }

    msg_header->message_id = message_id++;

    kernel_copyin(&message_id, g_sbl_kernel_data_base + g_sbl_kernel_offset_g_message_id, sizeof(message_id));

#if DEBUG
    SOCK_LOG(sock, "sceSblServiceRequest: retrieved message id (0x%llx) write to meta\n", msg_header->message_id);
    SOCK_LOG(sock, "sceSblServiceRequest: writing to %p (offset=%p)\n", g_sbl_kernel_data_base + g_sbl_kernel_offset_mailbox_meta + (MAILBOX_NUM * 0x28), g_sbl_kernel_offset_mailbox_meta);
#endif

    // Write mailbox metadata
    mailbox_metadata.message_id = msg_header->message_id;
    mailbox_metadata.unk_08h = 0;
    mailbox_metadata.unk_10h = 0;
    kernel_copyin(&mailbox_metadata, g_sbl_kernel_data_base + g_sbl_kernel_offset_mailbox_meta + (MAILBOX_NUM * 0x28), sizeof(struct sbl_mailbox_metadata));

    // Mark mailbox as in-use
    kernel_copyout(g_sbl_kernel_data_base + g_sbl_kernel_offset_mailbox_flags, &mailbox_to_bitmap,
                   sizeof(mailbox_to_bitmap));
    mailbox_to_bitmap |= (1 << MAILBOX_NUM);
    kernel_copyin(&mailbox_to_bitmap, g_sbl_kernel_data_base + g_sbl_kernel_offset_mailbox_flags,
                  sizeof(mailbox_to_bitmap));

#if DEBUG
    SOCK_LOG(sock, "sceSblServiceRequest: marked mailbox in-use (0x%08x)\n", mailbox_to_bitmap);
#endif

    // Send off the message
    while (1) {
        err = sceSblDriverSendMsg(sock, msg_header, in_buf);
        if (err != -11)
            break;

        usleep(10);
    }

    // Unlock the mailbox on error
    if (err != 0) {
        SOCK_LOG(sock, "sceSblServiceRequest: sceSblDriverSendMsg() failed, waiting 1s\n");
        sleep(1);
        
        kernel_copyout(g_sbl_kernel_data_base + g_sbl_kernel_offset_mailbox_flags, &mailbox_to_bitmap, sizeof(mailbox_to_bitmap));
        mailbox_to_bitmap &= (~(1 << MAILBOX_NUM));
        kernel_copyin(&mailbox_to_bitmap, g_sbl_kernel_data_base + g_sbl_kernel_offset_mailbox_flags, sizeof(mailbox_to_bitmap));

        SOCK_LOG(sock, "sceSblServiceRequest: sceSblDriverSendMsg() failed: %d\n", err);
        DumpHex(sock, msg_header, sizeof(struct sbl_msg_header));
        DumpHex(sock, in_buf, 0x80);

        usleep(50000);
        return err;
    }

#if DEBUG
    SOCK_LOG(sock, "sceSblServiceRequest: sceSblDriverSendMsg() returned: %d\n", err);
#endif

    int res_after = res_before;
    // try for 500ms
    for (int i = 0; i < 500; i++) {
        kernel_copyout(mailbox_addr + 0x18 + 0x4, &res_after, sizeof(res_after));

        if (res_after != res_before) {
            break;
        }

        usleep(1000);
    }

    usleep(2000);

    if (res_after == res_before) {
        SOCK_LOG(sock, "sceSblServiceRequest: request timed out\n");
        return -1;
    }

#if DEBUG
    char msg_out[0x98] = {};
    for (int i = 0; i < 1; i++) {
        SOCK_LOG(sock, "----- SBL response msg -----\n", i);
        kernel_copyout(mailbox_addr, &msg_out, sizeof(msg_out));

        DumpHex(sock, &msg_out, sizeof(msg_out));
    }
#endif

    kernel_copyout(mailbox_addr + 0x18, out_buf, msg_header->recv_len);

#if 0
    // Wait on reply message
    while (1) {
        kernel_copyout(g_sbl_kernel_data_base + 0x2D8DFC4, &mailbox_from_bitmap, sizeof(mailbox_from_bitmap));
        if ((mailbox_from_bitmap & (1 << mailbox_num)) != 0) {
            break;
        }

        usleep(1000);
    }

    kernel_copyout(g_sbl_kernel_data_base + g_sbl_kernel_offset_mailbox_meta, &mailbox_metadata, sizeof(struct sbl_mailbox_metadata));
    kernel_copyout(mailbox_metadata.unk_08h, &recv_msg, sizeof(recv_msg));

    err = (int) recv_msg.to_ret;
    if (err < 0) {
        goto out;
    }

    if (recv_msg.recv_len <= msg_header->recv_len) {
        msg_header->recv_len = recv_msg.recv_len;
        kernel_copyout(mailbox_metadata.unk_08h + 0x18, out_buf, recv_msg.recv_len);
    } else {
        printf("sceSblServiceRequest: rlen %u > %u\n", recv_msg.recv_len, msg_header->recv_len);
        err = -28;
    }
#endif
    kernel_copyout(g_sbl_kernel_data_base + g_sbl_kernel_offset_mailbox_flags, &mailbox_to_bitmap, sizeof(mailbox_to_bitmap));
    mailbox_to_bitmap &= (~(1 << MAILBOX_NUM));
    kernel_copyin(&mailbox_to_bitmap, g_sbl_kernel_data_base + g_sbl_kernel_offset_mailbox_flags, sizeof(mailbox_to_bitmap));

    return err;
}

int sceSblDriverSendMsgAnytime(int sock, struct sbl_msg_header *msg_header, void *in_buf, void *out_buf)
{
    return -1;
}

int sceSblDriverSendMsgPol(int sock, struct sbl_msg_header *msg_header, void *in_buf, void *out_buf)
{
    return -1;
}

uint64_t pmap_kextract(int sock, uint64_t va)
{
    uint64_t DMPML4I = 0;
    uint64_t DMPDPI = 0;
    uint64_t PML4PML4I = 0;
    uint64_t dmap;
    uint64_t dmap_end;
    uint64_t pde_addr;
    uint64_t pte_addr;
    uint64_t pde;
    uint64_t pte;

    kernel_copyout(g_sbl_kernel_data_base + g_sbl_kernel_offset_dmpml4i, &DMPML4I, sizeof(int));
    kernel_copyout(g_sbl_kernel_data_base + g_sbl_kernel_offset_dmpdpi, &DMPDPI, sizeof(int));
    kernel_copyout(g_sbl_kernel_data_base + g_sbl_kernel_offset_pml4pml4i, &PML4PML4I, sizeof(int));

    dmap     = (DMPDPI << 30) | (DMPML4I << 39) | 0xFFFF800000000000;
    dmap_end = ((DMPML4I +1 ) << 39) | 0xFFFF800000000000;

    if (dmap <= va && dmap_end > va) {
        return va - dmap;
    }

    pde_addr = ((PML4PML4I << 39) | (PML4PML4I << 30) | 0xFFFF800000000000) + 8 * ((va >> 21) & 0x7FFFFFF);

    kernel_copyout(pde_addr, &pde, sizeof(pde));
    if (pde & 0x80) {
        return (pde & 0xFFFFFFFE00000) | (va & 0x1FFFFF);
    }

    pte_addr = ((va >> 9) & 0xFE0) + dmap + (pde & 0xFFFFFFFFFF000);
    kernel_copyout(pte_addr, &pte, sizeof(pte));

    return (pte & 0xFFFFFFFFFF000) | (va & 0x3FFF);
}

int sceSblDriverSendMsg(int sock, struct sbl_msg_header *msg_header, void *in_buf)
{
    uint64_t mmio_space;
    static uint64_t mailbox_base = 0;
    uint64_t mailbox_addr;
    static uint64_t mailbox_pa = 0;
    uint32_t cmd;
    uint32_t status;

    // Get MMIO space
    mmio_space = g_sbl_dmap_base + 0xE0500000;

    // Get mailbox address
    if (mailbox_base == 0) {
        kernel_copyout(g_sbl_kernel_data_base + g_sbl_kernel_offset_mailbox_base, &mailbox_base, sizeof(mailbox_base));
    }
    mailbox_addr = mailbox_base + (0x800 * (0x10 + MAILBOX_NUM));

    // Copy into mailbox
    kernel_copyin(msg_header, mailbox_addr, sizeof(struct sbl_msg_header));
    kernel_copyin(in_buf, mailbox_addr + 0x18, msg_header->query_len);

    if (mailbox_pa == 0) {
        mailbox_pa = pmap_kextract(sock, mailbox_addr);
    }

    cmd = msg_header->cmd << 8;

    kernel_copyin(&mailbox_pa, mmio_space + 0x10568, sizeof(int));
    kernel_copyin(&cmd, mmio_space + 0x10564, sizeof(int));

    do {
        kernel_copyout(mmio_space + 0x10564, &status, sizeof(status));

        if ((status & 1) != 0) {
            break;
        }

        usleep(1000);
    } while (1);

#if DEBUG
    SOCK_LOG(sock, "sceSblDriverSendMsg: status = 0x%08x\n", status);
#endif

    return (int) ((uint32_t) (status << 0x1E) >> 0x1F) & 0xfffffffb;
}