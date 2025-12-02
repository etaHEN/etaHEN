#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/elf64.h>
#include <sys/stat.h>

#include <ps5/kernel.h>

#include "selfpager.h"

#define SELF_ORBIS_MAGIC 0x1D3D154F
#define SELF_PROSPERO_MAGIC 0xEEF51454
#define PAGE_SIZE 0x4000
#define SUPERPAGE_SIZE 0x200000

#define PT_SCE_DYNLIBDATA 0x61000000
#define PT_SCE_RELRO 0x61000010
#define PT_SCE_COMMENT 0x6FFFFF00
#define PT_SCE_VERSION 0x6FFFFF01

#ifdef SELF_PAGER_DO_LOGGING
#define LOG_ERROR(...)                \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
    } while (0)
#else
#define LOG_ERROR(...)
#endif

// https://github.com/Cryptogenic/PS5-SELF-Decrypter/blob/def326f36c1f1b461030222daa9ea6124d4ce610/include/self.h#L21
struct sce_self_header {
    uint32_t magic;         // 0x00
    uint8_t version;        // 0x04
    uint8_t mode;           // 0x05
    uint8_t endian;         // 0x06
    uint8_t attributes;     // 0x07
    uint32_t key_type;      // 0x08
    uint16_t header_size;   // 0x0C
    uint16_t metadata_size; // 0x0E
    uint64_t file_size;     // 0x10
    uint16_t segment_count; // 0x18
    uint16_t flags;         // 0x1A
    char pad_2[0x4];        // 0x1C
}; // Size: 0x20

struct sce_self_segment_header {
    uint64_t flags;             // 0x00
    uint64_t offset;            // 0x08
    uint64_t compressed_size;   // 0x10
    uint64_t uncompressed_size; // 0x18
}; // Size: 0x20

static uint16_t fwver = 0;
static intptr_t pagertab_addr = 0;
static intptr_t vnodepagerops_addr = 0;
static intptr_t selfpagerops_addr = 0;

static const int pagertab_vnodepagerops_index = 2;
static const int pagertab_selfpagerops_index = 7;

static int init() {
    if (pagertab_addr != 0) {
        return 0;
    }

    fwver = kernel_get_fw_version() >> 16;
    switch (fwver) {
    case 0x100:
    case 0x101:
    case 0x102:
    case 0x105:
    case 0x110:
    case 0x111:
    case 0x112:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC27C40;
        break;

    case 0x113:
    case 0x114:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC27CA0;
        break;

    case 0x200:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC4EF60;
        break;

    case 0x220:
    case 0x225:
    case 0x226:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC4EFA0;
        break;

    case 0x230:
    case 0x250:
    case 0x270:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC4F120;
        break;

    case 0x300:
    case 0x310:
    case 0x320:
    case 0x321:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xCAF8C0;
        break;

    case 0x400:
    case 0x402:
    case 0x403:
    case 0x450:
    case 0x451:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xD20840;
        break;

    case 0x500:
    case 0x502:
    case 0x510:
    case 0x550:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE0FEF0;
        break;

    case 0x600:
    case 0x602:
    case 0x650:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE30410;
        break;

    case 0x700:
    case 0x701:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE310C0;
        break;

    case 0x720:
    case 0x740:
    case 0x760:
    case 0x761:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE41180;
        break;

    case 0x800:
    case 0x820:
    case 0x840:
    case 0x860:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE31250;
        break;

    case 0x900:
    case 0x905:
    case 0x920:
    case 0x940:
    case 0x960:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xDE0420;
        break;

    case 0x1000:
    case 0x1001:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xDE04F0;
        break;

    default:
        return ENOSYS;
    }
    vnodepagerops_addr = kernel_getlong(pagertab_addr + pagertab_vnodepagerops_index * 8);
    selfpagerops_addr = kernel_getlong(pagertab_addr + pagertab_selfpagerops_index * 8);

    return 0;
}

void *mmap_self(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    int init_res = init();
    if (init_res != 0) {
        errno = init_res;
        return MAP_FAILED;
    }

    // make vnode pagerops point to selfpagerops
    kernel_setlong(pagertab_addr + (pagertab_vnodepagerops_index * 8), selfpagerops_addr);
    void *res = mmap(addr, len, prot, flags, fd, offset);
    // restore vnode pagerops
    kernel_setlong(pagertab_addr + (pagertab_vnodepagerops_index * 8), vnodepagerops_addr);
    return res;
}

void *map_self_segment(int fd, Elf64_Phdr *phdr, int segment_index) {
    off_t offset = ((uint64_t)segment_index) << 32;
    if (fwver >= 0x900) {
        // for example, for this segment:
        // Index  Type     VirtAddr     FileSize   MemSize    Align
        // 8      PT_LOAD  0xedf7e10    0xce8b98   0xce8b98   0x4000
        // the kernel expects 0x1f4000 in the lower 32 bits, by providing 0 it tells us in the klogs: 
        // self_pager.c(122) self_pager_seg_decode_pindex: off=0, diff=0x1f4000
        uint64_t aligned_vaddr = phdr->p_vaddr & ~(phdr->p_align - 1);
        offset |= aligned_vaddr & (SUPERPAGE_SIZE - 1);
    }
    return mmap_self(NULL, phdr->p_filesz, PROT_READ, MAP_PRIVATE | MAP_ALIGNED(phdr->p_align), fd, offset);
}
#include <ps5/klog.h>
int decrypt_self(int input_file_fd, char **out_data, uint64_t *out_size) {
    klog_printf("line %d: decrypt_self called\n", __LINE__);

    if (!out_data || !out_size) {
        return DECRYPT_ERROR_INTERNAL;
    }
    *out_data = NULL;
    *out_size = 0;

	klog_printf("line %d: decrypt_self called\n", __LINE__);
    struct sce_self_header self_header;
    ssize_t pread_res = pread(input_file_fd, &self_header, sizeof(self_header), 0);
    klog_printf("line %d: decrypt_self called\n", __LINE__);
    if (pread_res == -1) {
        LOG_ERROR("Failed to read self header | errno: %d (%s)\n", errno, strerror(errno));
        return DECRYPT_ERROR_IO;
    } else if (pread_res != sizeof(self_header)) {
        // https://man.freebsd.org/cgi/man.cgi?query=pread&apropos=0&sektion=2&manpath=FreeBSD+11.4-RELEASE&arch=default&format=html
        // The system guarantees to read the number of bytes requested if the descriptor
        // references a normal file that has that many bytes left before the end-of-file

        // the file is smaller than 0x20 bytes, so not a self
        return DECRYPT_ERROR_INPUT_NOT_SELF;
    }
    klog_printf("line %d: decrypt_self called\n", __LINE__);
    if (self_header.magic != SELF_ORBIS_MAGIC && self_header.magic != SELF_PROSPERO_MAGIC) {
        return DECRYPT_ERROR_INPUT_NOT_SELF;
    }
    klog_printf("line %d: decrypt_self called\n", __LINE__);
    Elf64_Ehdr elf_header;
    int self_elf_header_offset = sizeof(struct sce_self_header) + (sizeof(struct sce_self_segment_header) * self_header.segment_count);
    if (pread(input_file_fd, &elf_header, sizeof(elf_header), self_elf_header_offset) != sizeof(elf_header)) {
        LOG_ERROR("Failed to read ELF header\n");
        return DECRYPT_ERROR_IO;
    }
    klog_printf("line %d: decrypt_self called\n", __LINE__);
    if (elf_header.e_ident[EI_MAG0] != ELFMAG0 || elf_header.e_ident[EI_MAG1] != ELFMAG1 ||
        elf_header.e_ident[EI_MAG2] != ELFMAG2 || elf_header.e_ident[EI_MAG3] != ELFMAG3) {
        LOG_ERROR("Failed to find ELF header offset\n");
        return DECRYPT_ERROR_INTERNAL;
    }
    klog_printf("line %d: decrypt_self called\n", __LINE__);
    Elf64_Phdr phdrs[elf_header.e_phnum];
    int phdrs_size = elf_header.e_phnum * sizeof(Elf64_Phdr);
    int self_elf_phdrs_offset = self_elf_header_offset + sizeof(elf_header);
    if (pread(input_file_fd, phdrs, phdrs_size, self_elf_phdrs_offset) != phdrs_size) {
        LOG_ERROR("Failed to read program headers\n");
        return DECRYPT_ERROR_IO;
    }
    klog_printf("line %d: decrypt_self called\n", __LINE__);
    uint64_t output_file_size = 0;
    int version_segment_index = -1;
    for (int i = 0; i < elf_header.e_phnum; i++) {
        Elf64_Phdr *phdr = &phdrs[i];
        if (phdr->p_offset + phdr->p_filesz > output_file_size) {
            output_file_size = phdr->p_offset + phdr->p_filesz;
        }
        if (phdr->p_type == PT_SCE_VERSION) {
            version_segment_index = i;
        }
    }
    klog_printf("line %d: decrypt_self called\n", __LINE__);
    if (output_file_size == 0) {
        LOG_ERROR("Output file size is zero\n");
        return DECRYPT_ERROR_INTERNAL;
    }
    klog_printf("line %d: decrypt_self called\n", __LINE__);
    void *out_buf = mmap(NULL, output_file_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (out_buf == MAP_FAILED) {
        LOG_ERROR("Failed to mmap output buffer | errno: %d (%s)\n", errno, strerror(errno));
        return DECRYPT_ERROR_INTERNAL;
    }
    klog_printf("line %d: decrypt_self called\n", __LINE__);
    for (int i = 0; i < elf_header.e_phnum; i++) {
        Elf64_Phdr *phdr = &phdrs[i];
        if ((phdr->p_type != PT_LOAD && phdr->p_type != PT_SCE_DYNLIBDATA && phdr->p_type != PT_SCE_RELRO && phdr->p_type != PT_SCE_COMMENT) || phdr->p_filesz == 0) {
            continue;
        }
        void *mapped_segment = map_self_segment(input_file_fd, phdr, i);
        if (mapped_segment == MAP_FAILED) {
            if (errno == ENOSYS) {
                LOG_ERROR("Unsupported firmware version\n");
                munmap(out_buf, output_file_size);
                return DECRYPT_ERROR_UNSUPPORTED_FW;
            }
            LOG_ERROR("Failed to mmap_self segment %d | errno: %d (%s)\n", i, errno, strerror(errno));
            munmap(out_buf, output_file_size);
            return DECRYPT_ERROR_INTERNAL;
        }

        if (mlock(mapped_segment, phdr->p_filesz)) {
            LOG_ERROR("Failed to decrypt segment data | segment %d\n", i);
            munmap(mapped_segment, phdr->p_filesz);
            munmap(out_buf, output_file_size);
            return DECRYPT_ERROR_FAILED_TO_DECRYPT_SEGMENT_DATA;
        }

        memcpy((uint8_t *)out_buf + phdr->p_offset, mapped_segment, phdr->p_filesz);

        munmap(mapped_segment, phdr->p_filesz);
    }
    klog_printf("line %d: decrypt_self called\n", __LINE__);

    if (version_segment_index != -1) {
        Elf64_Phdr *phdr = &phdrs[version_segment_index];
        struct stat input_file_stat;
        if (fstat(input_file_fd, &input_file_stat)) {
            LOG_ERROR("Failed to stat input file\n");
            munmap(out_buf, output_file_size);
            return DECRYPT_ERROR_IO;
        }	klog_printf("line %d: decrypt_self called\n", __LINE__);

        int version_segment_self_offset = input_file_stat.st_size - phdr->p_filesz;
        int version_segment_elf_offset = phdr->p_offset;
        if (pread(input_file_fd, out_buf + version_segment_elf_offset, phdr->p_filesz, version_segment_self_offset) != (ssize_t)phdr->p_filesz) {
            LOG_ERROR("Failed to read version segment from input file\n");
            munmap(out_buf, output_file_size);
            return DECRYPT_ERROR_IO;
        }
        klog_printf("line %d: decrypt_self called\n", __LINE__);
    }

    klog_printf("line %d: decrypt_self called\n", __LINE__);
    // copy elf header
    memcpy(out_buf, &elf_header, sizeof(elf_header));
    memcpy(out_buf + sizeof(elf_header), phdrs, phdrs_size);

    *out_data = out_buf;
    *out_size = output_file_size;
    return 0;
}