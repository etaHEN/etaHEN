/* Copyright (C) 2025 etaHEN / LightningMods

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string>
#include <msg.hpp>

struct clientArgs {
    std::string ip;
    int socket;
    int cl_nmb;

};

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/elf_common.h>
#include <sys/elf64.h>
#include <sys/elf32.h>

#define SELF_PROSPERO_MAGIC     0xEEF51454

typedef struct elf32_hdr_new {
    unsigned char    e_ident[EI_NIDENT];
    uint16_t         e_type;
    uint16_t         e_machine;
    uint32_t         e_version;
    uint32_t         e_entry;  /* Entry point */
    uint32_t         e_phoff;
    uint32_t         e_shoff;
    uint32_t         e_flags;
    uint16_t         e_ehsize;
    uint16_t         e_phentsize;
    uint16_t         e_phnum;
    uint16_t         e_shentsize;
    uint16_t         e_shnum;
    uint16_t         e_shstrndx;
} Elf32_Ehdr_new;

typedef struct elf64_hdr_new {
    unsigned char	 e_ident[EI_NIDENT]; /* ELF "magic number" */
    uint16_t         e_type;
    uint16_t         e_machine;
    uint32_t         e_version;
    uint64_t         e_entry;            /* Entry point virtual address */
    uint64_t         e_phoff;            /* Program header table file offset */
    uint64_t         e_shoff;            /* Section header table file offset */
    uint32_t         e_flags;
    uint16_t         e_ehsize;
    uint16_t         e_phentsize;
    uint16_t         e_phnum;
    uint16_t         e_shentsize;
    uint16_t         e_shnum;
    uint16_t         e_shstrndx;
} Elf64_Ehdr_new;

typedef struct elf32_phdr_new {
    uint32_t         p_type;
    uint32_t         p_offset;
    uint32_t         p_vaddr;
    uint32_t         p_paddr;
    uint32_t         p_filesz;
    uint32_t         p_memsz;
    uint32_t         p_flags;
    uint32_t         p_align;
} Elf32_Phdr_new;

typedef struct elf64_phdr_new {
    uint32_t         p_type;
    uint32_t         p_flags;
    uint64_t         p_offset;      /* Segment file offset */
    uint64_t         p_vaddr;       /* Segment virtual address */
    uint64_t         p_paddr;       /* Segment physical address */
    uint64_t         p_filesz;      /* Segment size in file */
    uint64_t         p_memsz;       /* Segment size in memory */
    uint64_t         p_align;       /* Segment alignment, file & memory */
} Elf64_Phdr_new;


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

#ifdef __cplusplus
#define restrict // Define restrict as empty for C++
#endif

extern "C"
{
#define ENTRYPOINT_OFFSET 0x70

#define PROCESS_LAUNCHED 1

#define LOOB_BUILDER_SIZE 21
#define LOOP_BUILDER_TARGET_OFFSET 3
#define USLEEP_NID "QcteRwbsnV0"
#include <ps5/kernel.h>

}

/*==================== DPI =========================*/
#define PLAYGOSCENARIOID_SIZE 3
#define CONTENTID_SIZE 0x30
#define LANGUAGE_SIZE 8

typedef char playgo_scenario_id_t[PLAYGOSCENARIOID_SIZE];
typedef char language_t[LANGUAGE_SIZE];
typedef char content_id_t[CONTENTID_SIZE];

typedef struct
{
	content_id_t content_id;
	int content_type;
	int content_platform;
} SceAppInstallPkgInfo;

typedef struct
{
	const char *uri;
	const char *ex_uri;
	const char *playgo_scenario_id;
	const char *content_id;
	const char *content_name;
	const char *icon_url;
} MetaInfo;

#define NUM_LANGUAGES 30
#define NUM_IDS 64

typedef struct {
    language_t languages[NUM_LANGUAGES];
    playgo_scenario_id_t playgo_scenario_ids[NUM_IDS];
    content_id_t content_ids[NUM_IDS];
    long unknown[810];
} PlayGoInfo;

typedef struct {
  uint64_t pad0;
  char version_str[0x1C];
  uint32_t version;
  uint64_t pad1;
} OrbisKernelSwVersion;
extern "C" int sceKernelGetProsperoSystemSwVersion(OrbisKernelSwVersion *sw);

/*==================== DPI =========================*/

extern "C"  int sceAppInstUtilInstallByPackage(MetaInfo *arg1, SceAppInstallPkgInfo *pkg_info, PlayGoInfo *arg2);
extern "C"  int sceAppInstUtilInitialize(void);

void startMessageReceiver();
bool notifyHandlers(const uint32_t prefix, const pid_t pid, const bool isHomebrew) noexcept;
bool hasPrefixHandler(const uint32_t prefix) noexcept;
void* messageThread(void*);
bool GetFileContents(const char *path, char **buffer);
bool touch_file(const char *destfile);
bool decrypt_dir(const std::string& inputPath, const std::string& outputPath) ;
void *IPC_loop(void *args);