#pragma once

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "freebsd-helper.h"
#include "ps5/payload.h"
#include "ps5/kernel.h"

#include "syscalls.h"


#define MODULE_INFO_NAME_LENGTH 128
#define MODULE_INFO_SANDBOXED_PATH_LENGTH 1024
#define MODULE_INFO_MAX_SECTIONS 4
#define FINGERPRINT_LENGTH 20

typedef struct {
	uint64_t vaddr;
	uint64_t size;
    uint32_t prot;
} module_section_t;

typedef struct {
	char filename[MODULE_INFO_NAME_LENGTH];
	uint64_t handle;
	uint8_t unknown0[32]; // NOLINT(readability-magic-numbers)
	uint64_t init; // init
	uint64_t fini; // fini
	uint64_t eh_frame_hdr; // eh_frame_hdr
	uint64_t eh_frame_hdr_sz; // eh_frame_hdr_sz
	uint64_t eh_frame; // eh_frame
	uint64_t eh_frame_sz; // eh_frame_sz
	module_section_t sections[MODULE_INFO_MAX_SECTIONS];
	uint8_t unknown7[1176]; // NOLINT(readability-magic-numbers)
	uint8_t fingerprint[FINGERPRINT_LENGTH];
	uint32_t unknown8;
	char libname[MODULE_INFO_NAME_LENGTH];
	uint32_t unknown9;
	char sandboxed_path[MODULE_INFO_SANDBOXED_PATH_LENGTH];
	uint64_t sdk_version;
} module_info_t;




struct proc* find_proc_by_name(const char* process_name);
struct proc* get_proc_by_pid(pid_t pid);
module_info_t* get_module_handle(pid_t pid, const char* module_name);
void list_all_proc_and_pid();

void list_proc_modules(struct proc* proc);