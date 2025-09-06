#pragma once

#include "proc.h"
#include "pt.h"
#include "elfldr.h"
#include "ps5/mdbg.h"
#include "ps5/nid.h"
#include "nid.h"
#include "hello_world.h"
#include "ucred.h"

#include <stdbool.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <pthread.h>


#define TARGET_SPRX "/system_ex/common_ex/lib/libSceNKWebKit.sprx"
#define TARGET_SPRX_BASENAME "libSceNKWebKit.sprx"


typedef struct __scefunctions
{
    int (*sceKernelDebugOutText)(int channel, const char *msg);
    int (*elf_main)(void* payload_args);

    void* payload_args;
    int (*pthread_create_ptr)(pthread_t *, const pthread_addr_t*, void*(*)(void*), void*);
    // int (*sceKernelLoadStartModule)(const char *module_file_name, int args, const void *argp, int flags, void *opt, int *pRes);    

} SCEFunctions;


extern int attached;
extern SCEFunctions sce_functions;

int stager(SCEFunctions* functions);
uint32_t get_shellcode_size();
//
// Loader specifics
//
int inject_elf(struct proc* proc, void* elf);
int create_remote_thread(pid_t pid, uintptr_t target_address, uintptr_t parameters);
module_info_t* load_remote_library(pid_t pid, const char* library_path, const char* library_name);
void init_remote_function_pointers(pid_t pid);
// void shellcode_start(pid_t pid, uint64_t target_address);



