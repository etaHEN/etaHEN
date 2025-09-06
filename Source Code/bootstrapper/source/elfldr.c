/* Copyright (C) 2024 John Törnblom

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

#include <elf.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/elf_common.h>
#include <sys/elf64.h>


#include <ps5/kernel.h>
#include <ps5/mdbg.h>

#include "elfldr.h"
#include "pt.h"


#ifndef IPV6_2292PKTOPTIONS
#define IPV6_2292PKTOPTIONS 25
#endif


/**
 * Convenient macros.
 **/
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
		     (((x) & PF_W) ? PROT_WRITE : 0) | \
		     (((x) & PF_X) ? PROT_EXEC  : 0))


/**
 * Context structure for the ELF loader.
 **/
typedef struct elfldr_ctx {
  uint8_t* elf;
  pid_t    pid;

  intptr_t base_addr;
  size_t   base_size;
  void*    base_mirror;
} elfldr_ctx_t;


/**
 * Absolute path to the SceSpZeroConf eboot.
 **/
static const char* SceSpZeroConf = "/system/vsh/app/NPXS40112/eboot.bin";


int sceKernelSpawn(int *pid, int dbg, const char *path, char *root, char** argv);


/**
* Parse a R_X86_64_RELATIVE relocatable.
**/
static int
r_relative(elfldr_ctx_t *ctx, Elf64_Rela* rela) {
  intptr_t* loc = ctx->base_mirror + rela->r_offset;
  intptr_t val = ctx->base_addr + rela->r_addend;

  *loc = val;

  return 0;
}


/**
 * Parse a PT_LOAD program header.
 **/
static int
pt_load(elfldr_ctx_t *ctx, Elf64_Phdr *phdr) {
  void* data = ctx->base_mirror + phdr->p_vaddr;

  if(!phdr->p_memsz) {
    return 0;
  }

  if(!phdr->p_filesz) {
    return 0;
  }

  memcpy(data, ctx->elf+phdr->p_offset, phdr->p_filesz);

  return 0;
}


/**
 * Reload a PT_LOAD program header with executable permissions.
 **/
static int
pt_reload(elfldr_ctx_t *ctx, Elf64_Phdr *phdr) {
  intptr_t addr = ctx->base_addr + phdr->p_vaddr;
  void* data = ctx->base_mirror + phdr->p_vaddr;
  size_t memsz = ROUND_PG(phdr->p_memsz);
  int prot = PFLAGS(phdr->p_flags);
  int alias_fd = -1;
  int shm_fd = -1;
  int error = 0;

  // Create shm with executable permissions.
  if((shm_fd=pt_jitshm_create(ctx->pid, 0, memsz,
			      prot | PROT_READ | PROT_WRITE)) < 0) {
    pt_perror(ctx->pid, "pt_jitshm_create");
    error = -1;
  }

  // Map shm into an executable address space.
  else if((addr=pt_mmap(ctx->pid, addr, memsz, prot,
			MAP_FIXED | MAP_PRIVATE,
			shm_fd, 0)) == -1) {
    pt_perror(ctx->pid, "pt_mmap");
    error = -1;
  }

  // Create an shm alias fd with write permissions.
  else if((alias_fd=pt_jitshm_alias(ctx->pid, shm_fd,
				    PROT_READ | PROT_WRITE)) < 0) {
    pt_perror(ctx->pid, "pt_jitshm_alias");
    error = -1;
  }

  // Map shm alias into a writable address space.
  else if((addr=pt_mmap(ctx->pid, 0, memsz, PROT_READ | PROT_WRITE,
			MAP_SHARED, alias_fd, 0)) == -1) {
    pt_perror(ctx->pid, "pt_mmap");
    error = -1;
  }

  // Resore data
  else {
    if(mdbg_copyin(ctx->pid, data, addr, memsz)) {
      perror("mdbg_copyin");
      error = -1;
    }
    pt_munmap(ctx->pid, addr, memsz);
  }

  pt_close(ctx->pid, alias_fd);
  pt_close(ctx->pid, shm_fd);

  return error;
}


/**
 * Load an ELF into the address space of a process with the given pid.
 **/
static intptr_t
elfldr_load(pid_t pid, uint8_t *elf) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf;
  Elf64_Phdr *phdr = (Elf64_Phdr*)(elf + ehdr->e_phoff);
  Elf64_Shdr *shdr = (Elf64_Shdr*)(elf + ehdr->e_shoff);

  elfldr_ctx_t ctx = {.elf = elf, .pid=pid};

  size_t min_vaddr = -1;
  size_t max_vaddr = 0;

  int error = 0;

  // Sanity check, we only support 64bit ELFs.
  if(ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
     ehdr->e_ident[2] != 'L'  || ehdr->e_ident[3] != 'F') {
    puts("elfldr_load: Malformed ELF file");
    return 0;
  }

  // Compute size of virtual memory region.
  for(int i=0; i<ehdr->e_phnum; i++) {
    if(phdr[i].p_vaddr < min_vaddr) {
      min_vaddr = phdr[i].p_vaddr;
    }

    if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
      max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
  }

  min_vaddr = TRUNC_PG(min_vaddr);
  max_vaddr = ROUND_PG(max_vaddr);
  ctx.base_size = max_vaddr - min_vaddr;

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  int prot = PROT_READ | PROT_WRITE;
  if(ehdr->e_type == ET_DYN) {
    ctx.base_addr = 0;
  } else if(ehdr->e_type == ET_EXEC) {
    ctx.base_addr = min_vaddr;
    flags |= MAP_FIXED;
  } else {
    puts("elfldr_load: ELF type not supported");
    return 0;
  }

  // Reserve an address space of sufficient size.
  if((ctx.base_addr=pt_mmap(pid, ctx.base_addr, ctx.base_size, prot,
			    flags, -1, 0)) == -1) {
    pt_perror(pid, "pt_mmap");
    return 0;
  }
  if((ctx.base_mirror=mmap(0, ctx.base_size, prot, flags,
			   -1, 0)) == MAP_FAILED) {
    pt_munmap(pid, ctx.base_addr, ctx.base_size);
    perror("mmap");
    return 0;
  }

  // Parse program headers.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    switch(phdr[i].p_type) {
    case PT_LOAD:
      error = pt_load(&ctx, &phdr[i]);
      break;
    }
  }

  // Apply relocations.
  for(int i=0; i<ehdr->e_shnum && !error; i++) {
    if(shdr[i].sh_type != SHT_RELA) {
      continue;
    }

    Elf64_Rela* rela = (Elf64_Rela*)(elf + shdr[i].sh_offset);
    for(int j=0; j<shdr[i].sh_size/sizeof(Elf64_Rela); j++) {
      switch(rela[j].r_info & 0xffffffffl) {
      case R_X86_64_RELATIVE:
	error = r_relative(&ctx, &rela[j]);
	break;
      }
    }
  }

  if(mdbg_copyin(ctx.pid, ctx.base_mirror, ctx.base_addr, ctx.base_size)) {
    perror("mdbg_copyin");
    error = 1;
  }

  // Set protection bits on mapped segments.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(phdr[i].p_flags & PF_X) {
      error = pt_reload(&ctx, &phdr[i]);
    } else {
      if(pt_mprotect(pid, ctx.base_addr + phdr[i].p_vaddr,
		     ROUND_PG(phdr[i].p_memsz),
		     PFLAGS(phdr[i].p_flags))) {
	pt_perror(pid, "pt_mprotect");
	error = 1;
      }
    }
  }

  if(pt_msync(pid, ctx.base_addr, ctx.base_size, MS_SYNC)) {
    pt_perror(pid, "pt_msync");
    error = 1;
  }

  munmap(ctx.base_mirror, ctx.base_size);
  if(error) {
    pt_munmap(pid, ctx.base_addr, ctx.base_size);
    return 0;
  }

  return ctx.base_addr + ehdr->e_entry;
}


/**
 * Create payload args in the address space of the process with the given pid.
 **/
static intptr_t
elfldr_payload_args(pid_t pid) {
  int victim_sock;
  int master_sock;
  intptr_t buf;
  int pipe0;
  int pipe1;

  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    pt_perror(pid, "pt_mmap");
    return 0;
  }

  if((master_sock=pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    pt_perror(pid, "pt_socket");
    return 0;
  }

  mdbg_setint(pid, buf+0x00, 20);
  mdbg_setint(pid, buf+0x04, IPPROTO_IPV6);
  mdbg_setint(pid, buf+0x08, IPV6_TCLASS);
  mdbg_setint(pid, buf+0x0c, 0);
  mdbg_setint(pid, buf+0x10, 0);
  mdbg_setint(pid, buf+0x14, 0);
  if(pt_setsockopt(pid, master_sock, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf, 24)) {
    pt_perror(pid, "pt_setsockopt");
    return 0;
  }

  if((victim_sock=pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    pt_perror(pid, "pt_socket");
    return 0;
  }

  mdbg_setint(pid, buf+0x00, 0);
  mdbg_setint(pid, buf+0x04, 0);
  mdbg_setint(pid, buf+0x08, 0);
  mdbg_setint(pid, buf+0x0c, 0);
  mdbg_setint(pid, buf+0x10, 0);
  if(pt_setsockopt(pid, victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20)) {
    pt_perror(pid, "pt_setsockopt");
    return 0;
  }

  if(kernel_overlap_sockets(pid, master_sock, victim_sock)) {
    puts("kernel_overlap_sockets failed");
    return 0;
  }

  if(pt_pipe(pid, buf)) {
    pt_perror(pid, "pt_pipe");
    return 0;
  }
  pipe0 = pt_getint(pid, buf);
  pipe1 = pt_getint(pid, buf+4);

  intptr_t args       = buf;
  intptr_t rwpipe     = buf + 0x100;
  intptr_t rwpair     = buf + 0x200;
  intptr_t kpipe_addr = kernel_get_proc_file(pid, pipe0);
  intptr_t payloadout = buf + 0x300;

  // sys_dynlib_dlsym is invoked at <sceKernelDlsym+4>: e8 xx xx xx xx ; call rel32
  intptr_t dlsym = pt_resolve(pid, "LwG8g3niqwA") + 4;
  int32_t  rel32 = 0;
  mdbg_copyout(pid, dlsym+1, &rel32, sizeof(rel32));
  dlsym += rel32;
  dlsym += 5; // length of the call instruction

  mdbg_setlong(pid, args + 0x00, dlsym);
  mdbg_setlong(pid, args + 0x08, rwpipe);
  mdbg_setlong(pid, args + 0x10, rwpair);
  mdbg_setlong(pid, args + 0x18, kpipe_addr);
  mdbg_setlong(pid, args + 0x20, KERNEL_ADDRESS_DATA_BASE);
  mdbg_setlong(pid, args + 0x28, payloadout);
  mdbg_setint(pid, rwpipe + 0, pipe0);
  mdbg_setint(pid, rwpipe + 4, pipe1);
  mdbg_setint(pid, rwpair + 0, master_sock);
  mdbg_setint(pid, rwpair + 4, victim_sock);
  mdbg_setint(pid, payloadout, 0);

  return args;
}


int
elfldr_raise_privileges(pid_t pid) {
  static const uint8_t caps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
				   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  intptr_t vnode;

  if(!(vnode=kernel_get_root_vnode())) {
    return -1;
  }
  if(kernel_set_proc_rootdir(pid, vnode)) {
    return -1;
  }
  if(kernel_set_proc_jaildir(pid, 0)) {
    return -1;
  }
  if(kernel_set_ucred_uid(pid, 0)) {
    return -1;
  }
  if(kernel_set_ucred_caps(pid, caps)) {
    return -1;
  }

  return 0;
}


/**
 * Prepare registers of a process for execution of an ELF.
 **/
static int
elfldr_prepare_exec(pid_t pid, uint8_t *elf) {
  uint8_t call_rax[] = {0xff, 0xd0};
  intptr_t entry;
  intptr_t args;
  struct reg r;

  if(pt_getregs(pid, &r)) {
    perror("pt_getregs");
    return -1;
  }

  if(!(entry=elfldr_load(pid, elf))) {
    puts("elfldr_load failed");
    return -1;
  }

  if(!(args=elfldr_payload_args(pid))) {
    puts("elfldr_payload_args failed");
    return -1;
  }

  if(mdbg_copyin(pid, call_rax, r.r_rip, sizeof(call_rax))) {
    perror("mdbg_copyin");
    return -1;
  }

  r.r_rax = entry;
  r.r_rdi = args;

  if(pt_setregs(pid, &r)) {
    perror("pt_setregs");
    return -1;
  }

  return 0;
}


int
elfldr_set_heap_size(pid_t pid, ssize_t size) {
  intptr_t sceLibcHeapSize;
  intptr_t sceLibcParam;
  intptr_t sceProcParam;
  intptr_t Need_sceLibc;

  if(!(sceProcParam=pt_sceKernelGetProcParam(pid))) {
    pt_perror(pid, "pt_sceKernelGetProcParam");
    return -1;
  }

  if(mdbg_copyout(pid, sceProcParam+56, &sceLibcParam,
		  sizeof(sceLibcParam))) {
    perror("mdbg_copyout");
    return -1;
  }

  if(mdbg_copyout(pid, sceLibcParam+16, &sceLibcHeapSize,
		  sizeof(sceLibcHeapSize))) {
    perror("mdbg_copyout");
    return -1;
  }

  if(mdbg_setlong(pid, sceLibcHeapSize, size)) {
    perror("mdbg_setlong");
    return -1;
  }

  if(size != -1) {
    return 0;
  }

  if(mdbg_copyout(pid, sceLibcParam+72, &Need_sceLibc,
		  sizeof(Need_sceLibc))) {
    perror("mdbg_copyout");
    return -1;
  }

  return mdbg_setlong(pid, sceLibcParam+32, Need_sceLibc);
}


int
elfldr_set_cwd(pid_t pid, const char* cwd) {
  intptr_t buf;
  int err = 0;

  if(!cwd) {
    cwd = "/";
  }

  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    pt_perror(pid, "pt_mmap");
    return -1;
  }

  if(mdbg_copyin(pid, cwd, buf, strlen(cwd)+1)) {
    puts("mdbg_copyin() failed");
    err = -1;
  }
  else if (pt_syscall(pid, SYS_chdir, buf) < 0) {
    pt_perror(pid, "chdir");
    err = -1;
  }

  pt_msync(pid, buf, PAGE_SIZE, MS_SYNC);
  pt_munmap(pid, buf, PAGE_SIZE);

  return err;
}


int
elfldr_set_environ(pid_t pid, char** envp) {
  size_t size = sizeof(char*);
  intptr_t environ_addr = 0;
  intptr_t envp_addr = 0;
  intptr_t pos = 0;
  int n = 0;

  // no env variables defined
  if(!envp || !envp[0]) {
    return 0;
  }

  // compute needed memory size and number of variables
  while(envp[n]) {
    size += (8 + strlen(envp[n]) + 1);
    n++;
  }
  size = ROUND_PG(size);

  // allocate memory
  if((envp_addr=pt_mmap(pid, 0, size, PROT_WRITE | PROT_READ,
			MAP_ANONYMOUS | MAP_PRIVATE,
			-1, 0)) == -1) {
    pt_perror(pid, "pt_mmap");
    return -1;
  }

  // copy data
  pos = envp_addr + ((n + 1) * 8);
  for(int i=0; i<n; i++) {
    size_t len = strlen(envp[i]) + 1;

    // copy string
    if(mdbg_copyin(pid, envp[i], pos, len)) {
      perror("mdbg_copyin");
      pt_munmap(pid, envp_addr, size);
      return -1;
    }

    // copy pointer to string 
    if(mdbg_setlong(pid, envp_addr + (i*8), pos)) {
      perror("mdbg_setlong");
      pt_munmap(pid, envp_addr, size);
      return -1;
    }
    pos += len;
  }

  // null-terminate envp_addr
  if(mdbg_setlong(pid, envp_addr + (n*8), 0)) {
      perror("mdbg_setlong");
      pt_munmap(pid, envp_addr, size);
      return -1;
  }

  // resolve "environ"
  if(!(environ_addr=pt_resolve(pid, "+2thxYZ4syk"))) {
    perror("pt_resolve");
    pt_munmap(pid, envp_addr, size);
    return -1;
  }

  if(mdbg_setlong(pid, environ_addr, envp_addr)) {
    perror("mdbg_setlong");
    pt_munmap(pid, envp_addr, size);
    return -1;
  }

  return 0;
}


int
elfldr_set_procname(pid_t pid, const char* name) {
  intptr_t buf;

  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    pt_perror(pid, "pt_mmap");
    return -1;
  }

  mdbg_copyin(pid, name, buf, strlen(name)+1);
  pt_syscall(pid, SYS_thr_set_name, -1, buf);
  pt_msync(pid, buf, PAGE_SIZE, MS_SYNC);
  pt_munmap(pid, buf, PAGE_SIZE);

  return 0;
}


int
elfldr_set_stdio(pid_t pid, int stdio) {
  int err = 0;

  if(stdio >= 0) {
    if((stdio=pt_rdup(pid, getpid(), stdio)) < 0) {
      pt_perror(pid, "pt_rdup");
      err = -1;
    }
    else if(pt_dup2(pid, stdio, STDOUT_FILENO) < 0) {
      pt_perror(pid, "pt_dup2");
      err = -1;
    }
    else if(pt_dup2(pid, stdio, STDERR_FILENO) < 0) {
      pt_perror(pid, "pt_dup2");
      err = -1;
    }
    else if (pt_close(pid, stdio) < 0) {
      pt_perror(pid, "pt_close");
      err = -1;
    }
  }

  return err;
}


int
elfldr_exec(pid_t pid, uint8_t* elf) {
  uint8_t privcaps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  uint8_t orgcaps[16];

  if(kernel_get_ucred_caps(pid, orgcaps)) {
    puts("kernel_get_ucred_caps failed");
    return -1;
  }
  if(kernel_set_ucred_caps(pid, privcaps)) {
    puts("kernel_set_ucred_caps failed");
    return -1;
  }

  if(elfldr_prepare_exec(pid, elf)) {
    puts("elfldr_prepare_exec failed");
    return -1;
  }

  if(kernel_set_ucred_caps(pid, orgcaps)) {
    puts("kernel_set_ucred_caps failed");
    return -1;
  }

  if(pt_detach(pid, 0)) {
    perror("pt_detach");
    return -1;
  }

  return 0;
}


/**
 * Execute an ELF inside a new process.
 **/
pid_t
elfldr_spawn(const char* cwd, int stdio, uint8_t* elf, const char* name) {
  uint8_t int3instr = 0xcc;
  intptr_t brkpoint;
  uint8_t orginstr;
  pid_t pid = -1;
  char* argv[] = { (char*)"Spawner", NULL };

  if(sceKernelSpawn(&pid, 1, SceSpZeroConf, 0, argv)) {
    perror("sceKernelSpawn");
    return -1;
  }

  elfldr_raise_privileges(pid);

  // The proc is now in the STOP state, with the instruction pointer pointing
  // at the libkernel entry. Let the kernel assign process parameters accessed
  // via sceKernelGetProcParam()
  if(pt_syscall(pid, 599)) {
    puts("sys_dynlib_process_needed_and_relocate failed");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  // Allow libc to allocate arbitrary amount of memory.
  elfldr_set_heap_size(pid, -1);

  //Insert a breakpoint at the eboot entry.
  if(!(brkpoint=kernel_dynlib_entry_addr(pid, 0))) {
    puts("kernel_dynlib_entry_addr failed");
    pt_detach(pid, SIGKILL);
    return -1;
  }
  brkpoint += 58;// offset to invocation of main()
  if(mdbg_copyout(pid, brkpoint, &orginstr, sizeof(orginstr))) {
    perror("mdbg_copyout");
    pt_detach(pid, SIGKILL);
    return -1;
  }
  if(mdbg_copyin(pid, &int3instr, brkpoint, sizeof(int3instr))) {
    perror("mdbg_copyin");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  // Continue execution until we hit the breakpoint, then remove it.
  if(pt_continue(pid, SIGCONT)) {
    perror("pt_continue");
    pt_detach(pid, SIGKILL);
    return -1;
  }
  if(waitpid(pid, 0, 0) == -1) {
    perror("waitpid");
    pt_detach(pid, SIGKILL);
    return -1;
  }
  if(mdbg_copyin(pid, &orginstr, brkpoint, sizeof(orginstr))) {
    perror("mdbg_copyin");
    pt_detach(pid, SIGKILL);
    return -1;
  }


  elfldr_set_procname(pid, name);
  elfldr_set_cwd(pid, "/");
  elfldr_set_stdio(pid, stdio);

  // Execute the ELF
  if(elfldr_exec(pid, elf)) {
    kill(pid, SIGKILL);
    return -1;
  }

  elfldr_set_procname(pid, name);

  return pid;
}

