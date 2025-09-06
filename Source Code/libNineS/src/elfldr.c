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
#include <sys/signal.h>
#include <sys/sysctl.h>

#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>
#include <ps5/mdbg.h>

#include "../include/elfldr.h"
#include "../include/pt.h"
#include "../../lib/libmprotect.h" // kernel_mprotect implementation

// extern int kernel_mprotect(int pid, unsigned long addr, unsigned long len, int prot);

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


int sceKernelSpawn(int *pid, int dbg, const char *path, char *root, const char* argv[]);


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


int
elfldr_sanity_check(uint8_t *elf, size_t elf_size) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf;
  Elf64_Phdr *phdr;

  if(elf_size < sizeof(Elf64_Ehdr) ||
     elf_size < sizeof(Elf64_Phdr) + ehdr->e_phoff ||
     elf_size < sizeof(Elf64_Shdr) + ehdr->e_shoff) {
    return -1;
  }

  if(ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
     ehdr->e_ident[2] != 'L'  || ehdr->e_ident[3] != 'F') {
    return -1;
  }

  phdr = (Elf64_Phdr*)(elf + ehdr->e_phoff);
  for(int i=0; i<ehdr->e_phnum; i++) {
    if(phdr[i].p_offset + phdr[i].p_filesz > elf_size) {
      return -1;
    }
  }

  return 0;
}


/**
 * Load an ELF into the address space of a process with the given pid.
 **/
intptr_t
elfldr_load(pid_t pid, uint8_t *elf) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf;
  Elf64_Phdr *phdr = (Elf64_Phdr*)(elf + ehdr->e_phoff);
  Elf64_Shdr *shdr = (Elf64_Shdr*)(elf + ehdr->e_shoff);

  elfldr_ctx_t ctx = {.elf = elf, .pid=pid};

  size_t min_vaddr = -1;
  size_t max_vaddr = 0;

  int error = 0;

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
    klog_puts("elfldr_load: ELF type not supported");
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
    klog_perror("mmap");
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
    klog_perror("mdbg_copyin");
    error = 1;
  }

  // Set protection bits on mapped segments.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(phdr[i].p_flags & PF_X) {
      if(kernel_mprotect(pid, ctx.base_addr + phdr[i].p_vaddr,
                         ROUND_PG(phdr[i].p_memsz),
                         PFLAGS(phdr[i].p_flags))) {
	perror("kernel_mprotect");
      }
    } else {
      if(kernel_mprotect(pid, ctx.base_addr + phdr[i].p_vaddr,
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
intptr_t
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
    klog_puts("kernel_overlap_sockets failed");
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


/**
 * Prepare registers of a process for execution of an ELF.
 **/
int
elfldr_prepare_exec(pid_t pid, uint8_t *elf) {
  uint16_t call_rax = 0xd0ff;
  uint16_t org_inst;
  intptr_t entry;
  intptr_t args;
  struct reg r;

  if(pt_getregs(pid, &r)) {
    klog_perror("pt_getregs");
    return -1;
  }

  if(!(entry=elfldr_load(pid, elf))) {
    klog_puts("elfldr_load failed");
    return -1;
  }

  if(!(args=elfldr_payload_args(pid))) {
    klog_puts("elfldr_payload_args failed");
    return -1;
  }

  // backup next instruction
  if(mdbg_copyout(pid, r.r_rip, &org_inst, sizeof(org_inst))) {
    perror("mdbg_copyout");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  // replace next instruction with a call to rax
  if(mdbg_copyin(pid, &call_rax, r.r_rip, sizeof(call_rax))) {
    perror("mdbg_copyin");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  r.r_rax = entry;
  r.r_rdi = args;

  if(pt_setregs(pid, &r)) {
    klog_perror("pt_setregs");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  // call entry pointed at from rax
  if(pt_step(pid)) {
    klog_perror("pt_step");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  // restore next instruction
  if(mdbg_copyin(pid, &org_inst, r.r_rip, sizeof(org_inst))) {
    perror("mdbg_copyin");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  return 0;
}

/**
 * Escape jail and raise privileges.
 **/
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
 * Execute an ELF inside the process with the given pid.
 **/
int elfldr_exec(pid_t pid, int stdio, uint8_t* elf) {
  uint8_t caps[16];
  intptr_t jaildir;
  intptr_t rootdir;
  uint64_t authid;
  int error = 0;

//   // backup privileges
   jaildir = kernel_get_proc_jaildir(pid);
   if(!(rootdir=kernel_get_proc_rootdir(pid))) {
     klog_puts("kernel_get_proc_rootdir failed");
     pt_detach(pid);
     return -1;
   }
   if(kernel_get_ucred_caps(pid, caps)) {
     klog_puts("kernel_get_ucred_caps failed");
     pt_detach(pid);
     return -1;
   }
   if(!(authid=kernel_get_ucred_authid(pid))) {
     klog_puts("kernel_get_ucred_authid failed");
     pt_detach(pid);
     return -1;
   }

   if(elfldr_raise_privileges(pid)) {
     klog_puts("Unable to raise privileges");
     pt_detach(pid);
     return -1;
   }

   if(stdio > 0) {
     stdio = pt_rdup(pid, getpid(), stdio);

     pt_close(pid, STDERR_FILENO);
     pt_close(pid, STDOUT_FILENO);
     pt_close(pid, STDIN_FILENO);

     pt_dup2(pid, stdio, STDIN_FILENO);
     pt_dup2(pid, stdio, STDOUT_FILENO);
     pt_dup2(pid, stdio, STDERR_FILENO);

     pt_close(pid, stdio);
   }

   if(elfldr_prepare_exec(pid, elf)) {
     error = -1;
   }

   // restore privileges
   if(kernel_set_proc_jaildir(pid, jaildir)) {
     klog_puts("kernel_set_proc_jaildir failed");
     error = -1;
   }
   if(kernel_set_proc_rootdir(pid, rootdir)) {
     klog_puts("kernel_set_proc_rootdir failed");
     error = -1;
   }

   if(kernel_set_ucred_caps(pid, caps)) {
     klog_puts("kernel_set_ucred_caps failed");
     error = -1;
   }
   if(kernel_set_ucred_authid(pid, authid)) {
     klog_puts("kernel_set_ucred_authid failed");
     error = -1;
   }

   if(pt_detach(pid)) {
     klog_perror("pt_detach");
     error = -1;
   }

   return error;
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

/**
 * Set the name of a process.
 **/
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
/**
 * Execute an ELF inside a new process.
 **/
pid_t
elfldr_spawn(const char* cwd, int stdio, uint8_t* elf, const char* name) {
  uint8_t int3instr = 0xcc;
  intptr_t brkpoint;
  uint8_t orginstr;
  pid_t pid = -1;
  const char* argv[] = { (char*)"Spawner", NULL };

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
    pt_detach(pid);
    kill(pid, SIGKILL);
    return -1;
  }

  // Allow libc to allocate arbitrary amount of memory.
  elfldr_set_heap_size(pid, -1);

  //Insert a breakpoint at the eboot entry.
  if(!(brkpoint=kernel_dynlib_entry_addr(pid, 0))) {
    puts("kernel_dynlib_entry_addr failed");
    pt_detach(pid);
    kill(pid, SIGKILL);
    return -1;
  }
  brkpoint += 58;// offset to invocation of main()
  if(mdbg_copyout(pid, brkpoint, &orginstr, sizeof(orginstr))) {
    perror("mdbg_copyout");
    pt_detach(pid);
    kill(pid, SIGKILL);
    return -1;
  }
  if(mdbg_copyin(pid, &int3instr, brkpoint, sizeof(int3instr))) {
    perror("mdbg_copyin");
    pt_detach(pid);
    kill(pid, SIGKILL);
    return -1;
  }

  // Continue execution until we hit the breakpoint, then remove it.
  if(pt_continue(pid, SIGCONT)) {
    perror("pt_continue");
    pt_detach(pid);
    kill(pid, SIGKILL);
    return -1;
  }
  if(waitpid(pid, 0, 0) == -1) {
    perror("waitpid");
    pt_detach(pid);
    kill(pid, SIGKILL);
    return -1;
  }
  if(mdbg_copyin(pid, &orginstr, brkpoint, sizeof(orginstr))) {
    perror("mdbg_copyin");
    pt_detach(pid);
    kill(pid, SIGKILL);
    return -1;
  }


  elfldr_set_procname(pid, name);
  elfldr_set_cwd(pid, "/");
  elfldr_set_stdio(pid, stdio);

  // Execute the ELF
  if(elfldr_exec(pid, stdio, elf)) {
    kill(pid, SIGKILL);
    return -1;
  }

  return pid;
}

/**
 * Fint the pid of a process with the given name.
 **/
pid_t
elfldr_find_pid(const char* name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t mypid = getpid();
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    klog_perror("sysctl");
    return -1;
  }

  if(!(buf=malloc(buf_size))) {
    klog_perror("malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    klog_perror("sysctl");
    free(buf);
    return -1;
  }

  for(uint8_t *ptr=buf; ptr<(buf+buf_size);) {
    int ki_structsize = *(int*)ptr;
    pid_t ki_pid = *(pid_t*)&ptr[72];
    char *ki_tdname = (char*)&ptr[447];

    ptr += ki_structsize;
    if(!strcmp(name, ki_tdname) && ki_pid != mypid) {
      pid = ki_pid;
    }
  }

  free(buf);

  return pid;
}
