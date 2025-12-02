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

#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <machine/reg.h>


int pt_attach(pid_t pid);
int pt_detach(pid_t pid, int sig);
int pt_step(pid_t pid);
int pt_continue(pid_t pid, int sig);

int pt_getregs(pid_t pid, struct reg *r);
int pt_setregs(pid_t pid, const struct reg *r);

int pt_copyin(pid_t pid, const void* buf, intptr_t addr, size_t len);
int pt_copyout(pid_t pid, intptr_t addr, void* buf, size_t len);

int pt_setchar(pid_t pid, intptr_t addr, char val);
int pt_setshort(pid_t pid, intptr_t addr, short val);
int pt_setint(pid_t pid, intptr_t addr, int val);
int pt_setlong(pid_t pid, intptr_t addr, long val);

char  pt_getchar(pid_t pid, intptr_t addr);
short pt_getshort(pid_t pid, intptr_t addr);
int   pt_getint(pid_t pid, intptr_t addr);
long  pt_getlong(pid_t pid, intptr_t addr);

long pt_syscall(pid_t pid, int sysno, ...);
intptr_t pt_resolve(pid_t pid, const char* nid);

intptr_t pt_mmap(pid_t pid, intptr_t addr, size_t len, int prot, int flags,
		 int fd, off_t off);
int pt_msync(pid_t, intptr_t addr, size_t len, int flags);
int pt_munmap(pid_t pid, intptr_t addr, size_t len);
int pt_mprotect(pid_t pid, intptr_t addr, size_t len, int prot);

int pt_socket(pid_t pid, int domain, int type, int protocol);
int pt_setsockopt(pid_t pid, int fd, int level, int optname, intptr_t optval,
		  uint32_t optlen);
int pt_bind(pid_t pid, int sockfd, intptr_t addr, uint32_t addrlen) ;
ssize_t pt_recvmsg(pid_t pid, int fd, intptr_t msg, int flags);

int pt_close(pid_t pid, int fd);

int pt_dup2(pid_t pid, int oldfd, int newfd);
int pt_rdup(pid_t pid, pid_t other_pid, int fd);
int pt_pipe(pid_t pid, intptr_t pipefd);
int pt_errno(pid_t pid);


long pt_call(pid_t pid, intptr_t addr, ...);
long pt_call2(pid_t pid, intptr_t addr, ...);

intptr_t pt_sceKernelGetProcParam(pid_t pid);