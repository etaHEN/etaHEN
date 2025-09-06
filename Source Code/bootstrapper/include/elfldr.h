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

#include <unistd.h>


/**
 * Escape jail and raise privileges.
 **/
int elfldr_raise_privileges(pid_t pid);


/**
 * Execute an ELF inside a new process.
 **/
pid_t elfldr_spawn(const char* cwd, int stdio, uint8_t* elf, const char* name);

/**
 * Execute an ELF inside the process with the given pid.
 **/
int elfldr_exec(pid_t pid, uint8_t* elf);


/**
 * Set environmental variables in the given process.
 **/
int elfldr_set_environ(pid_t pid, char** envp);


/**
 * Set the name of a process.
 **/
int elfldr_set_procname(pid_t pid, const char* name);


/**
 * Set stdout and stderr file descriptors of the given process.
 **/
int elfldr_set_stdio(pid_t pid, int stdio);


/**
 * Set the current working directory.
 **/
int elfldr_set_cwd(pid_t pid, const char* cwd);


/**
 * Set the heap size for libc.
 **/
int elfldr_set_heap_size(pid_t pid, ssize_t size);
