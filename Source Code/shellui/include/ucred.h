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
#include <unistd.h>
#include "proc.h"

#define DEBUG_AUTHID 0x4800000000000006
#define PTRACE_AUTHID    0x4800000000010003
#define UCRED_AUTHID_KERNEL_OFFSET

// uintptr_t get_current_ucred();
uintptr_t set_ucred_to_debugger();
uintptr_t set_proc_authid(pid_t pid, uintptr_t new_authid);
uint8_t* jailbreak_process(pid_t pid);
void jail_process(pid_t pid, uint8_t* ucred);
