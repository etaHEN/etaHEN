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
extern "C" {
#include "ucred.h"
#include "external_symbols.hpp"
#include "../lib/libmprotect.h"
#include <cstdint>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "ps5/mdbg.h"
}

#define HOOK_LENGTH 14
#define SYS_jitshm_create   0x215
#define SYS_jitshm_alias    0x216


void  PatchInJump(uint64_t address, void* destination);
void* DetourFunction(uint64_t address, void* destination);
void  WriteMemory(uint64_t address, void* buffer, int length);
int JITAlloc(size_t size, void** executableAddress, void** writableAddress); 