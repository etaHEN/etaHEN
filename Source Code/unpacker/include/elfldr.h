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

pid_t elfldr_find_pid(const char* name);

pid_t elfldr_spawn(const char* progname, int stdio, uint8_t *elf);
int   elfldr_exec(pid_t pid, int stdio, uint8_t* elf);

int elfldr_raise_privileges(pid_t pid);
