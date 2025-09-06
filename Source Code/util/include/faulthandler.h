#pragma once

#include <setjmp.h>

extern jmp_buf g_catch_buf;

void fault_handler_init(void (*cleanup_handler)(void));
