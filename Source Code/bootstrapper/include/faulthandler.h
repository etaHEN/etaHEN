#pragma once

#include <setjmp.h>

extern jmp_buf g_catch_buf;

#if defined __cplusplus
extern "C"  {
#endif

void fault_handler_init(void (*cleanup_handler)(void));

#if defined __cplusplus
}
#endif
