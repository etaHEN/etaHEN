#pragma once

void etaHEN_log(const char *format, ...);

extern "C" {
	#include <stdio.h>
	size_t print_null(...);
}

#ifdef DEBUG
#define _puts(x) printf("%s:%d: %s\n", __PRETTY_FUNCTION__, __LINE__, x)
#define _printf(...) { \
	printf("%s:%d ", __PRETTY_FUNCTION__, __LINE__); \
	etaHEN_log(__VA_ARGS__); \
}
#define print_ret(func) printf("%s:%d: " #func ": 0x%08x\n", __PRETTY_FUNCTION__, __LINE__, func)
#else
#define _puts(x) print_null("%s:%d: %s\n", __PRETTY_FUNCTION__, __LINE__, x)
#define _printf(...) { \
	print_null("%s:%d ", __PRETTY_FUNCTION__, __LINE__); \
	etaHEN_log(__VA_ARGS__); \
}
#define print_ret(func) etaHEN_log("%s:%d: " #func ": 0x%08x\n", __PRETTY_FUNCTION__, __LINE__, func)
#endif
