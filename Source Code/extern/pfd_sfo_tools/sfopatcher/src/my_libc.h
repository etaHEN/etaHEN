#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

// libc

void *malloc(size_t size);
void free(void *ptr);
#define memset __builtin_memset
//void *memset( void * ptr, int value, size_t num );
size_t strnlen(const char *s, size_t maxlen);

#ifdef __cplusplus
}
#endif
