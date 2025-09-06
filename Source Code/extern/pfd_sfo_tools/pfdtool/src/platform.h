#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#include "types.h"

u64 get_page_size(void);

#if defined(_WIN32)
#	define PROT_READ 1
#	define PROT_WRITE 2

#	define MAP_SHARED 2
#	define MAP_PRIVATE 3

	void * mmap(void *start, size_t size, int protection, int flags, int fd, ptrdiff_t offset);
	int munmap(void *start, size_t size);
#endif

#endif /* !_PLATFORM_H_ */
