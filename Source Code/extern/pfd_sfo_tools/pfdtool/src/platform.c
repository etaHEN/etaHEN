#include "platform.h"
#include "types.h"

#if defined(_WIN32)
#	include <windows.h>
#	include <io.h>
#endif

u64 get_page_size(void) {
	static u64 page_size = 0;
	if (!page_size) {
#if defined(_WIN32)
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		page_size = (u32)info.dwPageSize;
#else
		page_size = getpagesize();
#endif
	}
	return page_size;
}

#if defined(_WIN32)
	void * mmap(void *start, size_t size, int protection, int flags, int fd, ptrdiff_t offset) {
		HANDLE map_handle;

		if (start || !(flags & MAP_PRIVATE))
			return NULL;
		if (offset % get_page_size() != 0)
			return NULL;

		map_handle = CreateFileMapping((HANDLE)_get_osfhandle(fd), NULL, PAGE_WRITECOPY, 0, 0, NULL);
		if (map_handle)
			start = MapViewOfFile(map_handle, FILE_MAP_COPY, 0, offset, size);

		return start;
	}

	int munmap(void *start, size_t size) {
		if (UnmapViewOfFile(start) != 0)
			return -1;

	  return 0;
	}
#endif
