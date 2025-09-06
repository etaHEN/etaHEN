#ifndef _TYPES_H_
#define _TYPES_H_

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#	if !defined(WIN32_LEAN_AND_MEAN)
#		define WIN32_LEAN_AND_MEAN
#	endif
#	include <windows.h>
#	include <io.h>
#
#	define snprintf _snprintf
#	define fileno _fileno
#	define strncasecmp strnicmp
#else
#	include <unistd.h>
#	include <sys/mman.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>

#if !defined(MAX_PATH)
#	define MAX_PATH 260
#endif

#ifdef min
#	undef min
#endif
#ifdef max
#	undef max
#endif

#if defined(_WIN32) && defined(_MSC_VER)
	typedef __int64 s64;
	typedef unsigned __int64 u64;
#else
	typedef int64_t s64;
	typedef uint64_t u64;
#endif

typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint8_t u8;
typedef int8_t s8;

#define ES16(_val) \
	((u16)(((((u16)_val) & 0xff00) >> 8) | \
	       ((((u16)_val) & 0x00ff) << 8)))

#define ES32(_val) \
	((u32)(((((u32)_val) & 0xff000000) >> 24) | \
	       ((((u32)_val) & 0x00ff0000) >> 8 ) | \
	       ((((u32)_val) & 0x0000ff00) << 8 ) | \
	       ((((u32)_val) & 0x000000ff) << 24)))

#define ES64(_val) \
	((u64)(((((u64)_val) & 0xff00000000000000ull) >> 56) | \
	       ((((u64)_val) & 0x00ff000000000000ull) >> 40) | \
	       ((((u64)_val) & 0x0000ff0000000000ull) >> 24) | \
	       ((((u64)_val) & 0x000000ff00000000ull) >> 8 ) | \
	       ((((u64)_val) & 0x00000000ff000000ull) << 8 ) | \
	       ((((u64)_val) & 0x0000000000ff0000ull) << 24) | \
	       ((((u64)_val) & 0x000000000000ff00ull) << 40) | \
	       ((((u64)_val) & 0x00000000000000ffull) << 56)))

#define countof(_array) (sizeof(_array) / sizeof(_array[0]))
#define offsetof(_type, _member) ((size_t)((char *)&((_type *)0)->_member - (char *)0))

#define min(_a, _b) ((_a) < (_b) ? (_a) : (_b))
#define max(_a, _b) ((_a) > (_b) ? (_a) : (_b))

#endif /* !_TYPES_H_ */
