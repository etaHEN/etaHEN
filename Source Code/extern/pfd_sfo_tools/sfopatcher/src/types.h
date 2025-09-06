#ifndef _TYPES_H_
#define _TYPES_H_

#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#define LE16(_val) ((_val) & 0xffffu)
#define LE32(_val) ((_val) & 0xffffffffu)
#define LE64(_val) ((_val) & 0xffffffffffffffffu)

// sus
#ifdef offsetof
#undef offsetof
#endif

#define offsetof(_type, _member) \
     ((size_t)((char *)&((_type *)0)->_member - (char *)0))

#define countof(_array) (sizeof(_array) / sizeof(_array[0]))

#endif /* !_TYPES_H_ */
