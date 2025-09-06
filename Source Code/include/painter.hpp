#pragma once
#include <stdint.h>

// base types

typedef uint8_t  u8,  U8;
typedef uint16_t u16, U16;
typedef uint32_t u32, U32;
typedef uint64_t u64, U64;

typedef int8_t  s8,  S8;
typedef int16_t s16, S16;
typedef int32_t s32, S32;
typedef int64_t s64, S64;

typedef float  f32, F32;
typedef double f64, F64;


typedef U64 unat, unat_t;	// 'Natural' sized base types, PS4 is x64 no check req.
typedef S64 snat, snat_t;

typedef unat  addr_t;




typedef int32_t sce_error;


// constexpr helpers

template<typename T> constexpr T KB(const T n) { return 1024 * n; }
template<typename T> constexpr T MB(const T n) { return 1024 * KB(n); }
template<typename T> constexpr T GB(const T n) { return 1024 * MB(n); }
template<typename T> constexpr T TB(const T n) { return 1024 * GB(n); }



#define INLINE inline // __forceinline__


// Generic Alignment for non pow2, up is abuseable since it's an integer :)

template<typename T> INLINE T Align(const T addr, const T align, unat up = 0)
{
	return (addr / align + up) * align;
}

// Alignment for unsigned integers of any type, align must be pow2!

#define POW2_MASK (align - static_cast<T>(1))

template<typename T> INLINE T AlignUp(const T addr, const T align)
{
	return (addr + POW2_MASK) & ~POW2_MASK;
}

template<typename T> INLINE T AlignDown(const T addr, const T align)
{
	return addr & ~POW2_MASK;
}

//#define alignTo		Align
#define alignUp		AlignUp
#define alignDown	AlignDown

class Painter
{
public:
  u32* fb;
  u32 col;

  enum Color { RED, WHITE, MAGENTA, DARK_BLUE, 
	       GREEN, BROWN, CYAN, BLACK };
  void rect(int x1, int y1, int x2, int y2);
  void setColor(Color);
};
