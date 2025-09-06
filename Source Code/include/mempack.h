#ifndef MEMPACK_H
#define MEMPACK_H

#include "global.h"

struct Mempack
{
    // 16 bytes
    const char* name;       // Which pack we are using
    int64_t packSize;       // Ammount of bytes in pack
    char* start;            // first byte in allocator
    
    // 16 bytes
    char* end;              // last byte in allocator
    char* firstFreeByte;    // low-side allocation
    char* lastFreeByte;     // end-side allocation
    
    // 16 bytes
    int64_t sizePrevAlloc;  // self-explanatory
    int numBookmarks;	    // amount of bookmarks used
    int unusedPadding4;     // for /Wall warnings
    
    char* bookmarks[16];    // address of each bookmark
};


void MEMPACK_Init_func(struct Mempack* mp, void* start, int64_t size, const char* name);

int64_t MEMPACK_NumFreeBytes(struct Mempack* mp);

void* MEMPACK_AllocMem_func(struct Mempack* mp, int64_t size, const char* name);

void MEMPACK_AlignUp_func(struct Mempack* mp, int64_t align, const char* name);

// This probably wont be used, but here it is if it's wanted,
// even in Crash Team Racing it's only used twice (as far as we know)
void* MEMPACK_AllocHighMem_func(struct Mempack* mp, int64_t size, const char* name);

void MEMPACK_AlignDown_func(struct Mempack* mp, int64_t align, const char* name);

void MEMPACK_EraseHighEnd(struct Mempack* mp);

// This erases the previous allocation, and replaces it with another one
void* MEMPACK_ReallocMem_func(struct Mempack* mp, int64_t size, const char* name);

// Add a bookmark
void MEMPACK_PushState(struct Mempack* mp);

// erase all memory
void MEMPACK_Clean(struct Mempack* mp);

void MEMPACK_PopState(struct Mempack* mp);

// Crash Team Racing only used it once
void MEMPACK_PopToState(struct Mempack* mp, int state);

#if (CONSOLE_ENABLE == 1)

#define MEMPACK_Init(a,b,c,d)       MEMPACK_Init_func(a,b,c,d)
#define MEMPACK_AllocMem(a,b,c)     MEMPACK_AllocMem_func(a,b,c)
#define MEMPACK_AlignUp(a,b,c)      MEMPACK_AlignUp_func(a,b,c)
#define MEMPACK_AllocHighMem(a,b,c) MEMPACK_AllocHighMem_func(a,b,c)
#define MEMPACK_AlignDown(a,b,c)    MEMPACK_AlignDown_func(a,b,c)
#define MEMPACK_ReallocMem(a,b,c)   MEMPACK_ReallocMem_func(a,b,c)

#else

#define MEMPACK_Init(a,b,c,d)       MEMPACK_Init_func(a,b,c,0)
#define MEMPACK_AllocMem(a,b,c)     MEMPACK_AllocMem_func(a,b,0)
#define MEMPACK_AlignUp(a,b,c)      MEMPACK_AlignUp_func(a,b,0)
#define MEMPACK_AllocHighMem(a,b,c) MEMPACK_AllocHighMem_func(a,b,0)
#define MEMPACK_AlignDown(a,b,c)    MEMPACK_AlignDown_func(a,b,0)
#define MEMPACK_ReallocMem(a,b,c)   MEMPACK_ReallocMem_func(a,b,0)

#endif

#endif