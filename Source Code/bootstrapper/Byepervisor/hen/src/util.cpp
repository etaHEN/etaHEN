#include <stdint.h>
#include <stddef.h>		   

#include "kdlsym.h"
#include "proc.h"
#include "util.h"


static uint64_t g_dmap_base = 0;
void *curthread;

void init_dmap_resolve()
{
    uint32_t DMPML4I;
    uint32_t DMPDPI;

    DMPML4I = *(uint32_t *) (kdlsym(KERNEL_SYM_DMPML4I));
    DMPDPI  = *(uint32_t *) (kdlsym(KERNEL_SYM_DMPDPI));

    g_dmap_base = ((uint64_t) (DMPDPI) << 30) | ((uint64_t ) (DMPML4I) << 39) | 0xFFFF800000000000;
}

uint64_t get_dmap_addr(uint64_t pa)
{
    // Init dmap resolve if it's not initialized already
    if (g_dmap_base == 0)
        init_dmap_resolve();

    return g_dmap_base + pa;
}

void *find_proc_by_name(const char *name)
{
    void *p;
    char *proc_name;
    //int proc_pid;

    //auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);
    auto allproc = (void *) *(uint64_t *) kdlsym(KERNEL_SYM_ALLPROC);

    if (!name) {
        return NULL;
    }

    //printf("find_proc_by_name: proc0 = %p\n", allproc);

    p = allproc;
    while (p) {
        proc_name = (char *) ((char *) (p) + PROC_OFFSET_P_COMM);
        //proc_pid  = *(int *) ((char *) (p) + PROC_OFFSET_P_PID);
        //printf("  proc '%s' (pid: 0x%x)\n", proc_name, proc_pid);

        if (!strncmp(proc_name, name, strlen(name))) {
            return p;
        }

        p = (void *) *(uint64_t *) p;
    }

    return NULL;
}

void *get_proc_vmmap(void *p)
{
    return (void *) *(uint64_t *) ((char *) (p) + PROC_OFFSET_P_VMSPACE);
}

void memcpy(void *dest, const void *src, size_t n)
{
    char *csrc = (char *) src;
    char *cdest = (char *) dest;

    for (size_t i = 0; i < n; i++) {
        cdest[i] = csrc[i];
    }
}

size_t strlen(const char *str)
{
    const char *s;

    for (s = str; *s; s++) ;
    return (s - str);
}

char *strstr(const char *str, const char *substring)
{
    const char *a;
    const char *b;

    b = substring;

    if (*b == 0) {
        return (char *) str;
    }

    for ( ; *str != 0; str += 1) {
        if (*str != *b) {
            continue;
        }

        a = str;
        while (1) {
            if (*b == 0) {
                return (char *) str;
            }
            if (*a++ != *b++) {
                break;
            }
        }
        b = substring;
    }

    return NULL;
}

int strncmp(const char * s1, const char * s2, size_t n)
{
    while (n && *s1 && (*s1 == *s2)) {
        ++s1;
        ++s2;
        --n;
    }
    if (n == 0) {
        return 0;
    } else {
        return (*(unsigned char *) s1 - *(unsigned char *) s2);
    }
}
