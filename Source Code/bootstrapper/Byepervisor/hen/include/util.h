#pragma once
#ifndef UTIL_H
#define UTIL_H

#include <sys/types.h>

#define PAD_(t) (sizeof(register_t) <= sizeof(t) ? \
                    0 : sizeof(register_t) - sizeof(t))

uint64_t get_dmap_addr(uint64_t pa);

void *find_proc_by_name(const char *name);
void *get_proc_vmmap(void *proc);

void memcpy(void *dest, const void *src, size_t n);
size_t strlen(const char *str);
char *strstr(const char *str, const char *substring);
int strncmp(const char * s1, const char * s2, size_t n);
bool if_exists(const char * path);

extern void *curthread;

#endif // UTIL_H