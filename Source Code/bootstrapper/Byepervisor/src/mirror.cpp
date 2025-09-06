#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "debug_log.h"
#include "kdlsym.h"
#include "mirror.h"
#include "paging.h"

#define MAX_MIRRORS                         0x100
#define UNUSED(x)                           (void) (x)

extern "C"
{
    int sceKernelUsleep(int usecs);
}

struct mirrored_page {
    uint64_t user_addr;
    uint64_t kernel_va;
    uint64_t kernel_pa;
    uint64_t orig_pa;
};

static struct mirrored_page g_mirrored_pages[MAX_MIRRORS];
int g_mirrored_page_index = 0;

void *mirror_page(uint64_t kernel_va)
{
    void *user_mirror;
    uint64_t pmap;
    uint64_t kernel_pa;
    uint64_t orig_pa;
    uint64_t pf_read;

    UNUSED(pf_read);

    // We can only do MAX_MIRRORS mirrors, this should be plenty
    if (g_mirrored_page_index >= MAX_MIRRORS) {
        //SOCK_LOG("[!] exceeded mirror limit\n");
        return NULL;
    }

    // Mask virtual address to page alignment and extract physical address
    kernel_va &= 0xFFFFFFFFFFFFF000;
    kernel_pa  = pmap_kextract(kernel_va);

    // Get process pmap
    pmap = get_proc_pmap();
    if (pmap == 0) {
        //SOCK_LOG("[!] failed to mirror 0x%lx due to failure to find proc\n", kernel_va);
        return NULL;
    }

    // Map a user page
    user_mirror = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_PREFAULT_READ, -1, 0);
    if (user_mirror == MAP_FAILED) {
        //SOCK_LOG("[!] failed to mirror 0x%lx due to mmap failure (%s)\n", kernel_va, strerror(errno));
        return NULL;
    }

    // Prefault page
    *(uint64_t *) (user_mirror) = 0x40404040;
    pf_read = *(uint64_t *) (user_mirror);

    sceKernelUsleep(50000);

    orig_pa = remap_page(pmap, (uint64_t) user_mirror, kernel_pa);
    if (orig_pa == 0xFFFFFFFFFFFFFFFFull) {
        //SOCK_LOG("[!] failed to mirror 0x%lx due to failure to remap page\n", kernel_va);
        return NULL;
    }

    // Store for later for lookup & restore
    g_mirrored_pages[g_mirrored_page_index].user_addr = (uint64_t) user_mirror;
    g_mirrored_pages[g_mirrored_page_index].kernel_va = kernel_va;
    g_mirrored_pages[g_mirrored_page_index].kernel_pa = kernel_pa;
    g_mirrored_pages[g_mirrored_page_index].orig_pa   = orig_pa;
    g_mirrored_page_index++;

    return user_mirror;
}

void *mirror_page_no_store(uint64_t kernel_va)
{
    void *user_mirror;
    uint64_t pmap;
    uint64_t kernel_pa;
    uint64_t orig_pa;
    uint64_t pf_read;

    UNUSED(pf_read);

    // Mask virtual address to page alignment and extract physical address
    kernel_va &= 0xFFFFFFFFFFFFF000;
    kernel_pa  = pmap_kextract(kernel_va);

    // Get process pmap
    pmap = get_proc_pmap();
    if (pmap == 0) {
        //SOCK_LOG("[!] failed to mirror 0x%lx due to failure to find proc\n", kernel_va);
        return NULL;
    }

    // Map a user page
    user_mirror = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_PREFAULT_READ, -1, 0);
    if (user_mirror == MAP_FAILED) {
        //SOCK_LOG("[!] failed to mirror 0x%lx due to mmap failure (%s)\n", kernel_va, strerror(errno));
        return NULL;
    }

    // Prefault page
    *(uint64_t *) (user_mirror) = 0x40404040;
    pf_read = *(uint64_t *) (user_mirror);

    sceKernelUsleep(50000);

    orig_pa = remap_page(pmap, (uint64_t) user_mirror, kernel_pa);
    if (orig_pa == 0xFFFFFFFFFFFFFFFFull) {
        //SOCK_LOG("[!] failed to mirror 0x%lx due to failure to remap page\n", kernel_va);
        return NULL;
    }

    return user_mirror;
}

// TODO: fix this to make it actually.. work
void *mirror_page_range(uint64_t kernel_va, int num_pages)
{
    void *user_mirror;
    uint64_t pmap;
    uint64_t kernel_pa;
    uint64_t orig_pa;
    uint64_t pf_read;

    UNUSED(pf_read);

    // We can only do MAX_MIRRORS mirrors, this should be plenty
    if (g_mirrored_page_index >= MAX_MIRRORS) {
        //SOCK_LOG("[!] exceeded mirror limit\n");
        return NULL;
    }

    // Mask virtual address to page alignment and extract physical address
    kernel_va &= 0xFFFFFFFFFFFFF000;
    kernel_pa  = pmap_kextract(kernel_va);

    // Get process pmap
    pmap = get_proc_pmap();
    if (pmap == 0) {
        //SOCK_LOG("[!] failed to mirror 0x%lx due to failure to find proc\n", kernel_va);
        return NULL;
    }

    // Map a user region
    user_mirror = mmap(0, num_pages * 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_PREFAULT_READ, -1, 0);
    if (user_mirror == MAP_FAILED) {
        //SOCK_LOG("[!] failed to mirror 0x%lx due to mmap failure (%s)\n", kernel_va, strerror(errno));
        return NULL;
    }

    sceKernelUsleep(50000);

    for (int i = 0; i < num_pages; i++) {
        orig_pa = remap_page(pmap, (uint64_t) user_mirror + (i * 0x1000), kernel_pa + (i * 0x1000));
        if (orig_pa == 0xFFFFFFFFFFFFFFFFull) {
            //SOCK_LOG("[!] failed to mirror 0x%lx due to failure to remap page\n", kernel_va);
            return NULL;
        }
    }

    // TODO: store for later cleanup

    return user_mirror;
}

void *get_mirrored_addr(uint64_t kernel_va)
{
    uint64_t aligned_kernel_va;
    uint64_t aligned_kernel_pa;
    void *mirrored_addr;

    // Mask virtual address to page alignment and extract physical address
    aligned_kernel_va = kernel_va & 0xFFFFFFFFFFFFF000;
    aligned_kernel_pa = pmap_kextract(aligned_kernel_va);

    // Check if mirror already exists for this PA
    for (int i = 0; i < g_mirrored_page_index; i++) {
        if (g_mirrored_pages[i].kernel_pa == aligned_kernel_pa) {
            // Return existing mirror
            return (void *) (g_mirrored_pages[i].user_addr | (kernel_va & 0xFFF));
        }
    }

    // If one doesn't, create one
    mirrored_addr = mirror_page(aligned_kernel_va);

    return (void *) ((uint64_t) mirrored_addr | (kernel_va & 0xFFF));
}

void reset_mirrors()
{
    uint64_t pmap;
    uint64_t va;
    uint64_t pa;

    pmap = get_proc_pmap();
    if (pmap == 0) {
        //SOCK_LOG("[!] failed to reset mirrors due to failure to find proc\n");
        return;
    }

    for (int i = 0; i < g_mirrored_page_index; i++) {
        va = g_mirrored_pages[i].user_addr;
        pa = g_mirrored_pages[i].orig_pa;
        remap_page(pmap, va, pa);
        bzero(&g_mirrored_pages[i], sizeof(struct mirrored_page));
    }

    g_mirrored_page_index = 0;
}