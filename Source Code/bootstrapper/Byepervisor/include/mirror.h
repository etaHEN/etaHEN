#ifndef MIRROR_H
#define MIRROR_H

void *mirror_page(uint64_t kernel_va);
void *mirror_page_no_store(uint64_t kernel_va);
void *mirror_page_range(uint64_t kernel_va, int num_pages);
void *get_mirrored_addr(uint64_t kernel_va);
void reset_mirrors();

#endif // MIRROR_H