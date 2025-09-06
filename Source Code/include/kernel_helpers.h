#pragma  once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

void kernel_init_rw(int master_sock, int victim_sock, int *rw_pipe, uint64_t pipe_addr);
int kernel_copyin(const void *uaddr, unsigned long kaddr, unsigned long len);
int kernel_copyout(unsigned long kaddr, void *uaddr, unsigned long len);

#ifdef __cplusplus
}
#endif
