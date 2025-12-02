#include <sys/types.h>
#include <sys/elf64.h>

// errors only
#define SELF_PAGER_DO_LOGGING 1

// these return the same values as mmap, but errno may be ENOSYS if the current firmware is not supported
void *mmap_self(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
void *map_self_segment(int fd, Elf64_Phdr *phdr, int segment_index);

// these are the return values for decrypt_self
#define DECRYPT_ERROR_IO -2
#define DECRYPT_ERROR_INTERNAL -3
#define DECRYPT_ERROR_UNSUPPORTED_FW -4
#define DECRYPT_ERROR_INPUT_NOT_SELF -5
// this happens if you try to decrypt an fself or a self with unavailable keys
#define DECRYPT_ERROR_FAILED_TO_DECRYPT_SEGMENT_DATA -6

// on success returns a pointer to the decrypted elf in out_data, you must free this with munmap
int decrypt_self(int input_file_fd, char **out_data, uint64_t *out_size);