#ifndef _UTIL_H_
#define _UTIL_H_

#include "types.h"

u64 x_to_u64(const char *hex);
u8 * x_to_u8_buffer(const char *hex);

void dump_data(const u8 *data, u64 size, FILE *fp);

int get_file_size(const char *file_path, u64 *size);
int read_file(const char *file_path, u8 *data, u64 size);
int write_file(const char *file_path, u8 *data, u64 size);
int mmap_file(const char *file_path, u8 **data, u64 *size);
int unmmap_file(u8 *data, u64 size);

int calculate_hmac_hash(const u8 *data, u64 size, const u8 *key, u32 key_length, u8 output[20]);
int calculate_file_hmac_hash(const char *file_path, const u8 *key, u32 key_length, u8 output[20]);

int wildcard_match(const char *data, const char *mask);
int wildcard_match_icase(const char *data, const char *mask);

u64 align_to_pow2(u64 offset, u64 alignment);

#endif /* !_UTIL_H_ */
