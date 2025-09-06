#ifndef _UTIL_H_
#define _UTIL_H_

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

u64 x_to_u64(const char *hex);
u8 * x_to_u8_buffer(const char *hex);

int read_buffer(const char *file_path, u8 **buf, size_t *size);
int write_buffer(const char *file_path, u8 *buf, size_t size);

#define ALIGN(_value, _alignment) (((_value) + (_alignment) - 1) & ~((_alignment) - 1))

#ifdef __cplusplus
}
#endif

#endif /* !_UTIL_H_ */
