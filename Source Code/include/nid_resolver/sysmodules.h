#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Get the sysmodule id for the library with the given name
 *
 * The library name must not have a file extension; ie libSceLibcInternal
 * @param name the library name without an extension
 * @param length the name length
 * @return the sysmodule id
 */
uint32_t get_sysmodule_id(const char *restrict name, const size_t length);

#ifdef __cplusplus
}
#endif
