#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

unsigned char * base64_encode(const unsigned char *src, size_t len,
                              size_t *out_len);

unsigned char * base64_decode(const unsigned char *src, size_t len,
                              size_t *out_len);