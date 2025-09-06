#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#if defined (__STDC_VERSION__) && __STDC_VERSION__ <= 201710L
// static_assert is a keyword in c23 and at this time assert.h doesn't propert define the macro
#ifndef static_assert
#define static_assert _Static_assert
#endif
#endif

#define NID_LENGTH 11
#define NID_KEY_VALUE_LENGTH 16

typedef union {

	char str[NID_LENGTH + 1]; // 12th character is for NULL terminator to allow constexpr constructor
	struct __attribute__((packed)) data_t {
		int64_t low;
		int32_t hi;
	} data;
} Nid;

static_assert(sizeof(Nid) == NID_LENGTH + 1, "sizeof(Nid) != 12");

extern Nid make_nid(const char *restrict sym, const size_t lenth);
