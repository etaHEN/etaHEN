#pragma once

#include <stdio.h> // IWYU pragma: keep

#ifndef LOG_PREFIX
#define LOG_PREFIX ""
#endif

// NOLINTBEGIN(*)
#define __MACRO_STRINGIFY__(x) #x
#define __DUMMY(x) x
#define __FILE_LINE_STRING__(x, y) __DUMMY(x":")__MACRO_STRINGIFY__(y)
#define LOG_PERROR(msg) perror(LOG_PREFIX __FILE_LINE_STRING__(__FILE_NAME__, __LINE__) ": " msg)
#define LOG_PRINTLN(msg) puts(LOG_PREFIX __FILE_LINE_STRING__(__FILE_NAME__, __LINE__) ": " msg)
#define LOG_PRINTF(msg, ...) printf(LOG_PREFIX __FILE_LINE_STRING__(__FILE_NAME__, __LINE__) ": " msg, __VA_ARGS__)
// NOLINTEND(*)
