#pragma once

#include "common_utils.h"


// NOLINTBEGIN(*)
#define __MACRO_STRINGIFY__(x) #x
#define __FILE_LINE_STRING__(x, y) x":"__MACRO_STRINGIFY__(y)
#define LOG_PERROR(msg) etaHEN_log("[etaHEN UTIL] " __FILE_LINE_STRING__(__FILE_NAME__, __LINE__) ": " msg)
#define LOG_PRINTLN(msg) etaHEN_log("[etaHEN UTIL] " __FILE_LINE_STRING__(__FILE_NAME__, __LINE__) ": " msg)
#define LOG_PRINTF(msg, ...) etaHEN_log("[etaHEN UTIL] " __FILE_LINE_STRING__(__FILE_NAME__, __LINE__) ": " msg, __VA_ARGS__)
// NOLINTEND(*)
