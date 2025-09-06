#ifndef DEBUG_LOG_H
#define DEBUG_LOG_H

extern int g_debug_sock;

#define SOCK_LOG(format, ...)  

void DumpHex(const void* data, size_t size);

#endif // DEBUG_LOG_H
