#pragma once

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdarg.h>

typedef struct notify_request {
  char useless1[45];
  char message[3075];
} notify_request_t;


int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);


void notify_send(const char* fmt, ...);