#include "../include/notify.h"


void notify_send(const char* fmt, ...)
{
    notify_request_t req;
    va_list args;

    bzero(&req, sizeof req);
    va_start(args, fmt);
    vsnprintf(req.message, sizeof req.message, fmt, args);
    va_end(args);

    sceKernelSendNotificationRequest(0, &req, sizeof req, 0);
}