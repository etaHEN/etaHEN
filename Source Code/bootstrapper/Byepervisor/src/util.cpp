#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/cpuset.h>
#include <unistd.h>

extern "C"
{
    #include <ps5/kernel.h>
    #include <ps5/klog.h>
}

#include "debug_log.h"
#include "util.h"

extern "C"
{
    int sceKernelGetCurrentCpu();

    typedef struct notify_request {
        char unk_00h[45];
        char message[3075];
    } notify_request_t;

    int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);
}

int pin_to_core(int num)
{
    uint64_t mask[2] = {};
    mask[0] = (1 << num);
    return cpuset_setaffinity(3, 1, -1, 0x10, (const cpuset_t *) mask);
}

void pin_to_first_available_core()
{
    for (int i = 0; i < 16; i++) {
        if (pin_to_core(i) == 0) {
            break;
        }
    }
}

int get_cpu_core()
{
    return sceKernelGetCurrentCpu();
}

void kernel_write8(uint64_t addr, uint64_t val)
{
    uint64_t val_to_write = val;
    kernel_copyin(&val_to_write, addr, sizeof(val_to_write));
}

void kernel_write4(uint64_t addr, uint32_t val)
{
    uint32_t val_to_write = val;
    kernel_copyin(&val_to_write, addr, sizeof(val_to_write));
}

uint64_t kernel_read8(uint64_t addr)
{
    uint64_t val;
    kernel_copyout(addr, &val, sizeof(val));
    return val;
}

uint32_t kernel_read4(uint64_t addr)
{
    uint32_t val;
    kernel_copyout(addr, &val, sizeof(val));
    return val;
}

void DumpHex(const void* data, size_t size) {
    char hexbuf[0x4000];
    (void)memset(hexbuf, 0, sizeof(hexbuf));
    char *cur = (char *) &hexbuf;

    sprintf(cur, "hex:\n");
    cur += strlen(cur);

    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        sprintf(cur, "%02X ", ((unsigned char*)data)[i]);
        cur += strlen(cur);

        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            sprintf(cur, " ");
            cur += strlen(cur);

            if ((i+1) % 16 == 0) {
                sprintf(cur, "|  %s \n", ascii);
                cur += strlen(cur);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    sprintf(cur, " ");
                    cur += strlen(cur);
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    sprintf(cur, "   ");
                    cur += strlen(cur);
                }
                sprintf(cur, "|  %s \n", ascii);
                cur += strlen(cur);
            }
        }
    }

    klog_printf("%s", hexbuf);
}

int flash_notification(const char *fmt, ...)
{
    va_list args;
    notify_request_t req;

    // Zero-init buffer to prevent dumb bugs
    bzero(&req, sizeof(req));

    // Construct message
    va_start(args, fmt);
    vsnprintf((char *) &req.message, sizeof(req.message), fmt, args);
    va_end(args);

	return sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}


