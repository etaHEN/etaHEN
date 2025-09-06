#ifndef UTIL_H
#define UTIL_H

#define MAX(a,b) ((a) > (b) ? (a) : (b))

// Core pinning
int pin_to_core(int num);
void pin_to_first_available_core();
int get_cpu_core();

// Kernel read/write
void kernel_write8(uint64_t addr, uint64_t val);
void kernel_write4(uint64_t addr, uint32_t val);
uint64_t kernel_read8(uint64_t addr);
uint32_t kernel_read4(uint64_t addr);

// Dumping
void DumpHex(const void* data, size_t size);

// Notifications
int flash_notification(const char *fmt, ...);

#endif // UTIL_H