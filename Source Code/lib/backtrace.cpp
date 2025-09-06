#include "../include/backtrace.hpp"

const Frame * __attribute__((naked)) getFramePointer() {
	__asm__ volatile(
		"push %rbp\n"
		"pop %rax\n"
		"ret\n"
	);
}

extern "C" int puts(const char*);

static uintptr_t __attribute__((naked, noinline)) getTextStart() {
	asm volatile(
		"lea __text_start(%rip), %rax\n"
		"ret\n"
	);
}

static uintptr_t __attribute__((naked, noinline)) getTextEnd() {
	asm volatile(
		"lea __text_end(%rip), %rax\n"
		"ret\n"
	);
}

void printBacktrace() {
	const uintptr_t start = getTextStart();
	const uintptr_t stop = getTextEnd();
	__builtin_printf(".text: 0x%08llx\n", (unsigned long long)start);
	puts("---backtrace start---");
	for (const Frame *__restrict frame = getFramePointer(); frame != nullptr; frame = frame->next) {
		if (frame->addr != 0) [[likely]] {
			if (frame->addr >= start && frame->addr <= stop) {
				__builtin_printf("0x%llx\n", (unsigned long long)frame->addr - start);
			}
		}
	}
	puts("---backtrace end---");
}

#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

extern "C" ssize_t _write(int fd, const void *buf, size_t count);
void crash_log(const char *fmt, ...) {
	char msg[0x1000];
	va_list args;
	va_start(args, fmt);
	__builtin_vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	// Append newline at the end
	size_t msg_len = strlen(msg);
	if (msg_len < sizeof(msg) - 1) {
		msg[msg_len] = '\n';
		msg[msg_len + 1] = '\0';
	} else {
		msg[sizeof(msg) - 2] = '\n';
		msg[sizeof(msg) - 1] = '\0';
	}

	int fd = open(CRASH_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0777);
	if (fd < 0) {
		return;
	}
	_write(fd, msg, strlen(msg));
	close(fd);
	printf("[Crash Log]: %s", msg);  // msg already includes a newline
}

void printBacktraceForCrash() {
	const uintptr_t start = getTextStart();
	const uintptr_t stop = getTextEnd();
	crash_log(".text: 0x%08llx", (unsigned long long)start);
	crash_log("---backtrace start---");
	for (const Frame *__restrict frame = getFramePointer(); frame != nullptr; frame = frame->next) {
		if (frame->addr != 0) [[likely]] {
			if (frame->addr >= start && frame->addr <= stop) {
				crash_log("0x%llx", (unsigned long long)frame->addr - start);
			}
		}
	}
	crash_log("---backtrace end---");
}