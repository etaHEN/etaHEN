#pragma once

extern "C" {
	#include <stdint.h>
}

enum DbgCommand : uint64_t {
	CREATE_SCRATCH_CMD = 0x3,
	READ_CMD = 0x12,
	WRITE_CMD = 0x13,
	PROCESS_LIST_CMD = 0x14,
	THREAD_LIST_CMD = 0x15,
	PROCESS_INFO_CMD = 0x18,
	THREAD_INFO_CMD = 0x19,
	ARG2_CMD = 0x1e
};

// NOLINTBEGIN(*)

// aggressively zero all dbg args
template <unsigned long size>
struct DbgArg {
	DbgArg() {
		// because of the stupid wrong pure attribute in the sdk headers
		// __builtin_memset must be used
		__builtin_memset(this, 0, size);
	}
};

struct DbgArg1 : DbgArg<0x20> {
	uint32_t type;
	uint32_t pad1;
	DbgCommand cmd;

	DbgArg1(uint32_t type, DbgCommand cmd) : DbgArg(), type(type), cmd(cmd){}
private:
	uint8_t __attribute__((unused)) pad[0x10];
};

static_assert(sizeof(DbgArg1) == 0x20, "sizeof(DbgArg1) != 0x20");

struct DbgArg2 : DbgArg<0x40> {
};

struct DbgReadArg : DbgArg2 {
	int pid;
	uintptr_t src;
	void *dst;
	uint64_t length;
	DbgReadArg(int pid, uintptr_t src, void *dst, uint64_t length)
			: pid(pid), src(src), dst(dst), length(length) {}
private:
	unsigned char __attribute__((unused)) pad[0x20];
};

static_assert(sizeof(DbgReadArg) == 0x40, "sizeof(DbgReadArg) != 0x40");

struct DbgKickProcessArg : DbgArg2 {
	uint32_t pid;
	uint32_t __attribute__((unused)) pad1;
	const uint32_t cmd = 16;
	uint32_t __attribute__((unused)) pad2;
	const uint32_t value = 3;
	DbgKickProcessArg(int pid) : pid(pid) {}
private:
	unsigned char __attribute__((unused)) pad[0x2c];
};

static_assert(sizeof(DbgKickProcessArg) == 0x40, "sizeof(DbgKickProcessArg) != 0x40");

struct DbgGetPidsArg : DbgArg2 {
	uint64_t buf;
	uint64_t length;

	template <unsigned long size>
	DbgGetPidsArg(int(&buf)[size]) : buf((uint64_t) &buf), length(size) {}
	DbgGetPidsArg(int *buf, unsigned long size) : buf((uint64_t) buf), length(size) {}
private:
	unsigned char __attribute__((unused)) pad[0x30];
};

static_assert(sizeof(DbgGetPidsArg) == 0x40, "sizeof(DbgGetPidsArg) != 0x40");

struct DbgGetTidsArg : DbgArg2 {
	uint32_t pid;
	uint64_t buf;
	uint64_t length;

	template <unsigned long size>
	DbgGetTidsArg(int pid, int(&buf)[size]) : pid(pid), buf((uint64_t) &buf), length(size) {}
	DbgGetTidsArg(int pid, int *buf, unsigned long size) : pid(pid), buf((uint64_t) buf), length(size) {}
private:
	unsigned char __attribute__((unused)) pad[0x28];
};

static_assert(sizeof(DbgGetTidsArg) == 0x40, "sizeof(DbgGetTidsArg) != 0x40");

struct DbgGetProcInfoArg : DbgArg2 {
	int pid;
	uintptr_t buf;
	uint64_t length;

	DbgGetProcInfoArg(int pid, void *buf, uint64_t length)
		: pid(pid), buf((uintptr_t) buf), length(length) {}
private:
	unsigned char __attribute__((unused)) pad[0x28];
};

static_assert(sizeof(DbgGetProcInfoArg) == 0x40, "sizeof(DbgGetProcInfoArg) != 0x40");


struct DbgGetThreadInfoArg : DbgArg2 {
	uint32_t pid;
	uint32_t __attribute__((unused)) pad1;
	uint32_t tid;
	uint64_t buf;
	uint64_t length;

	DbgGetThreadInfoArg(int pid, int tid, void *buf, uint64_t length)
		: pid(pid), tid(tid), buf((uintptr_t) buf), length(length) {}
private:
	unsigned char __attribute__((unused)) pad[0x20];
};

static_assert(sizeof(DbgGetThreadInfoArg) == 0x40, "sizeof(DbgGetThreadInfoArg) != 0x40");

struct DbgArg3 : DbgArg<0x20> {
	int64_t err;
	uint64_t length;

	explicit DbgArg3() : length() {}
private:
	unsigned char __attribute__((unused)) pad[0x10];
};

static_assert(sizeof(DbgArg3) == 0x20, "sizeof(DbgArg3) != 0x20");

// NOLINTEND(*)
