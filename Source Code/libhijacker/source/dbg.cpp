#include "dbg/args.hpp"
#include "dbg/dbg.hpp"
#include "hijacker/hijacker.hpp"
#include "nid.hpp"
#include "util.hpp"

extern "C" {
#include <ps5/kernel.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
}

static constexpr int SYSCALL_OFFSET = 10;

extern "C" int mdbg_call(void *, void *, void *);
extern "C" int sceKernelDlsym(int handle, const char* symbol, void** addrp);
extern "C" int *__error();

static constexpr uintptr_t PID_OFFSET = 0xBC;
static constexpr uintptr_t UCRED_OFFSET = 0x40;

static uintptr_t getCurrentProc() {

	const pid_t pid = getpid();
	uintptr_t proc = kread<uintptr_t>(kernel_base + offsets::allproc());
	while (proc != 0) {
		int cid = kread<int>(proc + PID_OFFSET);
		if (cid == pid) {
			return proc;
		}
		proc = kread<uintptr_t>(proc);
	}
	return 0;
}

namespace dbg {

int __attribute__((noinline)) mdbg_call(DbgArg1 &arg1, DbgArg2 &arg2, DbgArg3 &arg3) {
	AuthidSwapper swapper{DEBUGGER_AUTHID};
	return ::mdbg_call(&arg1, &arg2, &arg3);
}

IdArray getAllPids() {
	static constexpr size_t LENGTH = 10000;
	DbgArg1 arg1{1, DbgCommand::PROCESS_LIST_CMD};
	UniquePtr<int[]> buf{new int[LENGTH]};
	DbgGetPidsArg arg2{buf.get(), LENGTH};
	DbgArg3 arg3{};
	mdbg_call(arg1, arg2, arg3);
	return {buf.get(), arg3.length};
}

IdArray getAllTids(int pid) {
	static constexpr size_t LENGTH = 0x2000;
	DbgArg1 arg1{1, DbgCommand::THREAD_LIST_CMD};
	UniquePtr<int[]> buf{new int[LENGTH]};
	DbgGetTidsArg arg2{pid, buf.get(), LENGTH};
	DbgArg3 arg3{};
	mdbg_call(arg1, arg2, arg3);
	return {buf.get(), arg3.length};
}

void ProcessInfo::fillInfo() {
	DbgArg1 arg1{1, DbgCommand::PROCESS_INFO_CMD};
	DbgGetProcInfoArg arg2{_pid, buf.get(), BUF_LENGTH};
	DbgArg3 arg3{};
	mdbg_call(arg1, arg2, arg3);

}

void ThreadInfo::fillInfo() {
	DbgArg1 arg1{1, DbgCommand::THREAD_INFO_CMD};
	DbgGetThreadInfoArg arg2{_pid, _tid, buf.get(), BUF_LENGTH};
	DbgArg3 arg3{};
	mdbg_call(arg1, arg2, arg3);
}

static void logState(const DbgArg3 &arg) {
	// NOLINTBEGIN(*)
	uint64_t state = -1;
	if (arg.err == 0) {
		state = arg.length & 7;
		if ((arg.length & 0x10) != 0) {
			state |= 8;
		}
	}
	if (state == 7 || state == 0) {
		puts("idk what this means other than we're screwed");
	}
	printf("state: 0x%08lx\n", state);
	// NOLINTEND(*)
}

void suspend(int pid) {
	puts("suspending");
	DbgArg1 arg1{1, DbgCommand::ARG2_CMD};
	DbgKickProcessArg arg2{pid};
	DbgArg3 arg3{};
	mdbg_call(arg1, arg2, arg3);
	logState(arg3);
}

void resume(int pid) {
	puts("resuming");
	// this is the same as suspend but is separate for easier debugging
	DbgArg1 arg1{1, DbgCommand::ARG2_CMD};
	DbgKickProcessArg arg2{pid};
	DbgArg3 arg3{};
	mdbg_call(arg1, arg2, arg3);
	logState(arg3);
}

bool read(int pid, uintptr_t src, void *dst, size_t length) {
	DbgArg1 arg1{1, DbgCommand::READ_CMD};
	DbgReadArg arg2{pid, src, dst, length};
	DbgArg3 arg3{};
	mdbg_call(arg1, arg2, arg3);
	if (arg3.length != length) {
		int err = arg3.err != -1 ? (int) arg3.err : errno;
		printf("read failed %d: %s\n", err, strerror(err));
		return false;
	}
	return true;
}

bool write(int pid, uintptr_t dst, const void *src, size_t length) {
	DbgArg1 arg1{1, DbgCommand::WRITE_CMD};
	DbgReadArg arg2{pid, dst, const_cast<void *>(src), length}; // NOLINT(*)
	DbgArg3 arg3{};
	mdbg_call(arg1, arg2, arg3);
	if (arg3.length != length) {
		int err = arg3.err != -1 ? (int) arg3.err : errno;
		printf("write failed %d: %s\n", err, strerror(err));
		return false;
	}
	return true;
}

uint64_t setAuthId(uint64_t authid) {
	static constexpr int AUTHID_OFFSET = 0x58;
	uintptr_t proc = getCurrentProc();
	uintptr_t ucred = kread<uintptr_t>(proc + UCRED_OFFSET);
	uint64_t id = kread<uint64_t>(ucred + AUTHID_OFFSET);
	kwrite(ucred + AUTHID_OFFSET, authid);
	return id;
}

uintptr_t Tracer::call(const Registers &backup, Registers &jmp) const noexcept {
	if (libkernel_base == 0) [[unlikely]] {
		auto hijacker = Hijacker::getHijacker(pid);
		libkernel_base = hijacker->getLibKernelBase();
		if (libkernel_base == 0) [[unlikely]] {
			puts("failed to get libkernel base");
			return -1;
		}
	}

	jmp.rsp(jmp.rsp() - sizeof(uintptr_t));

	if (!setRegisters(jmp)) {
		return -1;
	}

	// set the return address to the `INT3` at the start of libkernel
	dbg::write(pid, jmp.rsp(), &libkernel_base, sizeof(libkernel_base));

	// call the function
	run();

	if (!getRegisters(jmp)) {
		return -1;
	}

	// restore registers
	if (!setRegisters(backup)) {
		return -1;
	}

	return jmp.rax();
}

uintptr_t Tracer::syscall(const Registers &backup, Registers &jmp) const noexcept {
	if (syscall_addr == 0) [[unlikely]] {
		auto hijacker = Hijacker::getHijacker(pid);
		auto addr = hijacker->getLibKernelFunctionAddress(nid::get_authinfo);
		if (addr != 0) {
			addr += SYSCALL_OFFSET;
		}
		syscall_addr = addr;
	}

	jmp.rip(syscall_addr);

	if (!setRegisters(jmp)) {
		return -1;
	}

	// execute the syscall instruction
	step();
	if (!getRegisters(jmp)) {
		setRegisters(backup);
		return -1;
	}

	// restore registers
	if (!setRegisters(backup)) {
		return -1;
	}

	return jmp.rax();
}

void Tracer::perror(const char *msg) const noexcept {
	if (errno_addr == 0) [[unlikely]] {
		auto hijacker = Hijacker::getHijacker(pid);
		errno_addr = hijacker->getLibKernelAddress(nid::_errno);
		if (errno_addr == 0) [[unlikely]] {
			puts("failed to get errno address");
			return;
		}
	}
	int err = 0;
	read(pid, errno_addr, &err, sizeof(err));
	printf("%s: %s\n", msg, strerror(err));
}

int Tracer::pipe(int *fildes) const noexcept {
	fildes[0] = -1;
	fildes[1] = -1;
	const Registers backup = getRegisters();
	Registers jmp = backup;
	const auto rsp = jmp.rsp() - sizeof(long[2]);
	dbg::write(pid, rsp, fildes, sizeof(int[2]));
	jmp.rax(PIPE2);
	jmp.rdi(rsp);
	jmp.rsi(0);
	int err = static_cast<int>(syscall(backup, jmp));
	if (err < 0) {
		return err;
	}
	dbg::read(pid, rsp, fildes, sizeof(int[2]));
	return 0;
}

int Tracer::setsockopt(int s, int level, int optname, const void *optval, unsigned int optlen) const noexcept {
	const Registers backup = getRegisters();
	Registers jmp = backup;
	const auto rsp = jmp.rsp() - optlen;
	jmp.rax(SETSOCKOPT);
	jmp.rsp(rsp);
	jmp.rdi(s); jmp.rsi(level); jmp.rdx(optname); jmp.r10(rsp); jmp.r8(optlen);
	dbg::write(pid, rsp, optval, optlen);
	int err = static_cast<int>(syscall(backup, jmp));
	if (err < 0) {
		return err;
	}
	return 0;
}

//int sys_dynlib_load_prx(const char* prxPath, int* moduleID){
//	return syscall<int, const char*, int, int*, int>(0x252, prxPath, 0, moduleID, 0);
//}


int Tracer::dynlib_load_prx(const char *path, int *handle) const noexcept {
    const Registers backup = getRegisters();
    Registers jmp = backup;
    const auto h = jmp.rsp() - sizeof(int);
    const auto pathLength = strlen(path) + 1;
    const auto rsp = jmp.rsp() - pathLength;
    dbg::write(pid, rsp, path, pathLength);
    jmp.rax(0x252);
    jmp.rdi(rsp);
    jmp.rsi(0);
    jmp.rdx(h);
    int err = static_cast<int>(syscall(backup, jmp));
	printf("err: %i\n", err);
    if (err != 0) {
        return err;
    }
    dbg::read(pid, h, handle, sizeof(int));
    return 0;
}

int Tracer::dynlib_dlsym(int handle, const char *name, void **address) const noexcept {
	const Registers backup = getRegisters();
	Registers jmp = backup;
	const auto rsp = jmp.rsp() - sizeof(void *);
	const auto nameLength = strlen(name) + 1;
	const auto rsp2 = rsp - nameLength;
	dbg::write(pid, rsp2, name, nameLength);
	jmp.rax(0x24f);
	jmp.rdi(handle);
	jmp.rsi(rsp2);
	jmp.rdx(rsp);
	int err = static_cast<int>(syscall(backup, jmp));
	if (err < 0) {
		return err;
	}
	dbg::read(pid, rsp, address, sizeof(void *));
	return 0;
}

} // dbg
