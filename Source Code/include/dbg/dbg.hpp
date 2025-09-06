#pragma once

#include "util.hpp"
#include <sys/_stdint.h>
#include <sys/types.h>
#include <machine/reg.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" {
	int pthread_getthreadid_np();
	int getpid();
	size_t strnlen(const char *s, size_t maxlen);
}

namespace dbg {

static constexpr uint64_t DEBUGGER_AUTHID = 0x4800000000000006;
static constexpr uint64_t PTRACE_ID = 0x4800000000010003l;

uint64_t setAuthId(uint64_t authid);

class AuthidSwapper {

	uint64_t id;
	static constexpr int AUTHID_OFFSET = 0x58;

public:
	AuthidSwapper(uint64_t authid) noexcept : id(setAuthId(authid)) {
	}
	AuthidSwapper(const AuthidSwapper&) = delete;
	AuthidSwapper &operator=(const AuthidSwapper&) = delete;
	AuthidSwapper(AuthidSwapper &&rhs) noexcept : id(rhs.id) { rhs.id = 0; }
	AuthidSwapper &operator=(AuthidSwapper &&rhs) noexcept = delete;
	~AuthidSwapper() {
		if (id != 0) {
			setAuthId(id);
			id = 0;
		}
	}
};

class IdArray {
	int *ptr;
	size_t size;

public:
	IdArray(decltype(nullptr)) : ptr(nullptr), size() {}
	IdArray(const int *ptr, size_t length) : ptr(new int[length]), size(length) {
		__builtin_memcpy(this->ptr, ptr, length * sizeof(int));
	}
	IdArray(const IdArray&) = delete;
	IdArray& operator=(const IdArray&) = delete;
	IdArray(IdArray &&rhs) noexcept : ptr(rhs.ptr), size(rhs.size) { rhs.ptr = nullptr; }
	IdArray& operator=(IdArray &&rhs) noexcept {
		delete[] ptr;
		ptr = rhs.ptr;
		rhs.ptr = nullptr;
		size = rhs.size;
		return *this;
	}
	~IdArray() {
		delete[] ptr;
	}

	int operator[](unsigned long i) const {
		if (ptr == nullptr) {
			return -1;
		}
		return ptr[i];
	}

	explicit operator bool() const { return ptr != nullptr; }

	size_t length() const { return size; }

	const int *begin() const { return ptr; }
	const int *end() const { return ptr + size; }
	bool contains(int value) const {
		for (int id : *this) {
			if (id == value) {
				return true;
			}
		}
		return false;
	}
};

class ProcessInfo {
	static constexpr unsigned int BUF_LENGTH = 0x51c;
	static constexpr unsigned int NAME_OFFSET = 0x18;
	static constexpr unsigned int NAME_LENGTH = 0x20;
	static constexpr unsigned int PATH_OFFSET = 0x38;
	static constexpr unsigned int PATH_LENGTH = 0x400;

	UniquePtr<uint8_t[]> buf;
	StringView _name;
	StringView _path;
	int _pid;

	void fillInfo();

public:

	ProcessInfo(int pid) : buf(new uint8_t[BUF_LENGTH]), _name(nullptr), _path(nullptr), _pid(pid) {
		fillInfo();
		const char *str = reinterpret_cast<char *>(buf.get());
		size_t nameLength = strnlen(str + NAME_OFFSET, NAME_LENGTH);
		_name = {str + NAME_OFFSET, nameLength};
		size_t pathLength = strnlen(str + PATH_OFFSET, PATH_LENGTH);
		_path = {str + NAME_OFFSET, pathLength};
	}
	ProcessInfo(const ProcessInfo&) = delete;
	ProcessInfo &operator=(const ProcessInfo&) = delete;
	ProcessInfo(ProcessInfo &&rhs) noexcept : buf(rhs.buf.release()), _name(rhs._name), _path(rhs._path), _pid(rhs._pid) {}
	ProcessInfo &operator=(ProcessInfo &&rhs) noexcept {
		buf = rhs.buf.release();
		_name = rhs._name;
		_path = rhs._path;
		_pid = rhs._pid;
		return *this;
	}
	~ProcessInfo() noexcept = default;

	const StringView &name() const {
		return _name;
	}

	const StringView &path() const {
		return _path;
	}

	int pid() const {
		return _pid;
	}
};


class ThreadInfo {
	static constexpr unsigned int BUF_LENGTH = 0x15c;
	static constexpr unsigned int NAME_OFFSET = 0x64;
	static constexpr unsigned int NAME_LENGTH = 0x20;

	UniquePtr<uint8_t[]> buf;
	StringView _name;
	int _pid;
	int _tid;

	void fillInfo();

public:

	ThreadInfo() : buf(new uint8_t[BUF_LENGTH]), _name(nullptr), _pid(getpid()), _tid(pthread_getthreadid_np()) {
		fillInfo();
		const char *str = reinterpret_cast<char *>(buf.get());
		size_t nameLength = strnlen(str + NAME_OFFSET, NAME_LENGTH);
		_name = {str + NAME_OFFSET, nameLength};
	}

	ThreadInfo(int tid) : buf(new uint8_t[BUF_LENGTH]), _name(nullptr), _pid(getpid()), _tid(tid) {
		fillInfo();
		const char *str = reinterpret_cast<char *>(buf.get());
		size_t nameLength = strnlen(str + NAME_OFFSET, NAME_LENGTH);
		_name = {str + NAME_OFFSET, nameLength};
	}

	ThreadInfo(int pid, int tid) : buf(new uint8_t[BUF_LENGTH]()), _name(nullptr), _pid(pid), _tid(tid) {
		fillInfo();
		const char *str = reinterpret_cast<char *>(buf.get());
		size_t nameLength = strnlen(str + NAME_OFFSET, NAME_LENGTH);
		_name = {str + NAME_OFFSET, nameLength};
	}

	ThreadInfo(const ThreadInfo&) = delete;
	ThreadInfo &operator=(const ThreadInfo&) = delete;
	ThreadInfo(ThreadInfo&&) noexcept = default;
	ThreadInfo &operator=(ThreadInfo&&) noexcept = default;
	~ThreadInfo() noexcept = default;

	const StringView &name() const {
		return _name;
	}

	int pid() const {
		return _pid;
	}

	int tid() const {
		return _tid;
	}
};


IdArray getAllPids();
IdArray getAllTids(int pid);
void suspend(int pid);
void resume(int pid);


bool read(int pid, uintptr_t addr, void *dst, size_t length);
inline UniquePtr<uint8_t[]> read(int pid, uintptr_t addr, size_t length) {
	UniquePtr<uint8_t[]> buf{new uint8_t[length]};
	if (!read(pid, addr, buf.get(), length))
	{
		return nullptr;
	}
	return buf;
}

bool write(int pid, uintptr_t dst, const void *src, size_t length);

class ProcessInfoIterator {

	IdArray pids{getAllPids()};

	class iterator {

		const int *ptr;

		public:
			iterator(const int *ptr) : ptr(ptr) {}

			ProcessInfo operator*() {
				return *ptr;
			}

			iterator operator++(int) {
				iterator it = ptr;
				ptr++;
				return it;
			}

			iterator &operator++() {
				++ptr;
				return *this;
			}

			bool operator!=(const iterator &rhs) const {
				return ptr != rhs.ptr;
			}
	};

	public:
		iterator begin() const {
			return pids.begin();
		}

		iterator end() const {
			return pids.end();
		}

		size_t length() const {
			return pids.length();
		}
};

inline ProcessInfoIterator getProcesses() {
	return {};
}

class ThreadInfoIterator {

	IdArray tids;
	int pid;

	class iterator {

		const int *ptr;
		int pid;

		public:
			iterator(const int *ptr, int pid) : ptr(ptr), pid(pid) {}

			ThreadInfo operator*() {
				return ThreadInfo{pid, *ptr};
			}

			iterator operator++(int) {
				iterator it{ptr, pid};
				ptr++;
				return it;
			}

			iterator &operator++() {
				++ptr;
				return *this;
			}

			bool operator!=(const iterator &rhs) const {
				return ptr != rhs.ptr;
			}
	};

	public:
		ThreadInfoIterator(int pid) : tids(getAllTids(pid)), pid(pid) {}
		iterator begin() const {
			return {tids.begin(), pid};
		}

		iterator end() const {
			return {tids.end(), pid};
		}
};

inline ThreadInfoIterator getThreads(int pid) {
	return {pid};
}

struct Registers : reg { // these are helpers as it is annoying that register_t is signed
	uintptr_t rax() const noexcept { return r_rax; }
	void rax(uintptr_t value) noexcept { r_rax = static_cast<register_t>(value); }
	uintptr_t rbx() const noexcept { return r_rbx; }
	void rbx(uintptr_t value) noexcept { r_rbx = static_cast<register_t>(value); }
	uintptr_t rcx() const noexcept { return r_rcx; }
	void rcx(uintptr_t value) noexcept { r_rcx = static_cast<register_t>(value); }
	uintptr_t rdx() const noexcept { return r_rdx; }
	void rdx(uintptr_t value) noexcept { r_rdx = static_cast<register_t>(value); }
	uintptr_t rsi() const noexcept { return r_rsi; }
	void rsi(uintptr_t value) noexcept { r_rsi = static_cast<register_t>(value); }
	uintptr_t rdi() const noexcept { return r_rdi; }
	void rdi(uintptr_t value) noexcept { r_rdi = static_cast<register_t>(value); }
	uintptr_t rbp() const noexcept { return r_rbp; }
	void rbp(uintptr_t value) noexcept { r_rbp = static_cast<register_t>(value); }
	uintptr_t rsp() const noexcept { return r_rsp; }
	void rsp(uintptr_t value) noexcept { r_rsp = static_cast<register_t>(value); }
	uintptr_t rip() const noexcept { return r_rip; }
	void rip(uintptr_t value) noexcept { r_rip = static_cast<register_t>(value); }
	uintptr_t r8() const noexcept { return r_r8; }
	void r8(uintptr_t value) noexcept { r_r8 = static_cast<register_t>(value); }
	uintptr_t r9() const noexcept { return r_r9; }
	void r9(uintptr_t value) noexcept { r_r9 = static_cast<register_t>(value); }
	uintptr_t r10() const noexcept { return r_r10; }
	void r10(uintptr_t value) noexcept { r_r10 = static_cast<register_t>(value); }
	uintptr_t r11() const noexcept { return r_r11; }
	void r11(uintptr_t value) noexcept { r_r11 = static_cast<register_t>(value); }
	uintptr_t r12() const noexcept { return r_r12; }
	void r12(uintptr_t value) noexcept { r_r12 = static_cast<register_t>(value); }
	uintptr_t r13() const noexcept { return r_r13; }
	void r13(uintptr_t value) noexcept { r_r13 = static_cast<register_t>(value); }
	uintptr_t r14() const noexcept { return r_r14; }
	void r14(uintptr_t value) noexcept { r_r14 = static_cast<register_t>(value); }
	uintptr_t r15() const noexcept { return r_r15; }
	void r15(uintptr_t value) noexcept { r_r15 = static_cast<register_t>(value); }
	uintptr_t cs() const noexcept { return r_cs; }
	void cs(uintptr_t value) noexcept { r_cs = static_cast<register_t>(value); }
	uintptr_t ss() const noexcept { return r_ss; }
	void ss(uintptr_t value) noexcept { r_ss = static_cast<register_t>(value); }
	uintptr_t rflags() const noexcept { return r_rflags; }
	void rflags(uintptr_t value) noexcept { r_rflags = static_cast<register_t>(value); }
	uint32_t trapno() const noexcept { return r_trapno; }
	void trapno(uint32_t value) noexcept { r_trapno = value; }
	uint32_t err() const noexcept { return r_err; }
	void err(uint32_t value) noexcept { r_err = value; }
	uint16_t fs() const noexcept { return r_fs; }
	void fs(uint16_t value) noexcept { r_fs = value; }
	uint16_t gs() const noexcept { return r_gs; }
	void gs(uint16_t value) noexcept { r_gs = value; }
	uint16_t es() const noexcept { return r_es; }
	void es(uint16_t value) noexcept { r_es = value; }
	uint16_t ds() const noexcept { return r_ds; }
	void ds(uint16_t value) noexcept { r_ds = value; }

	void setArgs(uintptr_t a) noexcept {
		rdi(a);
	}
	void setArgs(uintptr_t a, uintptr_t b) noexcept {
		rdi(a); rsi(b);
	}
	void setArgs(uintptr_t a, uintptr_t b, uintptr_t c) noexcept {
		rdi(a); rsi(b); rdx(c);
	}
	void setArgs(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d) noexcept {
		rdi(a); rsi(b); rdx(c); rcx(d);
	}
	void setArgs(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e) noexcept {
		rdi(a); rsi(b); rdx(c); rcx(d); r8(e);
	}
	void setArgs(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) noexcept {
		rdi(a); rsi(b); rdx(c); rcx(d); r8(e); r9(f);
	}
	void dump() const noexcept {
		printf("rax: 0x%08llx\n", rax());
		printf("rbx: 0x%08llx\n", rbx());
		printf("rcx: 0x%08llx\n", rcx());
		printf("rdx: 0x%08llx\n", rdx());
		printf("rsi: 0x%08llx\n", rsi());
		printf("rdi: 0x%08llx\n", rdi());
		printf("r8:  0x%08llx\n", r8());
		printf("r9:  0x%08llx\n", r9());
		printf("r10: 0x%08llx\n", r10());
		printf("r11: 0x%08llx\n", r11());
		printf("r12: 0x%08llx\n", r12());
		printf("r13: 0x%08llx\n", r13());
		printf("r14: 0x%08llx\n", r14());
		printf("r15: 0x%08llx\n", r15());
		printf("rbp: 0x%08llx\n", rbp());
		printf("rsp: 0x%08llx\n", rsp());
		printf("rip: 0x%08llx\n", rip());
	}
};

class Tracer {

	static constexpr int JITSHM_CREATE = 533;
	static constexpr int JITSHM_ALIAS = 534;
	static constexpr int MMAP = 477;
	static constexpr int MUNMAP = 73;
	static constexpr int MPROTECT = 74;
	static constexpr int CLOSE = 6;
	static constexpr int SOCKET = 97;
	static constexpr int PIPE = 42;
	static constexpr int PIPE2 = 687;
	static constexpr int SETSOCKOPT = 105;

	mutable uintptr_t syscall_addr;
	mutable uintptr_t libkernel_base;
	mutable uintptr_t errno_addr;
	int pid;

	static int ptrace(int request, pid_t pid, caddr_t addr, int data) noexcept {
		AuthidSwapper swapper{PTRACE_ID};
		return ::ptrace(request, pid, addr, data);
	}

	uintptr_t call(uintptr_t addr, uintptr_t a) const noexcept {
		const Registers backup = getRegisters();
		Registers jmp = backup;
		jmp.rip(addr);
		jmp.setArgs(a);
		return call(backup, jmp);
	}
	uintptr_t call(uintptr_t addr, uintptr_t a, uintptr_t b) const noexcept {
		const Registers backup = getRegisters();
		Registers jmp = backup;
		jmp.rip(addr);
		jmp.setArgs(a, b);
		return call(backup, jmp);
	}
	uintptr_t call(uintptr_t addr, uintptr_t a, uintptr_t b, uintptr_t c) const noexcept {
		const Registers backup = getRegisters();
		Registers jmp = backup;
		jmp.rip(addr);
		jmp.setArgs(a, b, c);
		return call(backup, jmp);
	}
	uintptr_t call(uintptr_t addr, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d) const noexcept {
		const Registers backup = getRegisters();
		Registers jmp = backup;
		jmp.rip(addr);
		jmp.setArgs(a, b, c, d);
		return call(backup, jmp);
	}
	uintptr_t call(uintptr_t addr, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e) const noexcept {
		const Registers backup = getRegisters();
		Registers jmp = backup;
		jmp.rip(addr);
		jmp.setArgs(a, b, c, d, e);
		return call(backup, jmp);
	}
	uintptr_t call(uintptr_t addr, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f) const noexcept {
		const Registers backup = getRegisters();
		Registers jmp = backup;
		jmp.rip(addr);
		jmp.setArgs(a, b, c, d, e, f);
		return call(backup, jmp);
	}
	// any remaining attempts to use the templated call will fail

	uintptr_t call(const Registers &backup, Registers &jmp) const noexcept;
	uintptr_t syscall(const Registers &backup, Registers &jmp) const noexcept;

	public:
		Tracer(int pid) noexcept : syscall_addr(0), libkernel_base(0), errno_addr(0), pid(pid) {
			if (pid == getpid()) {
				this->pid = 0;
			} else {
				if (ptrace(PT_ATTACH, pid, 0, 0) < 0) {
					::perror("ptrace PT_ATTACH Tracer::Tracer");
					this->pid = 0;
				} else {
					wait();
				}
			}
		}
		Tracer(const Tracer&) = delete;
		Tracer &operator=(const Tracer&) = delete;
		Tracer(Tracer &&rhs) noexcept : syscall_addr(rhs.syscall_addr), libkernel_base(rhs.libkernel_base), errno_addr(rhs.errno_addr), pid(rhs.pid) {
			rhs.syscall_addr = 0;
			rhs.errno_addr = 0;
			rhs.libkernel_base = 0;
			rhs.pid = 0;
		}
		Tracer &operator=(Tracer &&rhs) noexcept {
			if (pid != 0) [[unlikely]] {
				if (ptrace(PT_DETACH, pid, 0, 0) < 0) {
					::perror("ptrace PT_DETACH Tracer::operator=");
				}
			}
			syscall_addr = rhs.syscall_addr;
			libkernel_base = rhs.libkernel_base;
			errno_addr = rhs.errno_addr;
			pid = rhs.pid;
			rhs.syscall_addr = 0;
			rhs.libkernel_base = 0;
			rhs.errno_addr = 0;
			rhs.pid = 0;
			return *this;
		}
		~Tracer() noexcept {
			if (pid != 0) {
				if (ptrace(PT_DETACH, pid, 0, 0) < 0) {
					::perror("ptrace PT_DETACH Tracer::~Tracer");
				}
			}
		}

		explicit operator bool() const noexcept {
			return pid != 0;
		}

		int wait(int options=0) const noexcept {
			int status = 0;
			if (waitpid(pid, &status, options) < 0) {
				::perror("waitpid");
				return -1;
			}
			return status;
		}

		Registers getRegisters() const noexcept {
			Registers r;
			ptrace(PT_GETREGS, pid, reinterpret_cast<caddr_t>(&r), 0);
			return r;
		}

		bool getRegisters(Registers &r) const noexcept {
			return ptrace(PT_GETREGS, pid, reinterpret_cast<caddr_t>(&r), 0) >= 0;
		}

		bool setRegisters(const Registers &regs) const noexcept {
			struct reg *r = const_cast<Registers*>(&regs); // NOLINT(*)
			return ptrace(PT_SETREGS, pid, reinterpret_cast<caddr_t>(r), 0) >= 0;
		}

		int step() const noexcept {
			ptrace(PT_STEP, pid, reinterpret_cast<caddr_t>(1), 0);
			return wait();
		}

		int run(bool wait=true) const noexcept { // continue is a keyword :/
			ptrace(PT_CONTINUE, pid, reinterpret_cast<caddr_t>(1), 0);
			if (wait) {
				return this->wait();
			}
			return 0;
		}

		int kill() noexcept {
			int res = ptrace(PT_KILL, pid, 0, 0);
			if (res < 0) {
				::perror("kill");
				return res;
			}
			pid = 0;
			return 0;
		}

		template <typename R, typename ...Args>
		R call(uintptr_t addr, Args ...args) const noexcept {
			const Registers backup = getRegisters();
			Registers jmp = backup;
			jmp.rip(addr);
			// using C cast since it isn't known what cast is required
			jmp.setArgs(((uintptr_t) args)...);  // NOLINT(*)
			return (R) call(backup, jmp); // NOLINT(*)
		}

		template <typename R, typename ...Args>
		R syscall(int num, Args ...args) const noexcept {
			const Registers backup = getRegisters();
			Registers jmp = backup;
			jmp.rax(static_cast<uintptr_t>(num));
			// using C cast since it isn't known what cast is required
			jmp.setArgs(((uintptr_t) args)...);  // NOLINT(*)
			jmp.r10(jmp.rcx());
			return (R) syscall(backup, jmp); // NOLINT(*)
		}

		int jitshm_create(uintptr_t name, size_t size, int flags) const noexcept {
			return syscall<int, uintptr_t, size_t, int>(JITSHM_CREATE, name, size, flags);
		}

		int jitshm_alias(int fd, int flags) const noexcept {
			return syscall<int, int, int>(JITSHM_ALIAS, fd, flags);
		}

		uintptr_t mmap(uintptr_t addr, size_t len, int prot, int flags, int fd, off_t off) const noexcept {
			return syscall<uintptr_t, uintptr_t, size_t, int, int, int, off_t>(MMAP, addr, len, prot, flags, fd, off);
		}

		int munmap(uintptr_t addr, size_t len) const noexcept {
			return syscall<int, uintptr_t, size_t>(MUNMAP, addr, len);
		}

		int mprotect(uintptr_t addr, size_t len, int prot) const noexcept {
			return syscall<int, uintptr_t, size_t, int>(MPROTECT, addr, len, prot);
		}

		int close(int fd) const noexcept {
			return syscall<int, int>(CLOSE, fd);
		}

		int socket(int domain, int type, int protocol) const noexcept {
			return syscall<int, int, int, int>(SOCKET, domain, type, protocol);
		}

		int pipe(int *fildes) const noexcept;
		int dynlib_load_prx(const char *path, int *handle) const noexcept;
		int dynlib_dlsym(int handle, const char *name, void **address) const noexcept;


		int setsockopt(int s, int level, int optname, const void *optval, unsigned int optlen) const noexcept;

		void perror(const char *msg) const noexcept;
};

} // dbg
