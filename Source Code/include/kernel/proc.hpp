#pragma once

#include "kernel.hpp"
#include "kernel/kernel.hpp"
#include "rtld.hpp"
#include "kthread.hpp"
#include "../offsets.hpp"
#include "util.hpp"
#include <cstdint>

extern "C" {
	#include <ps5/kernel.h>
	extern int getpid();
	extern uint64_t kernel_base;
}

namespace {

static constexpr size_t SELFINFO_SIZE = 0x400;
static constexpr size_t SELFINFO_NAME_SIZE = 32;
static constexpr size_t SELFINFO_PATH_SIZE = 972;

static constexpr size_t FILEDESCENT_SIZE = 0x30;
static constexpr size_t PROC_SIZE = 0xc90;

}

struct SelfInfo {
	uint32_t type;
	uint32_t ps4_sdk_version;
	uint32_t ps5_sdk_version;
	uint32_t beef_face;
	uint32_t dbbcc;
	char name[SELFINFO_NAME_SIZE];
	char path[SELFINFO_PATH_SIZE];
};

static_assert(sizeof(SelfInfo) == SELFINFO_SIZE, "sizeof(SelfInfo) != 0x400");

class Filedescent : public KernelObject<Filedescent, FILEDESCENT_SIZE> {

	static constexpr size_t FILE_OFFSET = 0;
	static constexpr size_t FLAGS_OFFSET = 0x28;
	static constexpr size_t SEQ_OFFSET = 0x2c;

	public:
		Filedescent(uintptr_t addr) : KernelObject(addr) {}
		uintptr_t file() const {
			return get<uintptr_t, FILE_OFFSET>();
		}

		uint8_t flags() const {
			return get<uint8_t, FLAGS_OFFSET>();
		}

		uint32_t seq() const {
			return get<uint32_t, SEQ_OFFSET>();
		}
};

class FdTbl {
	uintptr_t addr;
	size_t ntables;

	size_t checkIndex(size_t i) const {
		#ifdef DEBUG
		if (i >= ntables) [[unlikely]] {
			fatalf("index %llu is out of bounds for length %llu\n", i, ntables);
		}
		#endif
		return i;
	}

	public:
		FdTbl(uintptr_t addr) : addr(addr), ntables((uint32_t)kread<uintptr_t>(addr)) {}

		Filedescent operator[](size_t i) const {
			return {addr + (checkIndex(i) * Filedescent::length) + sizeof(ntables)};
		}

		uintptr_t getFile(size_t i) const {
			uintptr_t fp = addr + (checkIndex(i) * Filedescent::length) + sizeof(ntables);
			return kread<uintptr_t>(fp);
		}

		void setFile(size_t i, uintptr_t file) const {
			uintptr_t fp = addr + (checkIndex(i) * Filedescent::length) + sizeof(ntables);
			kwrite(fp, file);
		}

		uintptr_t getFileData(size_t i) const {
			return kread<uintptr_t>(getFile(i));
		}

		void setFileData(size_t i, uintptr_t data) const {
			kwrite(getFile(i), data);
		}

		size_t length() const {
			return ntables;
		}
};

class KProc : public KernelObject<KProc, PROC_SIZE> {

	static constexpr size_t UCRED_OFFSET = 0x40;
	static constexpr size_t PATH_OFFSET = 0x3d8;
	static constexpr size_t SHARED_OBJECT_OFFSET = 0x3e8;
	static constexpr size_t PID_OFFSET = 0xbc;
	static constexpr size_t THREADS_OFFSET = 0x10;
	static constexpr size_t FD_OFFSET = 0x48;
	static constexpr size_t TITLEID_OFFSET = 0x470;
	static constexpr size_t SELFINFO_OFFSET = 0x588;
	static constexpr size_t SELFINFO_NAME_OFFSET = 0x59C;

	public:

		KProc(uintptr_t addr) : KernelObject(addr) {}
		uintptr_t p_ucred() const {
			return get<uintptr_t, UCRED_OFFSET>();
		}

		UniquePtr<KUcred> ucred() const {
			return new KUcred{p_ucred()};
		}

		int p_pid() const {
			return get<int, PID_OFFSET>();
		}

		int pid() const {
			return p_pid();
		}

		UniquePtr<SharedObject> getSharedObject() const {
			auto obj = get<uintptr_t, SHARED_OBJECT_OFFSET>();
			return obj != 0 ? new SharedObject{obj, pid()} : nullptr;
		}

		String getPath() const {
			return getString<PATH_OFFSET>();
		}

		KIterator<KThread> p_threads() const {
			return address() + THREADS_OFFSET;
		}

		KIterator<KThread> getThreads() const {
			return p_threads();
		}

		UniquePtr<KThread> getThread(int tid) const {
			for (auto td : getThreads()) {
				if (tid == td->tid()) {
					return td.release();
				}
			}
			return nullptr;
		}

		uintptr_t p_fd() const {
			return get<uintptr_t, FD_OFFSET>();
		}

		FdTbl getFdTbl() const {
			return {kread<uintptr_t>(p_fd())};
		}

		const SelfInfo *getSelfInfo() const {
			return reinterpret_cast<const SelfInfo *>(buf + SELFINFO_OFFSET);
		}

		// no flush required
		void setName(const StringView &name, bool reload=false) {
			const size_t length = name.length() < (SELFINFO_NAME_SIZE-1) ? name.length() : SELFINFO_NAME_SIZE;
			kwrite(address() + SELFINFO_NAME_OFFSET, name.c_str(), length + 1);
			if (reload) {
				this->reload();
			}
		}

		void setTID(const StringView &tid) {
			const size_t length = tid.length() < (TITLEID_OFFSET-1) ? tid.length() : TITLEID_OFFSET;
			kwrite(address() + TITLEID_OFFSET, tid.c_str(), length + 1);
		}

		String getTitleId() const noexcept {
			constexpr auto TITLE_ID_SIZE = 9;
			return StringView{reinterpret_cast<const char *>(buf) + TITLEID_OFFSET, TITLE_ID_SIZE};
		}

		String titleId() const
		{
			return getKernelString(address() + TITLEID_OFFSET);
		}
};

inline KIterator<KProc> getAllProcs() {
	return {kernel_base + offsets::allproc()};
}

UniquePtr<KProc> getProc(int pid);

inline UniquePtr<KProc> getProc() {
	return getProc(getpid());
}
