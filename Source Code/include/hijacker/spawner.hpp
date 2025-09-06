#pragma once

#include "hijacker.hpp"
#include "hijacker/hijacker.hpp"
#include "hijacker/spawner.hpp"
#include "memory.hpp"
#include "util.hpp"
#include <unistd.h>

extern "C" {
	#include <stdint.h>
	#include <stdio.h>
}

class Spawner {
	dbg::IdArray pids;
	uintptr_t nanosleepOffset;
	int pid;

	static inline constexpr Nid _nanosleep{"NhpspxdjEKU"};

	static uintptr_t getNanosleepOffset(const Hijacker &hijacker) {
		uintptr_t addr = hijacker.getLibKernelFunctionAddress(_nanosleep);
		return addr - hijacker.getLibKernelBase();
	}

	static uintptr_t getNanosleepOffset() {
		auto hijacker = Hijacker::getHijacker(getpid());
		if (hijacker == nullptr) [[unlikely]] {
			return 0;
		}
		return getNanosleepOffset(*hijacker);
	}

	public:
		explicit Spawner() : pids(dbg::getAllPids()), nanosleepOffset(getNanosleepOffset()), pid(getpid()) {}
		Spawner(const Hijacker &ptr) : pids(dbg::getAllPids()), nanosleepOffset(getNanosleepOffset(ptr)), pid(ptr.getPid()) {}
		UniquePtr<Hijacker> bootstrap(Hijacker &hijacker);
		UniquePtr<Hijacker> spawn();
};
