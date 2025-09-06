#pragma once

// IWYU pragma: begin_exports

#include "kernel/kernel.hpp"
#include "kernel/rtld.hpp"
#include "kernel/proc.hpp"
#include "kernel/frame.hpp"

// IWYU pragma: end_exports

#include "util.hpp"

bool createReadWriteSockets(const UniquePtr<KProc> &proc, const int *sockets) noexcept;

inline bool createReadWriteSockets(int pid, const int *sockets) noexcept {
	auto proc = getProc(pid);
	if (proc == nullptr) {
		puts("createReadWriteSockets proc == nullptr");
		return false;
	}
	return createReadWriteSockets(proc, sockets);
}
