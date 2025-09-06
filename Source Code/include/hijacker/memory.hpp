#pragma once

extern "C" {
	#include <stdint.h>
}

#include "dbg.hpp"

template <typename T>
class ProcessReference {
	uintptr_t addr;
	int pid;

	public:
		ProcessReference() = default;
		ProcessReference(int pid, uintptr_t addr) : addr(addr), pid(pid) {}
		ProcessReference(const ProcessReference &rhs) : addr(rhs.addr), pid(rhs.pid) {}
		ProcessReference(ProcessReference&&) noexcept = delete;
		ProcessReference &operator=(const ProcessReference &rhs) {
			addr = rhs.addr;
			pid = rhs.pid;
			return *this;
		}
		ProcessReference &operator=(ProcessReference&&) noexcept = delete;
		ProcessReference &operator=(T value) {
			dbg::write(pid, addr, &value, sizeof(value));
			return *this;
		}
		~ProcessReference() noexcept = default;
		operator T() const {
			T value;
			dbg::read(pid, addr, &value, sizeof(T));
			return value;
		}
};

template <>
class ProcessReference<bool> {
	uintptr_t addr;
	int pid;

	public:
		ProcessReference(int pid, uintptr_t addr) : addr(addr), pid(pid) {}
		ProcessReference(const ProcessReference &rhs) : addr(rhs.addr), pid(rhs.pid) {}
		ProcessReference(ProcessReference&&) noexcept = delete;
		ProcessReference &operator=(const ProcessReference &rhs) {
			addr = rhs.addr;
			pid = rhs.pid;
			return *this;
		}
		ProcessReference &operator=(bool value) {
			dbg::write(pid, addr, &value, sizeof(value));
			return *this;
		}
		ProcessReference &operator=(ProcessReference&&) noexcept = delete;
		~ProcessReference() noexcept = default;
		explicit operator bool() const {
			bool value; // NOLINT(cppcoreguidelines-init-variables)
			dbg::read(pid, addr, &value, sizeof(bool));
			return value;
		}
};

template <typename T>
class ProcessPointer {
	uintptr_t addr;
	int pid;

	public:
		ProcessPointer() : addr(), pid() {}
		ProcessPointer(int pid, uintptr_t addr) : addr(addr), pid(pid) {}
		ProcessReference<T> operator*() const { return {pid, addr}; }
		T get() const {
			T value{};
			dbg::read(pid, addr, &value, sizeof(T));
			return value;
		}
		uintptr_t address() const { return addr; }
};
