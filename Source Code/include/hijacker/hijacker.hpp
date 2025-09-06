#pragma once

#include "dbg.hpp"
#include "hijacker/allocator.hpp"
#include "memory.hpp"
#include "kernel.hpp"
#include "kernel/rtld.hpp"
#include "util.hpp"
#include "allocator.hpp"
#include <sys/_stdint.h>

class Hijacker {
	
#ifndef LIBKERNEL_HANDLE
	static constexpr int LIBKERNEL_HANDLE = 0x2001;
#endif

	UniquePtr<SharedObject> obj;

	protected:
		friend class Spawner;
		ProcessMemoryAllocator textAllocator;
		ProcessMemoryAllocator dataAllocator;

	private:
		mutable UniquePtr<SharedLib> libkernel;
		mutable int mainThreadId = -1;
		bool isMainThreadRunning = true;

		Hijacker(SharedObject *obj) : obj(obj), textAllocator(nullptr), dataAllocator(nullptr), libkernel(nullptr) {
			auto eboot = this->obj->getEboot();
			while (eboot == nullptr) {
				// this can happen when it is still loading
				eboot = this->obj->getEboot();
			}
			while (textAllocator == nullptr) {
				textAllocator = ProcessMemoryAllocator(eboot->getTextSection());
			}
			while (dataAllocator == nullptr) {
				dataAllocator = ProcessMemoryAllocator(eboot->getDataSection());
			}
		}

		RtldMeta *getLibKernelMetaData() const {
			auto *meta = getLibKernel();
			return meta ? meta->getMetaData() : nullptr;
		}

	public:
		uintptr_t getLibKernelBase() const {
			RtldMeta *meta = getLibKernelMetaData();
			return meta ? meta->imageBase : 0;
		}
	private:
		int getMainThreadId() const;

	public:
		static UniquePtr<Hijacker> getHijacker(const StringView &processName);
		static UniquePtr<Hijacker> getHijacker(int pid) {
			auto p = ::getProc(pid);
			if (p == nullptr) [[unlikely]] {
				return nullptr;
			}

			auto obj = p->getSharedObject();

			// obj may be a nullptr when racing process creation
			return obj != nullptr ? new Hijacker{obj.release()} : nullptr;
		}

		UniquePtr<KProc> getProc() const {
			return ::getProc(getPid());
		}

		void suspend() {
			if (isMainThreadRunning) {
				dbg::suspend(obj->pid);
				isMainThreadRunning = false;
			}
		}

		void resume() {
			if (!isMainThreadRunning) {
				dbg::resume(obj->pid);
				isMainThreadRunning = true;
			}
		}

		int getPid() const {
			return obj->pid;
		}

		SharedLib *getEboot() const {
			return obj->getEboot();
		}

		uintptr_t imagebase() const {
			auto eboot = obj->getEboot();
			return eboot ? eboot->imagebase() : 0;
		}

		SharedLib *getLibKernel() const {
			if (libkernel == nullptr) [[unlikely]] {
				libkernel = obj->getLib(LIBKERNEL_HANDLE);
			}
			return libkernel.get();
		}

		UniquePtr<SharedLib> getLib(int handle) const {
			return obj->getLib(handle);
		}

		UniquePtr<SharedLib> getLib(const StringView &name) const {
			return obj->getLib(name);
		}

		SharedLibIterator getLibs() const {
			return obj->getLibs();
		}

		UniquePtr<TrapFrame> getTrapFrame() const;
		void jailbreak(bool escapeSandbox=true) const;
		uintptr_t getFunctionAddress(const SharedLib *lib, const Nid &fname) const noexcept;

		uintptr_t getLibKernelFunctionAddress(const Nid &fname) const {
			return getFunctionAddress(getLibKernel(), fname);
		}

		uintptr_t getLibKernelAddress(const Nid &fname) const {
			return getFunctionAddress(getLibKernel(), fname);
		}

		ProcessMemoryAllocator &getDataAllocator() {
			return dataAllocator;
		}

		ProcessMemoryAllocator &getTextAllocator() {
			return textAllocator;
		}

		UniquePtr<uint8_t[]> read(uintptr_t src, size_t size) {
			return dbg::read(getPid(), src, size).release();
		}

		bool read(uintptr_t src, void *dst, size_t size) {
			return dbg::read(getPid(), src, dst, size);
		}

		template <typename T>
		T read(uintptr_t vaddr) {
			T t;
			read(vaddr, &t, sizeof(t));
			return t;
		}

		template <size_t size>
		bool write(uintptr_t vaddr, const uint8_t(&buf)[size]) {
			return dbg::write(getPid(), vaddr, buf, size);
		}

		bool write(uintptr_t vaddr, const void *src, size_t size) {
			return dbg::write(getPid(), vaddr, src, size);
		}

		template <typename T>
		bool write(uintptr_t vaddr, const T &value) {
			return write(vaddr, &value, sizeof(value));
		}

		template <typename T>
		ProcessPointer<T> getPointer(uintptr_t addr) const {
			return {getPid(), addr};
		}

		void hexdump(uintptr_t addr, size_t size) {
			auto buf = read(addr, size);
			::hexdump(buf.get(), size);
		}
};
