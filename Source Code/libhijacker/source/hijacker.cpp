#include "hijacker.hpp"
#include "offsets.hpp"
#include "util.hpp"
#include <ps5/kernel.h>

extern "C" {
#include <stdint.h>
#include <stdio.h>
}

UniquePtr<Hijacker> Hijacker::getHijacker(const StringView &processName) {
	UniquePtr<SharedObject> obj = nullptr;
	for (dbg::ProcessInfo info : dbg::getProcesses()) {
		if (info.name() == processName) {
			auto p = ::getProc(info.pid());
			obj = p->getSharedObject();
		}
	}
	return obj ? new Hijacker(obj.release()) : nullptr;
}

int Hijacker::getMainThreadId() const {
	if (mainThreadId == -1) {
		for (dbg::ThreadInfo info : dbg::getThreads(obj->pid)) {
			StringView name = info.name();
			if (name.contains("Main") || name.contains(".")) {
				// this works for most of them
				mainThreadId = info.tid();
				break;
			}
		}
		if (mainThreadId == -1) [[unlikely]] {
			puts("main thread id not found");
		}
	}
	return mainThreadId;
}

UniquePtr<TrapFrame> Hijacker::getTrapFrame() const {
	// do not cache this
	int tid = getMainThreadId();
	if (tid == -1) [[unlikely]] {
		return nullptr;
	}
	auto p = ::getProc(obj->pid);
	if (p == nullptr) {
		return nullptr;
	}

	auto td = p->getThread(tid);
	if (td == nullptr) {
		return nullptr;
	}
	return td->getFrame();
}

// NOLINTBEGIN
//
static inline void copyin(uintptr_t kdst, const void *src, size_t length) {
	kernel_copyin(const_cast<void *>(src), kdst, length);
}

void Hijacker::jailbreak(bool escapeSandbox) const {
	auto p = getProc();
	uintptr_t ucred = p->p_ucred();
	uintptr_t fd = p->p_fd();
	int uid = -1;
	kernel_copyout(ucred + 0x04, &uid, 0x4);
	if(uid == 0 && !escapeSandbox){
		puts("already jailbroken");
		return;
	}
	UniquePtr<uint8_t[]> rootvnode_area_store{new uint8_t[0x100]};
	kernel_copyout(kernel_base + offsets::root_vnode(), rootvnode_area_store.get(), 0x100);
	uint32_t uid_store = 0;
	uint32_t ngroups_store = 0;
	uint64_t authid_store = 0x4801000000000013l;
	int64_t caps_store = -1;
	uint8_t attr_store[] = {0x80, 0, 0, 0, 0, 0, 0, 0};

	copyin(ucred + 0x04, &uid_store, 0x4);		  // cr_uid
	copyin(ucred + 0x08, &uid_store, 0x4);		  // cr_ruid
	copyin(ucred + 0x0C, &uid_store, 0x4);		  // cr_svuid
	
	copyin(ucred + 0x10, &ngroups_store, 0x4);	  // cr_ngroups
	copyin(ucred + 0x14, &uid_store, 0x4);		  // cr_rgid

	if (escapeSandbox) {
		// Escape sandbox
		copyin(fd + 0x10, rootvnode_area_store.get(), 0x8);  // fd_rdir
		copyin(fd + 0x18, rootvnode_area_store.get(), 0x8);  // fd_jdir
	}

	// Escalate sony privileges
	copyin(ucred + 0x58, &authid_store, 0x8);	 // cr_sceAuthID
	copyin(ucred + 0x60, &caps_store, 0x8);		 // cr_sceCaps[0]
	copyin(ucred + 0x68, &caps_store, 0x8);		 // cr_sceCaps[1]
	copyin(ucred + 0x83, attr_store, 0x1);		 // cr_sceAttr[0]
}

uintptr_t Hijacker::getFunctionAddress(const SharedLib *lib, const Nid &fname) const noexcept {
	RtldMeta *meta = lib->getMetaData();
	rtld::ElfSymbol sym = meta->getSymbolTable()[fname];
	#ifdef DEBUG
	if (!sym) [[unlikely]] {
		fatalf("failed to get symbol for %s %s\n", lib->getPath().c_str(), fname.str);
	}
	#endif
	return sym ? sym.vaddr() : 0;
}
// NOLINTEND
