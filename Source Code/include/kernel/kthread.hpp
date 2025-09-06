#pragma once
#include "kernel.hpp"
#include "frame.hpp"

namespace {

static constexpr size_t THREAD_SIZE = 0x680;

}

class KThread : public KernelObject<KThread, THREAD_SIZE> {

	static constexpr size_t TID_OFFSET = 0x9c;
	static constexpr size_t FRAME_OFFSET = 0x460;

	public:
		KThread(uintptr_t addr) : KernelObject(addr) {}

		UniquePtr<TrapFrame> getFrame() {
			uintptr_t ptr = get<uintptr_t, FRAME_OFFSET>();
			return ptr ? new TrapFrame(ptr) : nullptr;
		}

		int tid() const {
			return get<int, TID_OFFSET>();
		}
};
