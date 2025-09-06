#pragma once
#include "kernel.hpp"

// "allocates" memory from another process out of EXISTING process memory
class ProcessMemoryAllocator {
	static constexpr size_t ALIGNMENT = 0x10;
	static constexpr size_t ALIGNMENT_MASK = 0xf;
	const SharedLibSection *section;
	size_t allocated;

	public:
		ProcessMemoryAllocator(decltype(nullptr)) : section(nullptr), allocated() {}
		ProcessMemoryAllocator(const SharedLibSection *section) : section(section), allocated() {}

		/**
		 * "Releases" all the allocated memory
		 */
		void release() {
			allocated = 0;
		}

		/**
		 * Allocated virtual memory from the end of the existing section.
		 * It is allocated from the end because this portion of memory is likely unused.
		 * @param size the size of memory to "allocate"
		 * @return the virtual address for the requested memory
		 */
		uintptr_t allocate(size_t size) {
			if ((size & ALIGNMENT_MASK) != 0) {
				size = (size & ~ALIGNMENT_MASK) + ALIGNMENT;
			}
			allocated += size;
			return section->end() - allocated;
		}

		operator bool() const {
			return section != nullptr;
		}

		bool operator==(decltype(nullptr)) const {
			return section == nullptr;
		}
};
