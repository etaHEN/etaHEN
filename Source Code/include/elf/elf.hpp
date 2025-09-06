#pragma once

extern "C" {
	#include <elf.h>
	#include <sys/elf64.h>
	#include <ps5/payload.h>
}

#include "hijacker.hpp"
#include "util.hpp"

class ManagedResolver;

constexpr auto i = sizeof(Elf64_Dyn);

class Elf : Elf64_Ehdr {

	public:
		struct MappedMemory {
			uintptr_t mem;
			size_t len;
		};

	private:
	dbg::Tracer tracer;
	const Elf64_Phdr *__restrict phdrs;
	const char *__restrict strtab;
	size_t strtabLength;
	const Elf64_Sym *__restrict symtab;
	size_t symtabLength;
	const Elf64_Rela *__restrict relatbl;
	size_t relaLength;
	const Elf64_Rela *__restrict plt;
	size_t pltLength;
	Hijacker *__restrict hijacker;
	size_t textOffset;
	uintptr_t imagebase;
	uint8_t *data;
	UniquePtr<ManagedResolver> resolver;
	Array<MappedMemory> mappedMemory;
	int jitFd;

	bool processProgramHeaders() noexcept;
	bool parseDynamicTable() noexcept;
	bool processRelocations() noexcept;
	bool processPltRelocations() noexcept;
	bool load() noexcept;
	bool start(uintptr_t args) noexcept;
	uintptr_t setupKernelRW() noexcept;
	uintptr_t getSymbolAddress(const Elf64_Rela *__restrict rel) const noexcept;

	public:
		Elf(Hijacker *hijacker, uint8_t *data) noexcept;
		Elf(const Elf&) = delete;
		Elf &operator=(const Elf&) = delete;
		Elf(Elf&&) noexcept = default;
		Elf &operator=(Elf&&) noexcept = default;
		~Elf() noexcept; // external linkage to prevent undefined behavior

		bool launch() noexcept;
		explicit operator bool() const noexcept {
			return static_cast<bool>(tracer);
		}
};
