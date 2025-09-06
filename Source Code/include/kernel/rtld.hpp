#pragma once

#include "kernel.hpp"
#include "nid.hpp"
#include "util.hpp"
#include <ps5/kernel.h>
#include <sys/_stdint.h>
#include <sys/types.h>

extern "C" {
	#include <elf.h>
}


class RtldMeta;

// namespace to hold these commonly named classes
// to prevent api conflict in the future
namespace rtld {

class ElfSymbolTable;
class ElfSymbol;
class ElfStringTable;

}

namespace {

static UniquePtr<RtldMeta> newRtldMeta(uintptr_t imageBase, uintptr_t addr);

static UniquePtr<rtld::ElfSymbolTable> newSymbolTable(const RtldMeta *meta);

static UniquePtr<rtld::ElfStringTable> newStringTable(const RtldMeta *meta);

static constexpr size_t SHARED_LIB_SECTION_SIZE = 0x18;
static constexpr size_t SHARED_LIB_SIZE = 0x200;
static constexpr size_t SHARED_OBJECT_SIZE = 0x188;
static constexpr size_t RTLD_META_SIZE = 0x118;

}

enum class SectionType : uint32_t {
	UNKNOWN = 0,
	TEXT = 1,
	XOTEXT = 2,
	RODATA = 4,
	RELRO = 8,
	DATA = 16,
	INVALID = (uint32_t)-1
};

class SharedLibSection : public KernelObject<SharedLibSection, SHARED_LIB_SECTION_SIZE> {

	friend class SharedLib;

	static constexpr size_t TYPE_OFFSET = 8;
	static constexpr size_t ADDRESS_OFFSET = 8;
	static constexpr size_t LENGTH_OFFSET = 16;

	mutable SectionType _type;

	public:
		SharedLibSection() = default;
		SharedLibSection(uintptr_t addr) : KernelObject(addr), _type(SectionType::INVALID) {}

		SectionType type() const {
			if (_type == SectionType::INVALID) {
				_type = kread<SectionType>(get<uintptr_t, 0>() + TYPE_OFFSET);
			}
			return _type;
		}

		uintptr_t start() const {
			return get<uintptr_t, ADDRESS_OFFSET>();
		}

		uintptr_t end() const {
			return start() + sectionLength();
		}

		size_t sectionLength() const {
			return get<size_t, LENGTH_OFFSET>();
		}
};

struct EhFrameInfo {
	uintptr_t hdr;
	size_t hdrSize;
	uintptr_t frame;
	size_t frameSize;
};

class SharedLib : public KernelObject<SharedLib, SHARED_LIB_SIZE> {

	static constexpr size_t DYNLIB_OFFSET = 0x148;
	static constexpr size_t HANDLE_OFFSET = 0x28;
	static constexpr size_t PATH_OFFSET = 0x8;
	static constexpr size_t NUM_SECTIONS_OFFSET = 0x48;
	static constexpr size_t SECTIONS_OFFSET = 0x40;
	static constexpr size_t IMAGEBASE_OFFSET = 0x30;
	static constexpr size_t EHFRAME_OFFSET = 0xf8;
	static constexpr size_t EHFRAME_HDR_SIZE_OFFSET = 0x100;
	static constexpr size_t EHFRAME_HDR_OFFSET = 0x108;
	static constexpr size_t EHFRAME_SIZE_OFFSET = 0x110;

	mutable String path;
	mutable Array<SharedLibSection> sections;
	mutable UniquePtr<RtldMeta> meta;

	public:
		int pid;

		SharedLib(uintptr_t addr, int pid)
			: KernelObject(addr), path(nullptr), sections(nullptr), meta(nullptr), pid(pid) {}

		int handle() const {
			return get<int, HANDLE_OFFSET>();
		}

		StringView getPath() const {
			if (path.length() == 0) [[unlikely]] {
				path = getString<PATH_OFFSET>();
			}
			return {path.c_str(), path.length()};
		}

		const Array<SharedLibSection> &getSections() const {
			if (sections == nullptr) [[unlikely]] {
				size_t numSections = get<size_t, NUM_SECTIONS_OFFSET>();
				uintptr_t ptr = get<uintptr_t, SECTIONS_OFFSET>();
				sections = Array<SharedLibSection>{numSections};
				for (size_t i = 0; i < numSections; i++) {
					sections[i] = SharedLibSection{ptr + (i * SharedLibSection::length)};
				}
			}
			return sections;
		}

		const SharedLibSection *getTextSection() const {
			for (SharedLibSection &section : getSections()) {
				SectionType type = section.type();
				if (type == SectionType::XOTEXT || type == SectionType::TEXT) {
					return &section;
				}
			}
			return nullptr;
		}

		void setTextAddress(uintptr_t addr) {
			const SharedLibSection *section = getTextSection();
			kwrite<uintptr_t>(section->address() + SharedLibSection::ADDRESS_OFFSET, addr);
		}

		void setRoDataAddress(uintptr_t addr) {
			const SharedLibSection *section = getRoDataSection();
			kwrite<uintptr_t>(section->address() + SharedLibSection::ADDRESS_OFFSET, addr);
		}

		const SharedLibSection *getDataSection() const {
			for (SharedLibSection &section : getSections()) {
				if (section.type() == SectionType::DATA) {
					return &section;
				}
			}
			return nullptr;
		}

		const SharedLibSection *getRoDataSection() const {
			for (SharedLibSection &section : getSections()) {
				if (section.type() == SectionType::RODATA) {
					return &section;
				}
			}
			return nullptr;
		}

		uintptr_t imagebase() const {
			return get<uintptr_t, IMAGEBASE_OFFSET>();
		}

		void imagebase(uintptr_t base) {
			kwrite<uintptr_t>(address() + IMAGEBASE_OFFSET, base);
		}

		RtldMeta *getMetaData() const {
			if (meta == nullptr) [[unlikely]] {
				uintptr_t addr = getMetaDataAddress();
				if (addr) {
					meta = newRtldMeta(imagebase(), addr);
				} else {
					puts("null metadata");
				}
			}
			return meta.get();
		}

		uintptr_t getMetaDataAddress() const {
			return get<uintptr_t, DYNLIB_OFFSET>();
		}

		EhFrameInfo getEhFrameInfo() const {
			return get<EhFrameInfo, EHFRAME_OFFSET>();
		}

		void setEhFrameInfo(const EhFrameInfo &info) const {
			kwrite<EhFrameInfo>(address() + EHFRAME_OFFSET, info);
		}

		uintptr_t getEhFrameHdr() const {
			return get<uintptr_t, EHFRAME_OFFSET>();
		}

		void setEhFrameHdr(uintptr_t value) {
			set<EHFRAME_OFFSET>(value);
		}

		size_t getEhFrameHdrSize() const {
			return get<size_t, EHFRAME_HDR_SIZE_OFFSET>();
		}

		void setEhFrameHdrSize(uintptr_t value)  {
			set<EHFRAME_HDR_SIZE_OFFSET>(value);
		}

		uintptr_t getEhFrame() const {
			return get<uintptr_t, EHFRAME_HDR_OFFSET>();
		}

		void setEhFrame(uintptr_t value) {
			set<EHFRAME_HDR_OFFSET>(value);
		}

		size_t getEhFrameSize() const {
			return get<size_t, EHFRAME_SIZE_OFFSET>();
		}

		void setEhFrameSize(uintptr_t value) {
			set<EHFRAME_SIZE_OFFSET>(value);
		}
};

class SharedLibIterable {

	uintptr_t addr;
	int pid;

	public:
		SharedLibIterable(decltype(nullptr)) : addr(), pid() {}
		SharedLibIterable(uintptr_t addr, int pid) : addr(addr), pid(pid) {}
		bool operator!=(decltype(nullptr)) const { return addr != 0; }
		UniquePtr<SharedLib> operator*() {
			return new SharedLib{addr, pid};
		}
		SharedLibIterable &operator++() {
			uintptr_t ptr = 0;
			kernel_copyout(addr, &ptr, sizeof(ptr));
			addr = ptr;
			return *this;
		}
		uintptr_t getAddress() const noexcept {
			return addr;
		}
};

struct SharedLibIterator {

	uintptr_t addr;
	int pid;

	SharedLibIterator(uintptr_t addr, int pid) : addr(addr), pid(pid) {}
	SharedLibIterable begin() const {
		return {addr, pid};
	}
	decltype(nullptr) end() const {
		return nullptr;
	}

};

class SharedObject : KernelObject<SharedObject, SHARED_OBJECT_SIZE> {

	static constexpr size_t EBOOT_OFFSET = 0;

	mutable UniquePtr<SharedLib> eboot;

	public:
		int pid;

		SharedObject(uintptr_t addr, int pid)
			: KernelObject(addr), eboot(nullptr), pid(pid) {}

		SharedLibIterator getLibs() const {
			return {get<uintptr_t, 0>(), pid};
		}

		SharedLib *getEboot() const {
			if (eboot == nullptr) [[unlikely]] {
				const auto ptr = get<uintptr_t, EBOOT_OFFSET>();
				if (ptr == 0) [[unlikely]] {
					return nullptr;
				}
				eboot = new SharedLib{ptr, pid};
			}
			return eboot.get();
		}

		UniquePtr<SharedLib> getLib(int handle) const {
			for (auto lib : getLibs()) {
				if (lib->handle() == handle) {
					return lib.release();
				}
			}
			return nullptr;
		}
		

		UniquePtr<SharedLib> getLib(const StringView &name) const {
			String fullname = name;
			if (!name.endswith(".sprx"_sv)) {
				fullname += ".sprx"_sv;
			}
			for (auto lib : getLibs()) {
				printf("lib: %s\n", lib->getPath().c_str());
				if (lib->getPath().endswith(fullname)) {
					return lib.release();
				}
			}
			return nullptr;
		}
};

class RtldMeta : public KernelObject<RtldMeta, RTLD_META_SIZE> {

	static constexpr size_t TOTAL_SIZE_OFFSET = 0x20;
	static constexpr size_t SYMTAB_OFFSET = 0x28;
	static constexpr size_t SYMTAB_SIZE_OFFSET = 0x30;
	static constexpr size_t STRTAB_OFFSET = 0x38;
	static constexpr size_t STRTAB_SIZE_OFFSET = 0x40;
	static constexpr size_t PLTTAB_OFFSET = 0x48;
	static constexpr size_t PLTTAB_SIZE_OFFSET = 0x50;

	// mutable members for caching
	mutable UniquePtr<rtld::ElfSymbolTable> symTable;
	mutable UniquePtr<rtld::ElfStringTable> strTable;
	mutable Array<Elf64_Rela> pltTbl;

	public:
		uintptr_t imageBase;
		RtldMeta(uintptr_t imageBase, uintptr_t addr) :
			KernelObject(addr), symTable(nullptr), strTable(nullptr), pltTbl(nullptr), imageBase(imageBase) {}

		size_t totalSize() const {
			return get<size_t, TOTAL_SIZE_OFFSET>();
		}

		uintptr_t symtab() const {
			return get<uintptr_t, SYMTAB_OFFSET>();
		}

		size_t symtabSize() const {
			return get<size_t, SYMTAB_SIZE_OFFSET>();
		}

		size_t nSymbols() const {
			return symtabSize() / sizeof(Elf64_Sym);
		}

		uintptr_t strtab() const {
			return get<uintptr_t, STRTAB_OFFSET>();
		}

		size_t strtabSize() const {
			return get<size_t, STRTAB_SIZE_OFFSET>();
		}

		uintptr_t plttab() const {
			return get<uintptr_t, PLTTAB_OFFSET>();
		}

		size_t pltTblSize() const {
			return get<size_t, PLTTAB_SIZE_OFFSET>();
		}

		size_t nPlt() const {
			return pltTblSize() / sizeof(Elf64_Rela);
		}

		const rtld::ElfSymbolTable &getSymbolTable() const {
			if (symTable == nullptr) {
				symTable = newSymbolTable(this);
			}
			return *symTable;
		}

		const rtld::ElfStringTable &getStringTable() const {
			if (strTable == nullptr) {
				strTable = newStringTable(this);
			}
			return *strTable;
		}

		const Array<Elf64_Rela> &getPltTable() const {
			if (pltTbl == nullptr) {
				pltTbl = Array<Elf64_Rela>(nPlt());
				kernel_copyout(plttab(), pltTbl.begin(), pltTblSize());
			}
			return pltTbl;
		}
};

class rtld::ElfStringTable {

	size_t size;
	UniquePtr<char[]> tbl;

	public:
		ElfStringTable(const RtldMeta *meta) : size(meta->strtabSize()), tbl(new char[size]) {
			kernel_copyout(meta->strtab(), tbl.get(), size);
		}
		ElfStringTable(const ElfStringTable &) = delete;
		ElfStringTable &operator=(const ElfStringTable &) = delete;
		ElfStringTable(ElfStringTable&&) noexcept = default;
		ElfStringTable &operator=(ElfStringTable&&) noexcept = default;
		~ElfStringTable() noexcept = default;

		StringView operator[](size_t offset) const {
			#ifdef DEBUG
			if (offset >= size) [[unlikely]] {
				fatalf("offset %llu is out of bounds for size %llu\n", offset, size);
			}
			#endif
			return tbl.get() + offset;
		}

		Nid getNid(size_t offset) const {
			return Nid{tbl.get() + offset};
		}

		const char *c_str() const noexcept {
			return tbl.get();
		}
};

class rtld::ElfSymbol : public Elf64_Sym {

	static constexpr auto EXPORT_MASK = 0x30;

	const RtldMeta *meta;

	public:
		ElfSymbol(decltype(nullptr)) : Elf64_Sym(), meta(nullptr) {}
		ElfSymbol(const RtldMeta *meta, const Elf64_Sym &sym) : Elf64_Sym(sym), meta(meta) {}

		StringView name() const {
			return meta->getStringTable()[st_name];
		}

		bool exported() const {
			// exported if the binding is global or weak and shndx is not 0
			return (st_info & EXPORT_MASK) && st_shndx != 0;
		}

		uintptr_t vaddr() const {
			return meta->imageBase + st_value;
		}

		Nid nid() const {
			return meta->getStringTable().getNid(st_name);
		}

		explicit operator bool() const { return meta; }

};


class rtld::ElfSymbolTable {

	const RtldMeta *meta;
	UniquePtr<Elf64_Sym[]> symbols;
	size_t size;

	Elf64_Sym *begin() const {
		return symbols.get();
	}

	Elf64_Sym *end() const {
		return symbols.get() + size;
	}

	public:
		ElfSymbolTable(const RtldMeta *meta) : meta(meta), symbols(new Elf64_Sym[meta->nSymbols()]), size(meta->nSymbols()) {
			kernel_copyout(meta->symtab(), symbols.get(), size * sizeof(Elf64_Sym));
		}

		const ElfSymbol operator[](size_t i) const {
			#ifdef DEBUG
			if (i >= size) [[unlikely]] {
				fatalf("index %llu is out of bounds for length %llu\n", i, size);
			}
			#endif
			return {meta, symbols.get()[i]};
		}

		const Elf64_Sym *getSymbol(size_t i) const {
			return symbols.get() + i;
		}

		ssize_t getSymbolIndex(const Nid &nid) const {
			const ssize_t len = static_cast<ssize_t>(size);
			for (ssize_t i = 0; i < len; i++) {
				if (meta->getStringTable().getNid(symbols[i].st_name) == nid) {
					return i;
				}
			}
			return -1;
		}

		const ElfSymbol operator[](const Nid &nid) const {
			for (Elf64_Sym &esym : *this) {
				ElfSymbol sym{meta, esym};
				if (!sym.exported()) {
					continue;
				}
				if (sym.nid() == nid) {
					return sym;
				}
			}
			return nullptr;
		}

		const ElfSymbol operator[](Nid &&nid) const {
			return this->operator[](nid);
		}

		size_t length() const {
			return size;
		}

		const Elf64_Sym *c_symbols() const noexcept {
			return symbols.get();
		}
};

namespace {

static inline UniquePtr<RtldMeta> newRtldMeta(uintptr_t imageBase, uintptr_t addr) {
	return new RtldMeta(imageBase, addr);
}

static inline UniquePtr<rtld::ElfSymbolTable> newSymbolTable(const RtldMeta *meta) {
	return new rtld::ElfSymbolTable(meta);
}

static inline UniquePtr<rtld::ElfStringTable> newStringTable(const RtldMeta *meta) {
	return new rtld::ElfStringTable(meta);
}

}
