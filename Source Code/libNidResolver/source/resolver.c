#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <elf.h>
#include <stdlib.h>

#include "nid.h"

extern void free(void*);
extern void *malloc(size_t);
extern void kernel_copyout(uint64_t ksrc, void *dest, size_t length);

#define memcpy __builtin_memcpy
#define EXPORT_MASK 0x30
#define INTERNAL_LIBRARY_METADATA_OFFSET 0x28

typedef struct {
	uintptr_t symtab;
	uintptr_t symtab_size;
	uintptr_t strtab;
	uintptr_t strtab_size;
} InternalLibraryMetadata;

typedef struct {
	Nid nid; 		// packed to fit in 12 bytes
	uint32_t index; // index into symtab (which is a 32 bit integer)
} NidKeyValue; // total size is 16 bytes to allow a memcpy size of a multiple of 16

static_assert(sizeof(NidKeyValue) == NID_KEY_VALUE_LENGTH, "sizeof(Nid) != 12");

typedef struct {
	NidKeyValue *restrict nids;
	uint_fast32_t size;
} NidMap;

typedef struct {
	uintptr_t imagebase;
	const Elf64_Sym *restrict symtab;
	size_t symtab_length;
	const char *restrict strtab;
	bool owns_memory;
} LibraryInfo;

typedef struct {
	LibraryInfo lib;
	NidMap nids;
} SymbolLookupTable;

typedef struct {
	SymbolLookupTable *restrict tables;
	size_t allocated_tables;
	size_t num_tables;
} resolver_t;

static int_fast64_t compareNid(const Nid *restrict lhs, const Nid *restrict rhs) {
	const int_fast64_t i = lhs->data.low - rhs->data.low;
	return i != 0 ? i : lhs->data.hi - rhs->data.hi;
}

static int_fast64_t binarySearch(const NidKeyValue *restrict entries, const size_t size, const Nid *restrict key) {
	int_fast64_t lo = 0;
	int_fast64_t hi = ((int_fast64_t)size) - 1;

	while (lo <= hi) {
		const int_fast64_t m = (lo + hi) >> 1;
		const int_fast64_t n = compareNid(&entries[m].nid, key);

		if (n == 0) {
			return m;
		}

		if (n < 0) {
			lo = m + 1;
		} else {
			hi = m - 1;
		}
	}
	return -(lo + 1);
}

static int_fast64_t toIndex(int_fast64_t i) {
	return -(i + 1);
}

static NidKeyValue *insert_nid_at(NidMap *restrict self, const Nid *restrict key, uint_fast32_t i) {
	if (self->size++ == i) {
		NidKeyValue *value = self->nids + i;
		value->nid = *key;
		return value;
	}
	memcpy(self->nids + i + 1, self->nids + i, sizeof(NidKeyValue) * (self->size - i));
	NidKeyValue *value = self->nids + i;
	value->nid = *key;
	return value;
}

static NidKeyValue *insert_nid(NidMap *restrict self, const Nid *restrict key) {
	const int_fast64_t index = binarySearch(self->nids, self->size, key);
	if (index < 0) {
		return insert_nid_at(self, key, toIndex(index));
	}
	return self->nids + index;
}

static const NidKeyValue *get_nid_entry(const NidMap *restrict self, const Nid *restrict key) {
	const int_fast64_t index = binarySearch(self->nids, self->size, key);
	if (index < 0) {
		return NULL;
	}
	return self->nids + index;
}

static void destroy_nids(const NidMap *restrict self) {
	free(self->nids);
}

static void destroy_table(const SymbolLookupTable *restrict self) {
	if (self->lib.owns_memory) {
		free((void*)self->lib.symtab);
		free((void*)self->lib.strtab);
	}
	destroy_nids(&self->nids);
}

void resolver_init(resolver_t *restrict self) {
	*self = (resolver_t) {
		.tables = NULL,
		.allocated_tables = 0,
		.num_tables = 0
	};
}

void resolver_move(resolver_t *restrict self, resolver_t *restrict rhs) {
	*self = *rhs;
	*rhs = (resolver_t) {
		.tables = NULL,
		.allocated_tables = 0,
		.num_tables = 0
	};
}

void resolver_finalize(const resolver_t *restrict self) {
	for (size_t i = 0; i < self->num_tables; i++) {
		destroy_table(self->tables + i);
	}
	free(self->tables);
}

static int is_exported(const Elf64_Sym *restrict sym) {
	return (sym->st_info & EXPORT_MASK) && sym->st_shndx != 0;
}

uintptr_t resolver_lookup_symbol(const resolver_t *restrict self, const char *restrict sym, const size_t length) {
	const Nid nid = make_nid(sym, length);
	for (size_t i = 0; i < self->num_tables; i++) {
		const NidKeyValue *entry = get_nid_entry(&self->tables[i].nids, &nid);
		if (entry) {
			const Elf64_Sym *elf_sym = self->tables[i].lib.symtab + entry->index;
			if (is_exported(elf_sym)) {
				return self->tables[i].lib.imagebase + elf_sym->st_value;
			}
		}
	}
	return 0;
}

int resolver_reserve_library_memory(resolver_t *restrict self, size_t num_libraries) {
	if (num_libraries <= self->allocated_tables) {
		return 0;
	}

	if (self->tables == NULL) {
		self->tables = (SymbolLookupTable *) malloc(num_libraries * sizeof(SymbolLookupTable));
	} else {
		const void *ptr = realloc(self->tables, num_libraries * sizeof(SymbolLookupTable));
		if (ptr == NULL) {
			return -1;
		}
		self->tables = (SymbolLookupTable *)ptr;
	}

	self->allocated_tables = num_libraries;
	return 0;
}

static void fill_lookup_table(SymbolLookupTable *restrict tbl) {
	// remember to skip the first null symbol
	for (size_t i = 1; i < tbl->lib.symtab_length; i++) {
		const Elf64_Sym *restrict sym = tbl->lib.symtab + i;
		Nid nid = *(Nid *)(tbl->lib.strtab + sym->st_name);
		nid.str[NID_LENGTH] = '\0';
		NidKeyValue *pair = insert_nid(&tbl->nids, &nid);
		pair->index = i;
	}
}

int resolver_add_library(resolver_t *restrict self, const uintptr_t imagebase, const Elf64_Sym *restrict symtab, const size_t symtab_length, const char *restrict strtab) {
	if (self->num_tables == self->allocated_tables) {
		if (resolver_reserve_library_memory(self, self->allocated_tables + 1)) {
			return -1;
		}
	}

	self->tables[self->num_tables] = (SymbolLookupTable) {
		.lib = (LibraryInfo) {
			.imagebase = imagebase,
			.symtab = symtab,
			.symtab_length = symtab_length,
			.strtab = strtab,
			.owns_memory = false
		},
		.nids = (NidMap) {
			.nids = malloc(sizeof(NidKeyValue) * symtab_length),
			.size = 0
		}
	};

	fill_lookup_table(self->tables + self->num_tables++);
	return 0;
}

int resolver_add_library_metadata(resolver_t *restrict self, const uintptr_t imagebase, const uintptr_t app_meta) {
	if ((intptr_t)app_meta >= 0) {
		return -1;
	}

	if (self->num_tables == self->allocated_tables) {
		if (resolver_reserve_library_memory(self, self->allocated_tables + 1)) {
			return -1;
		}
	}

	InternalLibraryMetadata meta = {0, 0, 0, 0};
	kernel_copyout(app_meta + INTERNAL_LIBRARY_METADATA_OFFSET, &meta, sizeof(meta));
	if (meta.symtab == 0 || meta.symtab_size == 0 || meta.strtab == 0 || meta.strtab_size == 0) {
		return -1;
	}

	Elf64_Sym *symtab = malloc(meta.symtab_size);
	if (symtab == NULL) {
		return -1;
	}

	kernel_copyout(meta.symtab, symtab, meta.symtab_size);
	if (symtab[1].st_name != 1) {
		free(symtab);
		return -1;
	}

	char *strtab = malloc(meta.strtab_size);
	if (strtab == NULL) {
		free(symtab);
		return -1;
	}

	kernel_copyout(meta.strtab, strtab, meta.strtab_size);
	if (strtab[1] == '\0') {
		free(symtab);
		free(strtab);
		return -1;
	}

	const size_t symtab_length = meta.symtab_size / sizeof(Elf64_Sym);

	self->tables[self->num_tables] = (SymbolLookupTable) {
		.lib = (LibraryInfo) {
			.imagebase = imagebase,
			.symtab = symtab,
			.symtab_length = symtab_length,
			.strtab = strtab,
			.owns_memory = true
		},
		.nids = (NidMap) {
			.nids = malloc(sizeof(NidKeyValue) * symtab_length),
			.size = 0
		}
	};

	fill_lookup_table(self->tables + self->num_tables++);
	return 0;
}
