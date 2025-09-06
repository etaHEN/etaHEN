#pragma once

#include <stddef.h>
#include <elf.h>

#ifdef __cplusplus
extern "C" {
#define restrict __restrict
#endif

typedef struct {
	size_t impl[3];
} resolver_t;

/**
 * @brief Initializes a resolver object
 */
void resolver_init(resolver_t *restrict self);

/**
 * @brief Destroy the resolver object
 *
 * @param self the resolver object
 */
void resolver_finalize(resolver_t *restrict self);

/**
 * @brief Moves the resolver object
 *
 * @param self the resolver object
 * @param rhs the resolver object to be moved
 */
void resolver_move(resolver_t *restrict self, resolver_t *restrict rhs);

/**
 * @brief Reserve memory for a specified number of libraries
 *
 * @param self the resolver object
 * @param num_libraries the number of libraries to reserve memory for
 * @return 0 on success, non-zero on error
 */
int resolver_reserve_library_memory(resolver_t *restrict self, size_t num_libraries);

/**
 * @brief Add a library to the resolver
 *
 * @param self the resolver object
 * @param imagebase the library image base
 * @param symtab the library symbol table
 * @param symtab_length the length of the symbol table
 * @param strtab the library string table
 * @return 0 on success, non-zero on error
 */
int resolver_add_library(resolver_t *restrict self, uintptr_t imagebase, const Elf64_Sym *restrict symtab, size_t symtab_length, const char *restrict strtab);

/**
 * @brief Add a library to the resolver
 *
 * @param self the resolver object
 * @param imagebase the library image base
 * @param app_meta the kernel address of the metadata for the library
 * @return 0 on success, non-zero on error
 */
int resolver_add_library_metadata(resolver_t *restrict self, uintptr_t imagebase, uintptr_t app_meta);

/**
 * @brief Lookup a symbol
 *
 * @param self the resolver object
 * @param sym the symbol to lookup
 * @param length the length of the symbol
 * @return the symbol virtual address if found otherwise 0
 */
uintptr_t resolver_lookup_symbol(const resolver_t *restrict self, const char *restrict sym, size_t length);


#ifdef __cplusplus
}
/**
 * @brief RAII wrapper for the Resolver object
 *
 */
class ManagedResolver : public resolver_t {

	public:
		ManagedResolver() noexcept {
			resolver_init(this);
		}
		ManagedResolver(const ManagedResolver&) = delete;
		ManagedResolver operator=(const ManagedResolver&) = delete;
		ManagedResolver(ManagedResolver &&rhs) noexcept {
			resolver_move(this, &rhs);
		}
		ManagedResolver &operator=(ManagedResolver &&rhs) noexcept {
			resolver_move(this, &rhs);
			return *this;
		}
		~ManagedResolver() noexcept {
			resolver_finalize(this);
		}
		/*! @copydoc reserve_library_memory(resolver_t *restrict, size_t) */
		int reserve_library_memory(size_t num_libraries) noexcept {
			return resolver_reserve_library_memory(this, num_libraries);
		}
		/*! @copydoc resolver_add_library(resolver_t *restrict, const uintptr_t, const Elf64_Sym *restrict, const size_t, const char *restrict) */
		int add_library(const uintptr_t imagebase, const Elf64_Sym *restrict symtab, const size_t symtab_length, const char *restrict strtab) noexcept {
			return resolver_add_library(this, imagebase, symtab, symtab_length, strtab);
		}
		/*! @copydoc resolver_add_library_metadata(resolver_t *restrict, const uintptr_t, const uintptr_t) */
		int add_library_metadata(const uintptr_t imagebase, const uintptr_t app_meta) noexcept {
			return resolver_add_library_metadata(this, imagebase, app_meta);
		}
		/*! @copydoc resolver_lookup_symbol(const resolver_t *restrict, const char *restrict) */
		uintptr_t lookup_symbol(const char *restrict sym, size_t length = 0) noexcept {
			if (length == 0) {
				length = strlen(sym);
			}
			return resolver_lookup_symbol(this, sym, length);
		}
};

#undef restrict
#endif
