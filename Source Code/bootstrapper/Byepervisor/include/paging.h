#ifndef PAGING_H
#define PAGING_H

enum pde_shift {
    PDE_PRESENT = 0,
    PDE_RW,
    PDE_USER,
    PDE_WRITE_THROUGH,
    PDE_CACHE_DISABLE,
    PDE_ACCESSED,
    PDE_DIRTY,
    PDE_PS,
    PDE_GLOBAL,
    PDE_XOTEXT = 58,
    PDE_PROTECTION_KEY = 59,
    PDE_EXECUTE_DISABLE = 63
};

#define PDE_PRESENT_MASK                1UL
#define PDE_RW_MASK                     1UL
#define PDE_USER_MASK                   1UL
#define PDE_WRITE_THROUGH_MASK          1UL
#define PDE_CACHE_DISABLE_MASK          1UL
#define PDE_ACCESSED_MASK               1UL
#define PDE_DIRTY_MASK                  1UL
#define PDE_PS_MASK                     1UL
#define PDE_GLOBAL_MASK                 1UL
#define PDE_XOTEXT_MASK                 1UL
#define PDE_PROTECTION_KEY_MASK         0xFUL
#define PDE_EXECUTE_DISABLE_MASK        1UL
#define PDE_ADDR_MASK                   0xffffffffff800ULL  // bits [12, 51]

#define PDE_FIELD(pde, name)            (((pde) >> PDE_##name) & PDE_##name##_MASK)
#define PDE_ADDR(pde)                   (pde & PDE_ADDR_MASK)
#define SET_PDE_FIELD(pde, name, val)   (pde |= (val << PDE_##name))
#define SET_PDE_BIT(pde, name)          (pde |= (PDE_##name##_MASK << PDE_##name))
#define CLEAR_PDE_BIT(pde, name)        (pde &= ~(PDE_##name##_MASK << PDE_##name))
#define SET_PDE_ADDR(pde, addr)         do { \
                                            pde &= ~(PDE_ADDR_MASK); \
                                            pde |= (addr & PDE_ADDR_MASK); \
                                        } while (0)

#define KERNEL_OFFSET_PROC_P_VMSPACE    0x200
#define KERNEL_OFFSET_VMSPACE_VM_PMAP   0x1D0
#define KERNEL_OFFSET_PMAP_PM_PML4      0x020

uint64_t get_proc_pmap();
uint64_t pmap_kextract(uint64_t va);
uint64_t get_dmap_addr(uint64_t pa);

uint64_t find_pml4e(uint64_t pmap, uint64_t va, uint64_t *out_pml4e);
uint64_t find_pdpe(uint64_t pmap, uint64_t va, uint64_t *out_pdpe);
uint64_t find_pde(uint64_t pmap, uint64_t va, uint64_t *out_pde);
uint64_t find_pte(uint64_t pmap, uint64_t va, uint64_t *out_pte);

int downgrade_kernel_superpages(uint64_t va, uint64_t kernel_pt_addr);
uint64_t remap_page(uint64_t pmap, uint64_t va, uint64_t new_pa);

#endif // PAGING_H