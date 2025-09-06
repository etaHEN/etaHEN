#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern "C" {
#include <ps5/kernel.h>
}

#include "debug_log.h"
#include "kdlsym.h"
#include "paging.h"

uint64_t g_dmap_base = 0;

uint64_t get_proc_pmap()
{
    pid_t pid;
    uint64_t proc;
    uint64_t p_vmspace;
    uint64_t vm_pmap;

    // Get process pid
    pid = getpid();

    // Get proc
    proc = kernel_get_proc(pid);
    ////SOCK_LOG("get_proc_pmap: proc=0x%lx\n", proc);
    if (proc == 0) {
        ////SOCK_LOG("get_proc_pmap: proc is null\n");
        return 0;
    }

    // Get proc->p_vmspace
    kernel_copyout(proc + KERNEL_OFFSET_PROC_P_VMSPACE, &p_vmspace, sizeof(p_vmspace));
    ////SOCK_LOG("get_proc_pmap: vmspace=0x%lx\n", p_vmspace);
    if (p_vmspace == 0) {
        ////SOCK_LOG("get_proc_pmap: vmspace is null\n");
        return 0;
    }

    // Get vmspace->vm_pmap
    kernel_copyout(p_vmspace + KERNEL_OFFSET_VMSPACE_VM_PMAP, &vm_pmap, sizeof(vm_pmap));
    ////SOCK_LOG("get_proc_pmap: pmap=0x%lx\n", vm_pmap);
    if (vm_pmap == 0) {
        ////SOCK_LOG("get_proc_pmap: pmap is null\n");
        return 0;
    }

    return vm_pmap;
}

void init_dmap_resolve()
{
    uint64_t DMPML4I;
    uint64_t DMPDPI;
    uint64_t PML4PML4I;

    kernel_copyout(kdlsym(KERNEL_SYM_DMPML4I), &DMPML4I, sizeof(int));
    kernel_copyout(kdlsym(KERNEL_SYM_DMPDPI), &DMPDPI, sizeof(int));
    kernel_copyout(kdlsym(KERNEL_SYM_PML4PML4I), &PML4PML4I, sizeof(int));

    g_dmap_base = (DMPDPI << 30) | (DMPML4I << 39) | 0xFFFF800000000000;
}

uint64_t get_dmap_addr(uint64_t pa)
{
    // Init dmap resolve if it's not initialized already
    if (g_dmap_base == 0)
        init_dmap_resolve();

    return g_dmap_base + pa;
}

uint64_t pmap_kextract(uint64_t va)
{
    uint64_t DMPML4I;
    uint64_t DMPDPI;
    uint64_t PML4PML4I;
    uint64_t dmap;
    uint64_t dmap_end;
    uint64_t pde_addr;
    uint64_t pte_addr;
    uint64_t pde;
    uint64_t pte;

    kernel_copyout(kdlsym(KERNEL_SYM_DMPML4I), &DMPML4I, sizeof(int));
    kernel_copyout(kdlsym(KERNEL_SYM_DMPDPI), &DMPDPI, sizeof(int));
    kernel_copyout(kdlsym(KERNEL_SYM_PML4PML4I), &PML4PML4I, sizeof(int));

    dmap     = (DMPDPI << 30) | (DMPML4I << 39) | 0xFFFF800000000000;
    dmap_end = ((DMPML4I +1 ) << 39) | 0xFFFF800000000000;

    if (dmap <= va && dmap_end > va) {
        return va - dmap;
    }

    pde_addr = ((PML4PML4I << 39) | (PML4PML4I << 30) | 0xFFFF800000000000) + 8 * ((va >> 21) & 0x7FFFFFF);

    kernel_copyout(pde_addr, &pde, sizeof(pde));
    if (pde & 0x80) {
        return (pde & 0xFFFFFFFE00000) | (va & 0x1FFFFF);
    }

    pte_addr = ((va >> 9) & 0xFE0) + dmap + (pde & 0xFFFFFFFFFF000);
    kernel_copyout(pte_addr, &pte, sizeof(pte));

    return (pte & 0xFFFFFFFFFF000) | (va & 0x3FFF);
}

uint64_t find_pml4e(uint64_t pmap, uint64_t va, uint64_t *out_pml4e)
{
    uint64_t pml4e_addr;
    uint64_t pm_pml4;

    // Get pmap->pm_pml4
    kernel_copyout(pmap + KERNEL_OFFSET_PMAP_PM_PML4, &pm_pml4, sizeof(pm_pml4));
    if (pm_pml4 == 0) {
        return 0xFFFFFFFFFFFFFFFFull;
    }
    ////SOCK_LOG("pm_pml4 = 0x%lx\n", pm_pml4);

    // Calculate pml4 entry via index encoded in virtual addr
    pml4e_addr = pm_pml4 + (((va >> 39) & 0x1FF) * 8);

    // Copy pml4e out and return address of it
    kernel_copyout(pml4e_addr, (char *) out_pml4e, sizeof(uint64_t));
    ////SOCK_LOG("find_pml4e(0x%lx): pml4e addr = 0x%lx, pml4e = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, xo: 0x%lx)\n",
    //    va, pml4e_addr, *out_pml4e, PDE_FIELD(*out_pml4e, RW), PDE_FIELD(*out_pml4e, EXECUTE_DISABLE), PDE_FIELD(*out_pml4e, USER), PDE_FIELD(*out_pml4e, XOTEXT));
    return pml4e_addr;
}

uint64_t find_pdpe(uint64_t pmap, uint64_t va, uint64_t *out_pdpe)
{
    uint64_t pdpe_addr;
    uint64_t pdp_table_pml4_entry;
    uint64_t pdp_table_dmap_addr;

    // Get pdp table address from pml4 entry
    if (find_pml4e(pmap, va, &pdp_table_pml4_entry) == 0xFFFFFFFFFFFFFFFFull) {
        return 0xFFFFFFFFFFFFFFFFull;
    }

    // Calculate pdp entry via index encoded in virtual addr
    pdp_table_dmap_addr     = get_dmap_addr(PDE_ADDR(pdp_table_pml4_entry));
    pdpe_addr               = pdp_table_dmap_addr + (((va >> 30) & 0x1FF) * 8);

    // Copy pdpe out and return address of it
    kernel_copyout(pdpe_addr, (char *) out_pdpe, sizeof(uint64_t));
    ////SOCK_LOG("find_pdpe(0x%lx): pdpe addr = 0x%lx, pdpe = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, xo: 0x%lx)\n",
    //    va, pdpe_addr, *out_pdpe, PDE_FIELD(*out_pdpe, RW), PDE_FIELD(*out_pdpe, EXECUTE_DISABLE), PDE_FIELD(*out_pdpe, USER), PDE_FIELD(*out_pdpe, XOTEXT));
    return pdpe_addr;
}

uint64_t find_pde(uint64_t pmap, uint64_t va, uint64_t *out_pde)
{
    uint64_t pde_addr;
    uint64_t pd_table_pdp_entry;
    uint64_t pd_table_dmap_addr;

    // Get pd table address from pdp entry
    if (find_pdpe(pmap, va, &pd_table_pdp_entry) == 0xFFFFFFFFFFFFFFFFull) {
        return 0xFFFFFFFFFFFFFFFFull;
    }

    // Calculate pd entry via index encoded in virtual addr
    pd_table_dmap_addr      = get_dmap_addr(PDE_ADDR(pd_table_pdp_entry));
    pde_addr                = pd_table_dmap_addr + (((va >> 21) & 0x1FF) * 8);

    // Copy pde out and return address of it
    kernel_copyout(pde_addr, (char *) out_pde, sizeof(uint64_t));
    ////SOCK_LOG("find_pde(0x%lx): pde addr = 0x%lx, pde = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, xo: 0x%lx)\n",
    //    va, pde_addr, *out_pde, PDE_FIELD(*out_pde, RW), PDE_FIELD(*out_pde, EXECUTE_DISABLE), PDE_FIELD(*out_pde, USER), PDE_FIELD(*out_pde, XOTEXT));
    return pde_addr;
}

uint64_t find_pte(uint64_t pmap, uint64_t va, uint64_t *out_pte)
{
    uint64_t pte_addr;
    uint64_t page_table_pde_entry;
    uint64_t page_table_dmap_addr;

    // Get page table address from pde entry
    if (find_pde(pmap, va, &page_table_pde_entry) == 0xFFFFFFFFFFFFFFFFull) {
        return 0xFFFFFFFFFFFFFFFFull;
    }

    // Calculate pt entry via index encoded in virtual addr
    page_table_dmap_addr    = get_dmap_addr(PDE_ADDR(page_table_pde_entry));
    pte_addr                = page_table_dmap_addr + (((va >> 12) & 0x1FF) * 8);

    // Copy pte out and return address of it
    kernel_copyout(pte_addr, (char *) out_pte, sizeof(uint64_t));
    ////SOCK_LOG("find_pte(0x%lx): pte addr = 0x%lx, pte = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, xo: 0x%lx)\n",
    //    va, pte_addr, *out_pte, PDE_FIELD(*out_pte, RW), PDE_FIELD(*out_pte, EXECUTE_DISABLE), PDE_FIELD(*out_pte, USER), PDE_FIELD(*out_pte, XOTEXT));
    return pte_addr;
}

int downgrade_kernel_superpages(uint64_t va, uint64_t kernel_pt_addr)
{
    uint64_t kernel_pmap;
    uint64_t pde_addr;
    uint64_t pde;
    uint64_t new_pte;
    uint64_t new_pt_pa;
    uint64_t cur_pa;

    // Get kernel pmap
    kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);

    // Get the PDE of the address and check if it actually is a superpage
    pde_addr = find_pde(kernel_pmap, va, &pde);
    if (pde_addr == 0xFFFFFFFFFFFFFFFFull) {
        //SOCK_LOG("downgrade_kernel_superpages: va = 0x%lx, could not find PDE\n", va);
        return -1;
    }

    if (PDE_FIELD(pde, PS) != 1) {
        //SOCK_LOG("downgrade_kernel_superpages: va = 0x%lx is not a superpage\n", va);
        return -1;
    }

    //SOCK_LOG("downgrade_kernel_superpages: va = 0x%lx, downgrading to small pages\n", va);

    cur_pa      = pde & PDE_ADDR_MASK;

    // Construct PTEs
    for (int i = 0; i < 512; i++) {
        new_pte  = 0;
        SET_PDE_FIELD(new_pte, RW, PDE_FIELD(pde, RW));
        SET_PDE_FIELD(new_pte, USER, PDE_FIELD(pde, USER));
        SET_PDE_FIELD(new_pte, DIRTY, PDE_FIELD(pde, DIRTY));
        SET_PDE_FIELD(new_pte, GLOBAL, PDE_FIELD(pde, GLOBAL));
        SET_PDE_FIELD(new_pte, XOTEXT, PDE_FIELD(pde, PROTECTION_KEY));
        SET_PDE_FIELD(new_pte, EXECUTE_DISABLE, PDE_FIELD(pde, EXECUTE_DISABLE));
        SET_PDE_ADDR(new_pte, cur_pa);
        SET_PDE_BIT(new_pte, PRESENT);

        kernel_copyin(&new_pte, kernel_pt_addr + (i * 0x8), sizeof(new_pte));
        cur_pa += 0x1000;
    }

    // Get the physical address of the newly created page table
    new_pt_pa = pmap_kextract(kernel_pt_addr);

    // Update PDE
    SET_PDE_BIT(pde, RW);
    CLEAR_PDE_BIT(pde, PS);
    CLEAR_PDE_BIT(pde, GLOBAL);
    CLEAR_PDE_BIT(pde, XOTEXT);
    SET_PDE_ADDR(pde, new_pt_pa);

    //SOCK_LOG("downgrade_kernel_superpages: updating PDE @ 0x%lx to 0x%lx\n", pde_addr, pde);
    kernel_copyin(&pde, pde_addr, sizeof(pde));

    return 0;
}

uint64_t remap_page(uint64_t pmap, uint64_t va, uint64_t new_pa)
{
    uint64_t pde_addr;
    uint64_t pde = 0;
    uint64_t pte_addr;
    uint64_t pte = 0;
    uint64_t orig_pa;

    pte_addr = find_pte(pmap, va, &pte);
    if (pte_addr != 0xFFFFFFFFFFFFFFFFull) {
        orig_pa = PDE_ADDR(pte);
        SET_PDE_ADDR(pte, new_pa);
        kernel_copyin(&pte, pte_addr, sizeof(pte));
        ////SOCK_LOG("remap_page: va = 0x%lx, new pa = 0x%lx (old pa = 0x%lx)\n", va, new_pa, orig_pa);
        return orig_pa;
    }

    ////SOCK_LOG("remap_page: va = 0x%lx, could not find PTE, trying PDE\n", va);
    pde_addr = find_pde(pmap, va, &pde);
    if (pde_addr != 0xFFFFFFFFFFFFFFFFull && (PDE_FIELD(pde, PS) == 1)) {
        orig_pa = PDE_ADDR(pde);
        SET_PDE_ADDR(pde, new_pa);
        kernel_copyin(&pde, pde_addr, sizeof(pde));
        ////SOCK_LOG("remap_page: va = 0x%lx, new pa = 0x%lx (old pa = 0x%lx)\n", va, new_pa, orig_pa);
        return orig_pa;
    }
    
    ////SOCK_LOG("remap_page: va = 0x%lx, could not find PDE either (or PDE is not a leaf)\n", va);
    return 0xFFFFFFFFFFFFFFFFull;
}
