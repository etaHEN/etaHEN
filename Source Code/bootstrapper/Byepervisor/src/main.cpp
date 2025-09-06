#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

extern "C" {
#include <ps5/kernel.h>
#include "hen.h"

}

#include "config.h"
#include "debug_log.h"
#include "kdlsym.h"
#include "kexec.h"
#include "mirror.h"
#include "paging.h"
#include "patching.h"
#include "self.h"
#include "util.h"

struct UserServiceLoginUserIdList
{
	int user_id[4];
};


extern "C"
{
    int sceKernelSleep(int secs);
    int sceKernelLoadStartModule(char *name, size_t argc, const void *argv, uint32_t flags, void *unk, int *res);
    int __sys_is_development_mode();

    int sceUserServiceGetLoginUserIdList(UserServiceLoginUserIdList *userIdList);
    int sceKernelPrepareToSuspendProcess(pid_t pid);
    int sceKernelSuspendProcess(pid_t pid);

    __asm__ (
    ".section .rodata\n"
    ".global KELF\n"
    ".type KELF, @object\n"
    ".align 16\n"
    "KELF:\n"
    ".incbin \"../hen/hen.bin\"\n"  // Path to binary file
    "KELF_END:\n"
    ".global KELF_SZ\n"
    ".type KELF_SZ, @object\n"
    ".align 16\n"
    "KELF_SZ:\n"
    ".quad KELF_END - KELF\n"
);

int sceSystemStateMgrEnterStandby(void);
}

bool Byepervisor()
{
    uint64_t kernel_pmap;
    uint64_t pte_addr;
    uint64_t pde_addr;
    uint64_t pte;
    uint64_t pde;

    // Set shellcore auth ID
    kernel_set_ucred_authid(getpid(), 0x4800000000000007);

    // Jailbreak
    kernel_set_proc_rootdir(getpid(), kernel_get_root_vnode());

    kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);

    for (uint64_t addr = ktext(0); addr < KERNEL_ADDRESS_DATA_BASE; addr += 0x1000) {
        pde_addr = find_pde(kernel_pmap, addr, &pde);
        if (pde_addr != 0xFFFFFFFFFFFFFFFFull) {
            CLEAR_PDE_BIT(pde, XOTEXT);
            SET_PDE_BIT(pde, RW);
            kernel_copyin(&pde, pde_addr, sizeof(pde));
        }

        pte_addr = find_pte(kernel_pmap, addr, &pte);
        if (pte_addr != 0xFFFFFFFFFFFFFFFFull) {
            CLEAR_PDE_BIT(pte, XOTEXT);
            SET_PDE_BIT(pte, RW);
            kernel_copyin(&pte, pte_addr, sizeof(pte));
        }
    }

    // Check if this is a resume state or not, if it's not, prompt for restart and exit
    if (kernel_read4(kdlsym(KERNEL_SYM_DATA_CAVE)) != 0x1337) {
        // Notify the user that they have to suspend/resume their console
        flash_notification("[etaHEN] Entering rest mode for Byepervisor in 3 secs\nRe-run etaHEN after resuming to continue...");
        kernel_write4(kdlsym(KERNEL_SYM_DATA_CAVE), 0x1337);
        sleep(3);
        sceSystemStateMgrEnterStandby();
        return false;
    }
    
    // Print out the kernel base
     printf("[+] Kernel base = 0x%lx\n", ktext(0));

    // run_dump_server(9003);
    // reset_mirrors();
    // return 0;

    // Apply patches
    if (apply_kernel_patches() != 0) {
         flash_notification("[!] Applying kernel patches failed, firmware likely not supported\n");
        return false;
    }

    // Calculate the remaining blocks after 0x1000 segments
    uint64_t KELF_REMAINING = KELF_SZ % 0x1000;

    // Calculate the number of blocks to copy
    uint64_t KELF_BLOCK_COPIES = KELF_SZ / 0x1000;

    // Calculate the offset of the remaining data
    uint64_t KELF_REMAINING_START_OFFSET = KELF_BLOCK_COPIES * 0x1000;

    // Copy hen into kernel code cave
    for (uint32_t i = 0; i < KELF_SZ; i += 0x1000) {
        kernel_copyin(&KELF[i], kdlsym(KERNEL_SYM_CODE_CAVE) + i, 0x1000);
    }
    if (KELF_REMAINING != 0)
        kernel_copyin(&KELF[KELF_REMAINING_START_OFFSET], kdlsym(KERNEL_SYM_CODE_CAVE) + KELF_REMAINING_START_OFFSET, KELF_REMAINING);

    // Install kexec syscall
    printf("[+] Installing kexec syscall\n");
    install_kexec();

    // Print out the development mode before and after jailbreak
    printf("[+] Bef. hook is_development_mode = 0x%x\n", __sys_is_development_mode());

    // Run hen from the code cave
    int test_ret = kexec(kdlsym(KERNEL_SYM_CODE_CAVE));
    printf("[+] kexec returned: 0x%x\n", test_ret);

    printf("[+] Aft. hook is_development_mode = 0x%x\n", __sys_is_development_mode());

    reset_mirrors();
    //run_self_server(9004);
    return true;
}
