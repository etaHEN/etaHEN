#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

extern "C" {
    #include <ps5/kernel.h>
}

#include "debug_log.h"
#include "kdlsym.h"
#include "kexec.h"
#include "mirror.h"
#include "util.h"

void install_custom_syscall(int sysc, uint32_t num_args, uint64_t gadget)
{
    void *sysent_mirror;
    struct sysent *entry;
    uint64_t ppr_sysent         = kdlsym(KERNEL_SYM_PPR_SYSENT);
    uint64_t sysc_sysent_offset = sysc * sizeof(struct sysent);
    uint64_t target             = ppr_sysent + sysc_sysent_offset;

    // Mirror sysent entry
    sysent_mirror = get_mirrored_addr(target);
    entry = (struct sysent *) sysent_mirror;

    //SOCK_LOG("[+] prev sysent for syscall %d:\n", sysc);
    DumpHex(sysent_mirror, sizeof(struct sysent));

    entry->n_arg     = num_args;
    entry->sy_call   = gadget;
    entry->sy_flags  = 0;
    entry->sy_thrcnt = 1;

    //SOCK_LOG("[+] cur  sysent for syscall %d:\n", sysc);
    DumpHex(sysent_mirror, sizeof(struct sysent));

    //SOCK_LOG("[+] installed 0x%lx to 0x%lx (0x%lx)\n", gadget, target, sysc_sysent_offset);
}

void install_kexec()
{
    install_custom_syscall(0x11, 2, kdlsym(KERNEL_SYM_GADGET_JMP_PTR_RSI));
}

int kexec(uint64_t fptr)
{
    // struct kexec_args args;

    // args.fptr           = fptr;
    // args.fw             = kernel_get_fw_version() & 0xFFFF0000;
    // args.kernel_base    = ktext(0);

    return syscall(0x11, fptr, kernel_get_fw_version() & 0xFFFF0000, ktext(0));
}
