extern "C"{
#include "../include/ucred.h"
}
#define UCRED_SIZE 0x200


uintptr_t set_ucred_to_debugger()
{
    return set_proc_authid(getpid(), DEBUG_AUTHID);
}


//
// Search process entr on the allproc linked list
// acquire the "ucred" structure and set it
uintptr_t set_proc_authid(pid_t pid, uintptr_t new_authid)
{
    struct proc* proc = get_proc_by_pid(getpid());

    if (proc)
    {
        //
        // Read from kernel
        //
        uintptr_t authid = 0;
        kernel_copyout((uintptr_t) proc->p_ucred + 0x58, &authid, sizeof(uintptr_t));
        kernel_copyin(&new_authid, (uintptr_t) proc->p_ucred + 0x58, sizeof(uintptr_t));

        free(proc);

        return authid;
    }

    return 0;
}


uint8_t* jailbreak_process(pid_t pid)
{
    uint8_t* backup_ucred = (uint8_t*) malloc(UCRED_SIZE);

    if (!backup_ucred)
    {
        return NULL;
    }

    uintptr_t ucred = kernel_get_proc_ucred(pid);
    //
    // Backup it
    //
    kernel_copyout(ucred, backup_ucred, UCRED_SIZE);

    uint32_t uid_store = 0;
    uint32_t ngroups_store = 0;
    int64_t caps_store = -1;
    uint8_t attr_store[] = {0x80, 0, 0, 0, 0, 0, 0, 0};

    kernel_copyin(&uid_store, ucred + 0x04, 0x4);
    kernel_copyin(&uid_store, ucred + 0x08, 0x4);
    kernel_copyin(&uid_store, ucred + 0x0C, 0x4);
    kernel_copyin(&ngroups_store, ucred + 0x0C, 0x4);
    kernel_copyin(&uid_store, ucred + 0x14, 0x4);


    // Escalate sony privileges
    // kernel_copyin(&authid_store, ucred + 0x58, 0x8);	 // cr_sceAuthID
    kernel_copyin(&caps_store, ucred + 0x60, 0x8);		 // cr_sceCaps[0]
    kernel_copyin(&caps_store, ucred + 0x68, 0x8);		 // cr_sceCaps[1]
    kernel_copyin(attr_store, ucred + 0x83, 0x1);		 // cr_sceAttr[0]

    return backup_ucred;
}


//
// Restore
//
void jail_process(pid_t pid, uint8_t* old_ucred)
{
    uintptr_t ucred = kernel_get_proc_ucred(pid);
    kernel_copyin(old_ucred, ucred, UCRED_SIZE);
}

