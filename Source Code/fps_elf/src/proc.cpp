extern "C"{
#include "../include/proc.h"
#include <ps5/klog.h>
}
struct proc* find_proc_by_name(const char* proc_name)
{

    uint64_t next = 0;
    kernel_copyout(KERNEL_ADDRESS_ALLPROC, &next, sizeof(uint64_t));
    struct proc* proc = (struct proc*) malloc(sizeof(struct proc));
    do
    {
        kernel_copyout(next, (void*) proc, sizeof(struct proc));
        if (!strcmp(proc->p_comm, proc_name))
            return proc;

        kernel_copyout(next, &next, sizeof(uint64_t));

    } while (next);

    free(proc);
    return NULL;
}

struct proc* get_proc_by_title_id(const char* title_id)
{
    uint64_t next = 0;
    kernel_copyout(KERNEL_ADDRESS_ALLPROC, &next, sizeof(uint64_t));
    struct proc* proc = (struct proc*) malloc(sizeof(struct proc));
    do
    {
        kernel_copyout(next, (void*) proc, sizeof(struct proc));
        if (!strcmp(proc->title_id, title_id))
            return proc;

        kernel_copyout(next, &next, sizeof(uint64_t));

    } while (next);

    free(proc);
    return NULL;
}

void list_all_proc_and_pid()
{

    uint64_t next = 0;
    kernel_copyout(KERNEL_ADDRESS_ALLPROC, &next, sizeof(uint64_t));
    struct proc* proc = (struct proc*) malloc(sizeof(struct proc));
    struct vmspace vmspace;

    do
    {
        kernel_copyout(next, (void*) proc, sizeof(struct proc));

        kernel_copyout((intptr_t) proc->p_vmspace, (void*) &vmspace, sizeof(vmspace));

        printf("%s - %d\n", proc->p_comm, proc->pid);

        kernel_copyout(next, &next, sizeof(uint64_t));

    } while (next);

    free(proc);
}

struct proc* get_proc_by_pid(pid_t pid)
{
    uintptr_t next = 0;

    kernel_copyout(KERNEL_ADDRESS_ALLPROC, &next, sizeof(uintptr_t));
    struct proc* proc =  (struct proc*) malloc(sizeof(struct proc));
    do
    {
        kernel_copyout(next, proc, sizeof(struct proc));

        if (proc->pid == pid)
            return proc;

        kernel_copyout(next, &next, sizeof(uint64_t));

    } while (next);

    free(proc);
    return NULL;
}


//
// List process modules by using the sys_dynlib_get_info_ex syscall
//
void list_proc_modules(struct proc* proc)
{
    size_t num_handles = 0;
    syscall(SYS_dl_get_list, proc->pid, NULL, 0, &num_handles);
    klog_printf("Number of modules: %zu\n", num_handles);
    
    if (num_handles)
    {
        uintptr_t* handles = (uintptr_t*) calloc(num_handles, sizeof(uintptr_t));
        klog_printf("Allocated handles array at %p\n", handles);
        syscall(SYS_dl_get_list, proc->pid, handles, num_handles, &num_handles);
        klog_printf("Retrieved module handles for PID %d\n", proc->pid);
        for (int i = 0; i < num_handles; ++i)
        {
            module_info_t mod_info;
            bzero(&mod_info, sizeof(mod_info));

            klog_printf("Getting info for handle %p\n", (void*)handles[i]);
            syscall(SYS_dl_get_info_2, proc->pid, 1, handles[i], &mod_info);

            klog_printf("%s - ", mod_info.filename);
            klog_printf("%#02lx\n", mod_info.init);
        }
        
        free(handles);
    }
}


module_info_t* get_module_info(pid_t pid, const char* module_name)
{
    size_t num_handles = 0;
    syscall(SYS_dl_get_list, pid, NULL, 0, &num_handles);
    
    if (num_handles)
    {
        uintptr_t* handles = (uintptr_t*) calloc(num_handles, sizeof(uintptr_t));
        syscall(SYS_dl_get_list, pid, handles, num_handles, &num_handles);

        module_info_t* mod_info = (module_info_t*) malloc(sizeof(module_info_t));
        
        for (int i = 0; i < num_handles; ++i)
        {
            bzero(mod_info, sizeof(module_info_t));
            syscall(SYS_dl_get_info_2, pid, 1, handles[i], mod_info);
            if (!strcmp(mod_info->filename, module_name))
            {
                return mod_info;
            }
        }
        
        free(handles);
        free(mod_info);
    }

    return NULL;
}


int get_module_handle(pid_t pid, const char* module_name)
{
    module_info_t* mod_info = get_module_info(pid, module_name);
    return mod_info ? mod_info->handle : 0; 
}





