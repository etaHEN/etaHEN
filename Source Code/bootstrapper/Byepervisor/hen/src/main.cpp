#include <climits>
#include <stdint.h>

#include "fpkg.h"
#include "fself.h"
#include "hook.h"
#include "kdlsym.h"
#include "patch_shellcore.h"
#include "util.h"

struct args
{
    uint64_t fptr;
    uint64_t fw;
    uint64_t kernel_base;
};

extern "C" {
    int kernel_main(void *td, struct args *args);
}

/**
 * @brief The kernel sysent entrypoint
 * 
 * @param td struct thread* The calling thread
 * @param args struct args* Syscall arguments
 * @return int 0 on success, error otherwise
 */
int kernel_main(void *td, struct args *args)
{
    int ret = -1;

    curthread = td;
    init_kdlsym(args->fw, args->kernel_base);

    // kdlsym assignments
    auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);

    // Reset hooks before installing new ones
    printf("[HEN] Resetting hooks\n");
    for (int i = 0; i < HOOK_MAX; i++) {
        reset_hook((hook_id) i);
    }

    // Install new hooks
    printf("[HEN] Applying test hook\n");
    ret = apply_test_hook();
    if (ret != 0) {
        printf("[HEN] Failed to apply test hook\n");
        return -1;
    }

    printf("[HEN] Applying fself hooks\n");
    apply_fself_hooks();

    printf("[HEN] Applying fpkg hooks\n");
    apply_fpkg_hooks();

    return 0;
}