#include <sys/types.h>

extern "C"
{
#include <ps5/kernel.h>
}

#include "debug_log.h"
#include "kdlsym.h"

#include "offsets/1_00.h"
#include "offsets/1_01.h"
#include "offsets/1_02.h"
#include "offsets/1_05.h"
#include "offsets/1_10.h"
#include "offsets/1_11.h"
#include "offsets/1_12.h"
#include "offsets/1_13.h"
#include "offsets/1_14.h"
#include "offsets/2_00.h"
#include "offsets/2_20.h"
#include "offsets/2_25.h"
#include "offsets/2_26.h"
#include "offsets/2_30.h"
#include "offsets/2_50.h"

uint64_t g_fw_version;
uint64_t g_kernel_base = 0;

void init_kdlsym()
{
    // Set firmware version
    g_fw_version    = kernel_get_fw_version() & 0xFFFF0000;

    // Resolve symbols
    switch (g_fw_version) {
    case 0x1000000:
    case 0x1010000:
    case 0x1020000:
    case 0x1050000:
    case 0x1100000:
    case 0x1110000:
    case 0x1120000:
    case 0x1130000:
    case 0x1140000:
        g_kernel_base = KERNEL_ADDRESS_DATA_BASE - 0x1B40000;
        break;
    case 0x2000000:
    case 0x2200000:
    case 0x2250000:
    case 0x2260000:
    case 0x2300000:
    case 0x2500000:
    case 0x2700000:
        g_kernel_base = KERNEL_ADDRESS_DATA_BASE - 0x1B80000;
        break;
    }
}

uint64_t ktext(uint64_t offset)
{
    // Init kdlsym if it's not initialized already
    if (g_kernel_base == 0)
        init_kdlsym();

    return g_kernel_base + offset;
}

uint64_t kdlsym(ksym_t sym)
{
    // Init kdlsym if it's not initialized already
    if (g_kernel_base == 0)
        init_kdlsym();

    // Don't overflow sym table
    if (sym >= KERNEL_SYM_MAX)
        return 0;

    switch (g_fw_version) {
    case 0x1000000:
        return g_kernel_base + g_sym_map_100[sym];
    case 0x1010000:
        return g_kernel_base + g_sym_map_101[sym];
    case 0x1020000:
        return g_kernel_base + g_sym_map_102[sym];
    case 0x1050000:
        return g_kernel_base + g_sym_map_105[sym];
    case 0x1100000:
        return g_kernel_base + g_sym_map_110[sym];
    case 0x1110000:
        return g_kernel_base + g_sym_map_111[sym];
    case 0x1120000:
        return g_kernel_base + g_sym_map_112[sym];
    case 0x1130000:
        return g_kernel_base + g_sym_map_113[sym];
    case 0x1140000:
        return g_kernel_base + g_sym_map_114[sym];
    case 0x2000000:
        return g_kernel_base + g_sym_map_200[sym];
    case 0x2200000:
        return g_kernel_base + g_sym_map_220[sym];
    case 0x2250000:
        return g_kernel_base + g_sym_map_225[sym];
    case 0x2260000:
        return g_kernel_base + g_sym_map_226[sym];
    case 0x2300000:
        return g_kernel_base + g_sym_map_230[sym];
    case 0x2500000:
    case 0x2700000:
        return g_kernel_base + g_sym_map_250[sym];
    }

    return 0;
}
