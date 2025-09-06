/*
 * Credit: sleirsgoevy
 * https://github.com/sleirsgoevy/ps4jb-payloads/blob/87f31afca6afc573d953e8343113c179a416e1b0/ps5-kstuff/uelf/fakekeys.c
 */

#include <stdint.h>

#include "fkeys.h"
#include "util.h"

struct key_area shared_area = {};

int register_fake_key(const char key_data[32])
{
    uint64_t mask, mask1;
    mask = __atomic_load_n(&shared_area.bitmask, __ATOMIC_ACQUIRE);
    do
    {
        mask1 = (mask | (mask + 1)) & ((1ull << 63) - 1);
        if(mask1 == mask)
            return -1;
    }
    while(!__atomic_compare_exchange_n(&shared_area.bitmask, &mask, mask1, 1, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE));
    int key_idx = 63 - __builtin_clzll(mask ^ mask1);
    memcpy(shared_area.key_data[key_idx], key_data, 32);
    return key_idx;
}

int unregister_fake_key(int key_id)
{
    if(key_id < 0 || key_id >= 63)
        return 0;
    uint64_t mask, mask1;
    mask = __atomic_load_n(&shared_area.bitmask, __ATOMIC_ACQUIRE);
    do
    {
        if(!(mask & (1ull << key_id)))
            return 0;
        mask1 = mask & ~(1ull << key_id);
    }
    while(!__atomic_compare_exchange_n(&shared_area.bitmask, &mask, mask1, 1, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE));
    return 1;
}

int get_fake_key(int key_id, char key_data[32])
{
    if(key_id < 0 || key_id >= 63)
        return 0;
    uint64_t mask = __atomic_load_n(&shared_area.bitmask, __ATOMIC_ACQUIRE);
    if(!(mask & (1ull << key_id)))
        return 0;
    memcpy(key_data, shared_area.key_data[key_id], 32);
    return 1;
}