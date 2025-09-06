#ifndef FKEYS_H
#define FKEYS_H

#include <stdint.h>

struct key_area
{
    uint64_t bitmask;
    char pad[24];
    char key_data[63][32];
};

extern struct key_area shared_area;

int register_fake_key(const char key_data[32]);
int unregister_fake_key(int key_id);
int get_fake_key(int key_id, char key_data[32]);

#endif // FKEYS_H