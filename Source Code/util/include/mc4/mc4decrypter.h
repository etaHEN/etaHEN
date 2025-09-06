#pragma once

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include "mc4/base64.h"

#define CBC 1
#include "mc4/aes.h"

uint8_t* encrypt_data(uint8_t* data, size_t* size);
uint8_t* decrypt_data(uint8_t* data, size_t* size);