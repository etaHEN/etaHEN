/* Copyright (C) 2025 etaHEN / LightningMods

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include "mc4/mc4decrypter.h"

#include <stdio.h>

const unsigned char MC4_AES256CBC_KEY[] = "304c6528f659c766110239a51cl5dd9c";
const unsigned char MC4_AES256CBC_IV[]  = "u@}kzW2u[u(8DWar";
void etaHEN_log(const char* format, ...);

uint8_t* decrypt_data(uint8_t* data, size_t* size)
{
        uint8_t* bin_data;
        size_t bin_size;
        struct AES_ctx ctx;

        etaHEN_log("[*] Base64 Encoded Size: %zu bytes", *size);

        bin_data = base64_decode(data, *size, &bin_size);
        if (!bin_data)
        {
                etaHEN_log("Base64 Error!");
                return data;
        }

        *size = bin_size;
        
        //
        // This avoid the heap overflow caused by the AES_CBC_decrypt_buffer
        //
        size_t new_buff_size = bin_size + 0x100;
        uint8_t* bin_data_2 = calloc(new_buff_size, sizeof(uint8_t));
        memcpy(bin_data_2, bin_data, bin_size);
        free(bin_data);

        bin_data = bin_data_2;

        etaHEN_log("[*] Total Decrypted Size: %zu bytes", bin_size);

        AES_init_ctx_iv(&ctx, MC4_AES256CBC_KEY, MC4_AES256CBC_IV);
        AES_CBC_decrypt_buffer(&ctx, bin_data, bin_size);

        etaHEN_log("[*] Decrypted File Successfully!");
        return bin_data;
}

uint8_t* encrypt_data(uint8_t* data, size_t* size)
{
        uint8_t* b64_data;
        size_t b64_size;
        struct AES_ctx ctx;

        etaHEN_log("[*] Total XML Size: %zu bytes", *size);

        AES_init_ctx_iv(&ctx, MC4_AES256CBC_KEY, MC4_AES256CBC_IV);
        AES_CBC_encrypt_buffer(&ctx, data, *size);

        b64_data = base64_encode(data, *size, &b64_size);
        if (!b64_data)
        {
                etaHEN_log("Base64 Error!");
                return data;
        }

        *size = b64_size;

        etaHEN_log("[*] Total Encrypted Size: %zu bytes", b64_size);
        etaHEN_log("[*] Encrypted File Successfully!");
        return b64_data;
}