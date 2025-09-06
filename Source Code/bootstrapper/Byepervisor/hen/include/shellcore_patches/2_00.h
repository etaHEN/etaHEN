#ifndef SHELLCORE_PATCHES_2_00
#define SHELLCORE_PATCHES_2_00

#include "common.h"

struct patch g_shellcore_patches_200[] = {
    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x21E513,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x21E55C,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x21E5CC,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x9D4433,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x9D447C,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x9D44EC,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xA62A32,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xC61D13,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xC61D5C,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xC61DCC,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * longjmp
         */
        0x49C0D1,
        "\x90\xE9",
        2
    },

    {
        /*
         * strfree
         */
        0x136DE1C,
        "\x66\x72\x65\x65",
        4
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x3D3764,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x3D379F,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x3D3B2E,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; ret
         */
        0x4E7020,
        "\x31\xC0\xFF\xC0\xC3",
        5
    },

    {
        /*
         * PS4 Disc Installer Patch 1
         */
        0x21585B,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 Disc Installer Patch 1
         */
        0x2158D8,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 1
         */
        0x2159DB,
        "\xEB",
        1
    },

    {
        /*
         * PS5 PKG Installer Patch 1
         */
        0x215AAF,
        "\xEB",
        1
    },

    {
        /*
         * PS4 PKG Installer Patch 2
         */
        0x215F1A,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 PKG Installer Patch 2
         */
        0x2160EE,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 3
         */
        0x2164A5,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 PKG Installer Patch 3
         */
        0x216542,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 4
         */
        0x487847,
        "\xEB",
        1
    },

    {
        /*
         * PS5 PKG Installer Patch 4
         */
        0x48795C,
        "\xEB",
        1
    },

    {
        /*
         * PKG Installer Patch
         */
        0x4897B0,
        "\x48\x31\xC0\xC3",
        4
    }
};

#endif // SHELLCORE_PATCHES_2_00
