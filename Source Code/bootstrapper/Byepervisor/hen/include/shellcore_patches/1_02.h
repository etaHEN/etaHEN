#ifndef SHELLCORE_PATCHES_1_02
#define SHELLCORE_PATCHES_1_02

#include "common.h"

struct patch g_shellcore_patches_102[] = {
    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x1e6a93,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x1e6adf,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x1e6b4b,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x91d263,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x91d2af,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x91d31b,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x9a96e2,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xb70733,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xb7077f,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xb707eb,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * longjmp
         */
        0x42ef81,
        "\x90\xE9",
        2
    },

    {
        /*
         * strfree
         */
        0x11e544e,
        "\x66\x72\x65\x65",
        4
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x371137,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x371172,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x371501,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; ret
         */
        0x47af30,
        "\x31\xC0\xFF\xC0\xC3",
        5
    },

    {
        /*
         * PS4 Disc Installer Patch 1
         */
        0x1DDB1B,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 Disc Installer Patch 1
         */
        0x1DDB98,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 1
         */
        0x1DDC9B,
        "\xEB",
        1
    },

    {
        /*
         * PS5 PKG Installer Patch 1
         */
        0x1DDD6F,
        "\xEB",
        1
    },

    {
        /*
         * PS4 PKG Installer Patch 2
         */
        0x1DE1DA,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 PKG Installer Patch 2
         */
        0x1DE3AE,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 3
         */
        0x1DE75E,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 PKG Installer Patch 3
         */
        0x1DE824,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 4
         */
        0x41C6D7,
        "\xEB",
        1
    },

    {
        /*
         * PS5 PKG Installer Patch 4
         */
        0x41C7EC,
        "\xEB",
        1
    }
};

#endif // SHELLCORE_PATCHES_1_02
