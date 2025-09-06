#ifndef SHELLCORE_PATCHES_1_14
#define SHELLCORE_PATCHES_1_14

#include "common.h"

struct patch g_shellcore_patches_114[] = {
    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x1E69E3,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x1E6A2F,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x1E6A9B,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x91DC83,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x91DCCF,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x91DD3B,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x9AA102,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xB711D3,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xB7121F,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xB7128B,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * longjmp
         */
        0x42F511,
        "\x90\xE9",
        2
    },

    {
        /*
         * strfree
         */
        0x11E9741,
        "\x66\x72\x65\x65",
        4
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x371547,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x371582,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x371911,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; ret
         */
        0x47B5C0,
        "\x31\xC0\xFF\xC0\xC3",
        5
    },

    {
        /*
         * PS4 Disc Installer Patch 1
         */
        0x1DDAFB,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 Disc Installer Patch 1
         */
        0x1DDB78,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 1
         */
        0x1DDC7B,
        "\xEB",
        1
    },

    {
        /*
         * PS5 PKG Installer Patch 1
         */
        0x1DDD4F,
        "\xEB",
        1
    },

    {
        /*
         * PS4 PKG Installer Patch 2
         */
        0x1DE1BA,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 PKG Installer Patch 2
         */
        0x1DE38E,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 3
         */
        0x1DE73E,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 PKG Installer Patch 3
         */
        0x1DE804,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 4
         */
        0x41CBC7,
        "\xEB",
        1
    },

    {
        /*
         * PS5 PKG Installer Patch 4
         */
        0x41CCDC,
        "\xEB",
        1
    }
};

#endif // SHELLCORE_PATCHES_1_14
