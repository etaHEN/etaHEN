#ifndef SHELLCORE_PATCHES_2_20
#define SHELLCORE_PATCHES_2_20

#include "common.h"

struct patch g_shellcore_patches_220[] = {
    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x21E7B3,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x21E7FC,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x21E86C,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x9D4783,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x9D47CC,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x9D483C,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xA62D92,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xC62073,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xC620BC,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xC6212C,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * longjmp
         */
        0x49C421,
        "\x90\xE9",
        2
    },

    {
        /*
         * strfree
         */
        0x1371F7E,
        "\x66\x72\x65\x65",
        4
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x3D3A34,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x3D3A6F,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x3D3DFE,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; ret
         */
        0x4E7370,
        "\x31\xC0\xFF\xC0\xC3",
        5
    },

    {
        /*
         * PS4 Disc Installer Patch 1
         */
        0x215AFB,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 Disc Installer Patch 1
         */
        0x215B78,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 1
         */
        0x215C7B,
        "\xEB",
        1
    },

    {
        /*
         * PS5 PKG Installer Patch 1
         */
        0x215D4F,
        "\xEB",
        1
    },

    {
        /*
         * PS4 PKG Installer Patch 2
         */
        0x2161BA,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 PKG Installer Patch 2
         */
        0x21638E,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 3
         */
        0x216745,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 PKG Installer Patch 3
         */
        0x2167E2,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 4
         */
        0x487B97,
        "\xEB",
        1
    },

    {
        /*
         * PS5 PKG Installer Patch 4
         */
        0x487CAC,
        "\xEB",
        1
    },

    {
        /*
         * PKG Installer Patch
         */
        0x489B00,
        "\x48\x31\xC0\xC3",
        4
    }
};

#endif // SHELLCORE_PATCHES_2_20
