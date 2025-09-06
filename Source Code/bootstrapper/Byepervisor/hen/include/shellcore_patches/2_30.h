#ifndef SHELLCORE_PATCHES_2_30
#define SHELLCORE_PATCHES_2_30

#include "common.h"

struct patch g_shellcore_patches_230[] = {
    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x220623,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x22066C,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x2206DC,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x9D7043,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x9D708C,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x9D70FC,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xA65652,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xC64933,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xC6497C,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xC649EC,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * longjmp
         */
        0x49E8C1,
        "\x90\xE9",
        2
    },

    {
        /*
         * strfree
         */
        0x1371BFD,
        "\x66\x72\x65\x65",
        4
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x3D5E94,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x3D5ECF,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x3D625E,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; ret
         */
        0x4E9890,
        "\x31\xC0\xFF\xC0\xC3",
        5
    },

    {
        /*
         * PS4 Disc Installer Patch 1
         */
        0x21741B,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 Disc Installer Patch 1
         */
        0x217498,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 1
         */
        0x21759B,
        "\xEB",
        1
    },

    {
        /*
         * PS5 PKG Installer Patch 1
         */
        0x21766F,
        "\xEB",
        1
    },

    {
        /*
         * PS4 PKG Installer Patch 2
         */
        0x217ADA,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 PKG Installer Patch 2
         */
        0x217CAE,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 3
         */
        0x218065,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS5 PKG Installer Patch 3
         */
        0x218102,
        "\x90\xE9",
        2
    },

    {
        /*
         * PS4 PKG Installer Patch 4
         */
        0x48A037,
        "\xEB",
        1
    },

    {
        /*
         * PS5 PKG Installer Patch 4
         */
        0x48A14C,
        "\xEB",
        1
    },

    {
        /*
         * PKG Installer Patch
         */
        0x48BFA0,
        "\x48\x31\xC0\xC3",
        4
    }
};

#endif // SHELLCORE_PATCHES_2_30
