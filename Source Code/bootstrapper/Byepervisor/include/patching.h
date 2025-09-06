#pragma once
#ifndef PATCHING_H
#define PATCHING_H

#include "patches/patch_common.h"

// int install_hook(hook_id id, void *func);

int apply_kernel_patches();
// int apply_test_hook();

#endif // PATCHING_H