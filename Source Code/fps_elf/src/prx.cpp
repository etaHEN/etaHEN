
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
#include "defs.h"
#include "Detour.h"
#include "ipc.hpp"
#include "proc.h"
#include "ps5/kernel.h"
#include "ucred.h"
#include <cstdint>
#include <iostream>
#include "webserver.hpp"

#include <unistd.h>
#include <util.hpp>

extern "C" long ptr_syscall = 0;

void __syscall() {
  asm(".intel_syntax noprefix\n"
      "  mov rax, rdi\n"
      "  mov rdi, rsi\n"
      "  mov rsi, rdx\n"
      "  mov rdx, rcx\n"
      "  mov r10, r8\n"
      "  mov r8,  r9\n"
      "  mov r9,  qword ptr [rsp + 8]\n"
      "  call qword ptr [rip + ptr_syscall]\n"
      "  ret\n");
}

struct OrbisKernelTimespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

extern "C" {
    int sceKernelGetSocSensorTemperature(int sensorId, int* soctime);
    int get_page_table_stats(int vm, int type, int* total, int* free);
    int sceKernelGetCpuUsage(struct Proc_Stats* out, int32_t* size);
    int sceKernelGetThreadName(uint32_t id, char* out);
	int sceKernelGetCpuTemperature(int* cputemp);
    int sceKernelClockGettime(int clockId, OrbisKernelTimespec* tp);
}

bool touch_file(const char* destfile) {
    static constexpr int FLAGS = 0777;
    int fd = open(destfile, O_WRONLY | O_CREAT | O_TRUNC, FLAGS);
    if (fd > 0) {
        close(fd);
        return true;
    }
    return false;
}


void notify(const char* text, ...)
{
    OrbisNotificationRequest req;
    memset(&req, 0, sizeof(OrbisNotificationRequest));
    char buff[1024];

    // printf("******************** text: %s\n", text);

    va_list args{};
    va_start(args, text);
    vsnprintf(buff, sizeof(buff), text, args);
    va_end(args);

    req.type = 0;
    req.unk3 = 0;
    req.use_icon_image_uri = 1;
    req.target_id = -1;
    strncpy(req.uri, "cxml://psnotification/tex_icon_system", 38);
    strncpy(req.message, buff, 1024);

    game_log("Sending notification: %s", req.message);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

#define KERNEL_DLSYM(handle, sym) \
    (*(void**)&sym=(void*)kernel_dynlib_dlsym(-1, handle, #sym))

int main(int argc, char const* argv[]) {
    //OrbisKernelSwVersion sw;

	notify("fps_elf loaded!");

    pid_t pid = getpid();
    uintptr_t old_authid = set_ucred_to_debugger();


    int libkernelsys_handle = get_module_handle(pid, "libkernel.sprx");

    KERNEL_DLSYM(libkernelsys_handle, sceKernelDebugOutText);
    KERNEL_DLSYM(libkernelsys_handle, sceKernelMkdir);
    KERNEL_DLSYM(libkernelsys_handle, scePthreadCreate);
    KERNEL_DLSYM(libkernelsys_handle, sceKernelMprotect);
    KERNEL_DLSYM(libkernelsys_handle, sceKernelSendNotificationRequest);
    KERNEL_DLSYM(libkernelsys_handle, sceKernelGetProsperoSystemSwVersion);
    KERNEL_DLSYM(libkernelsys_handle, sceKernelGetAppInfo);
    KERNEL_DLSYM(libkernelsys_handle, sceKernelGetProcessName);

    game_log("Starting game ELF ....");

    KERNEL_DLSYM(libSceKernelHandle, ioctl);

    // get the yscall address for the ioctl hook
    static __attribute__((used)) long getpid = 0;
    KERNEL_DLSYM(libSceKernelHandle, getpid);
    ptr_syscall = getpid;
    ptr_syscall += 0xa; // jump directly to the syscall instruction

    // file to let the main daemon know that its finished loading
    touch_file("/system_tmp/fps_online");
    set_proc_authid(pid, old_authid);

    while (true) {
        game_log("sleeping ....");
        sleep(0x100000);
    }
    return 0;

}
