
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
#include <chrono>

#include <unistd.h>
#include <util.hpp>

#define u32 uint32_t
#define s32 int32_t



extern "C" {
    long ptr_syscall = 0;
   
    int sceKernelLoadStartModule(const char *moduleFileName, int args, const void *argp, int flags, void *opt, int *pRes) ;
    int sceKernelDlsym(int handle, const char *symbol, void **addrp);

    s32 sceGnmSubmitAndFlipCommandBuffersForWorkload(
	u32 workload, u32 count, u32* dcb_gpu_addrs[], u32* dcb_sizes_in_bytes, u32* ccb_gpu_addrs[],
	u32* ccb_sizes_in_bytes, u32 vo_handle, u32 buf_idx, u32 flip_mode, u32 flip_arg);
}
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

static int frame_count = 0;

bool touch_file(const char* destfile) {
    static constexpr int FLAGS = 0777;
    int fd = open(destfile, O_WRONLY | O_CREAT | O_TRUNC, FLAGS);
    if (fd > 0) {
        close(fd);
        return true;
    }
    return false;
}

 typedef struct {
   int32_t type;             // 0x00
   int32_t req_id;           // 0x04
   int32_t priority;         // 0x08
   int32_t msg_id;           // 0x0C
   int32_t target_id;        // 0x10
   int32_t user_id;          // 0x14
   int32_t unk1;             // 0x18
   int32_t unk2;             // 0x1C
   int32_t app_id;           // 0x20
   int32_t error_num;        // 0x24
   int32_t unk3;             // 0x28
   char use_icon_image_uri;  // 0x2C
   char message[1024];       // 0x2D
   char uri[1024];           // 0x42D
   char unkstr[1024];        // 0x82D
 } OrbisNotificationRequest; // Size = 0xC30

 extern "C" int sceKernelSendNotificationRequest(int userId, OrbisNotificationRequest *request, size_t requestSize, int flags);

void printf_notification(const char* fmt, ...)
{
	OrbisNotificationRequest noti_buffer{};

	va_list args{};
	va_start(args, fmt);
	int len = vsnprintf(noti_buffer.message, sizeof(noti_buffer.message), fmt, args);
	va_end(args);

	// these dont do anything currently
	// that or the structure has changed
	// lets just copy messages for now
	/*
	noti_buffer.type = 0;
	noti_buffer.unk3 = 0;
	noti_buffer.use_icon_image_uri = 0;
	noti_buffer.target_id = -1;
	*/
	// trim newline
	if (noti_buffer.message[len - 1] == '\n')
	{
		noti_buffer.message[len - 1] = '\0';
	}
	sceKernelSendNotificationRequest(0, (OrbisNotificationRequest*)&noti_buffer, sizeof(noti_buffer), 0);
}

void CalculateAndPrintFPS() {
	auto current_time = std::chrono::high_resolution_clock::now();
	static auto last_time = current_time;
	auto delta = std::chrono::duration<double>(current_time - last_time).count();
	
	frame_count++;

	if (delta >= 1.0) {
		double fps = frame_count / delta;
		// Send FPS
		printf_notification("FPS %.2f", fps);

		frame_count = 0;
		last_time = current_time;
	}
}

s32 (*sceGnmSubmitAndFlipCommandBuffersForWorkload_orig)(
	u32 workload, u32 count, u32* dcb_gpu_addrs[], u32* dcb_sizes_in_bytes, u32* ccb_gpu_addrs[],
	u32* ccb_sizes_in_bytes, u32 vo_handle, u32 buf_idx, u32 flip_mode, u32 flip_arg) = nullptr;

s32 sceGnmSubmitAndFlipCommandBuffersForWorkload_hook(
	u32 workload, u32 count, u32* dcb_gpu_addrs[], u32* dcb_sizes_in_bytes, u32* ccb_gpu_addrs[],
	u32* ccb_sizes_in_bytes, u32 vo_handle, u32 buf_idx, u32 flip_mode, u32 flip_arg) {
	//printf("sceGnmSubmitAndFlipCommandBuffersForWorkload_hook called!\n");
	CalculateAndPrintFPS();
	int ret = sceGnmSubmitAndFlipCommandBuffersForWorkload_orig(
		workload, count, dcb_gpu_addrs, dcb_sizes_in_bytes, ccb_gpu_addrs,
		ccb_sizes_in_bytes, vo_handle, buf_idx, flip_mode, flip_arg);
    if(ret == 0x80D11081){
        printf("sceGnmSubmitAndFlipCommandBuffersForWorkload returned BUSY\n");
    }
	else
    if(ret != 0) {
		printf("sceGnmSubmitAndFlipCommandBuffersForWorkload returned error: %d\n", ret);
	}

	return ret;

}

int main(int argc, char const* argv[]) {
    //OrbisKernelSwVersion sw;
    char buff[256];
    klog_puts("============== fps_elf Started =================");
	printf_notification("fps_counter loaded!");

    while(sceKernelMprotect(&buff, sizeof(buff), PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        klog_puts("sceKernelMprotect failed, retrying...");
        sleep(1);
    }

    klog_printf("sceGnmSubmitAndFlipCommandBuffersForWorkload addr: %p\n", &sceGnmSubmitAndFlipCommandBuffersForWorkload);
    sceGnmSubmitAndFlipCommandBuffersForWorkload_orig = (decltype(sceGnmSubmitAndFlipCommandBuffersForWorkload_orig))DetourFunction((uint64_t)&sceGnmSubmitAndFlipCommandBuffersForWorkload, (void*)&sceGnmSubmitAndFlipCommandBuffersForWorkload_hook);

    while (true) {
        game_log("sleeping ....");
        sleep(0x10000);
    }
    return 0;

}
