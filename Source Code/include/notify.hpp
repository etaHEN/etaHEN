#pragma once

extern "C"
{
	#include <stdint.h>
	#include <stdarg.h>
	#include <string.h>
	#include <stdio.h>
	#include <unistd.h>

	typedef struct
	{
		int32_t type;			 // 0x00
		int32_t req_id;			 // 0x04
		int32_t priority;		 // 0x08
		int32_t msg_id;			 // 0x0C
		int32_t target_id;		 // 0x10
		int32_t user_id;		 // 0x14
		int32_t unk1;			 // 0x18
		int32_t unk2;			 // 0x1C
		int32_t app_id;			 // 0x20
		int32_t error_num;		 // 0x24
		int32_t unk3;			 // 0x28
		char use_icon_image_uri; // 0x2C
		char message[1024];		 // 0x2D
		char uri[1024];			 // 0x42D
		char unkstr[1024];		 // 0x82D
	} OrbisNotificationRequest;	 // Size = 0xC30

	int32_t sceKernelSendNotificationRequest(int32_t device, OrbisNotificationRequest *req, size_t size, int32_t blocking);
	
}

void printf_notification(const char *fmt, ...);
