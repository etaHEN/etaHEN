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

#include "../include/external_symbols.hpp"

/* ====================================== Dynamic SystemService Symbols ===================================*/
int (*sceSystemServiceNavigateToGoHome)(void) = nullptr;
int (*sceSystemServiceGetAppIdOfRunningBigApp)(void) = nullptr;
// Global function pointers
SceLncUtilLaunchAppType sceLncUtilLaunchApp_dyn = nullptr;
int (*sceSystemServiceGetAppTitleId)(int appid, char* titleid) = nullptr; 

/* ====================================== Remote Play Symbols ======================================*/
int (*sceRemoteplayNotifyPinCodeError)(int errorcode) = nullptr;
int (*sceRemoteplayInitialize)(void*, size_t) = nullptr;
int (*sceRemoteplayGeneratePinCode)(uint32_t*) = nullptr;
int (*sceRemoteplayConfirmDeviceRegist)(int*, int*) = nullptr;

/* ====================================== Dynamic Appmsg Symbols ===================================*/

uint32_t(*sceAppMessagingSendMsg)(uint32_t appId, uint32_t msgType, const void* msg, size_t msgLength, uint32_t flags) = nullptr;
int (*sceAppMessagingReceiveMsg)(const AppMessage* msg) = nullptr;

/* ====================================== Dynamic libkernel_sys Symbols ===================================*/
int (*sceKernelGetProcessName)(int pid, char* name) = nullptr;
int (*sceKernelMprotect)(void* addr, size_t len, int prot) = nullptr;
int (*sceKernelDebugOutText)(int DBG_CHANNEL, const char* text) = nullptr;
//  int (*close_alt)(int fd) = nullptr;
int (*sceKernelSleep_alt)(int seconds) = nullptr;
//  ssize_t (*write_alt)(int fd, const void* buf, size_t count) = nullptr;
int (*sceKernelMkdir)( const char* path,int mode) = nullptr;
int (*sceKernelSendNotificationRequest)(int unk1, OrbisNotificationRequest* req, int size, int unk2) = nullptr;
int (*sceKernelGetProsperoSystemSwVersion)(OrbisKernelSwVersion* sw) = nullptr;

int (*scePthreadCreate)(void* thread, const void* attr, void* (*entry) (void*), void* arg, const char* name) = nullptr;

int (*sceKernelJitCreateSharedMemory)(int flags, size_t size, int protection, int *destinationHandle) = nullptr;
int (*sceKernelJitCreateAliasOfSharedMemory)(int handle, int protection, int *destinationHandle) = nullptr;
int (*sceKernelJitMapSharedMemory)(int handle, int protection, void **destination) = nullptr;
int (*sceKernelGetAppInfo)(pid_t pid, app_info_t *info) = nullptr;

int(*ioctl)(int, int, void*) = nullptr;
int (*sceRegMgrGetInt)(long, int*) = nullptr;

int (*sceShellUIUtilInitialize)(void) = nullptr;
int (*sceShellUIUtilLaunchByUri)(const char* uri, SceShellUIUtilLaunchByUriParam* Param) = nullptr;