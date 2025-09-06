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


/* ====================================== Global vars ======================================================*/
MonoDomain* Root_Domain = nullptr;

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

/* ====================================== Dynamic Mono Symbols ===================================*/
MonoArray* (*mono_array_new)(MonoDomain* domain, MonoClass* eclass, uint32_t size) = nullptr;
MonoString* (*mono_object_to_string)(MonoObject* obj, MonoObject** exc) = nullptr;
void (*mono_gchandle_new)(MonoObject* obj, int pinned) = nullptr;
MonoClass* (*mono_get_byte_class)() = nullptr;
char* (*mono_array_addr_with_size)(MonoArray* array, int size, uintptr_t idx) = nullptr;
uint64_t(*mono_aot_get_method)(MonoDomain* domain, MonoMethod* method) = nullptr;
uint64_t(*mono_compile_method)(MonoMethod* method) = nullptr;
const char* (*mono_string_to_utf8)(MonoString* str) = nullptr;
void (*mono_free)(void* ptr) = nullptr;
void (*mono_raise_exception)(MonoObject *exception) = nullptr;
MonoDomain* (*mono_get_root_domain)() = nullptr;
MonoDomain* (*mono_jit_init_version)(const char* file, const char* runtime_version) = nullptr;
MonoClass* (*mono_class_from_name)(MonoImage* image, const char* name_space, const char* name) = nullptr;
MonoAssembly* (*mono_domain_assembly_open)(MonoDomain* domain, const char* name) = nullptr;
MonoImage* (*mono_assembly_get_image)(MonoAssembly* assembly) = nullptr;
MonoMethod* (*mono_property_get_get_method)(MonoProperty* prop) = nullptr;
MonoMethod* (*mono_property_get_set_method)(MonoProperty* prop) = nullptr;
MonoProperty* (*mono_class_get_property_from_name)(MonoClass* klass, const char* name) = nullptr; //
MonoObject* (*mono_runtime_invoke)(MonoMethod* method, void* obj, void** params, MonoObject** exc) = nullptr; //
MonoString* (*mono_string_new)(MonoDomain* domain, const char* str) = nullptr; //
MonoThread* (*mono_thread_attach)(MonoDomain* domain) = nullptr;
MonoMethod* (*mono_class_get_method_from_name)(MonoClass* klass, const char* name, int param_count) = nullptr;//
void (*mono_runtime_object_init)(MonoObject* obj) = nullptr;
MonoClassField* (*mono_class_get_field_from_name)(MonoClass* klass, const char* name) = nullptr;
void (*mono_field_static_set_value)(MonoVTable* vt, MonoClassField* field, void* value) = nullptr;
MonoVTable* (*mono_class_vtable)(MonoDomain* domain, MonoClass* klass) = nullptr;
MonoImage* (*mono_image_open_from_data)(char* data, uint32_t data_len, int need_copy, MonoImageOpenStatus* status) = nullptr;
MonoAssembly* (*mono_assembly_load_from)(MonoImage* image, const char* fname, MonoImageOpenStatus* status) = nullptr;
void (*setenv)(const char*, const char*, int) = nullptr;
MonoDomain* (*mono_domain_get)() = nullptr;
void (*mono_set_dirs)(const char*, const char*) = nullptr;
void (*mono_assembly_setrootdir)(const char*) = nullptr;
void (*mono_thread_detach)(MonoThread* thread) = nullptr;
MonoThread* (*mono_thread_current)() = nullptr;
void (*mono_jit_set_aot_only)(int aot_only) = nullptr;
void (*mono_domain_unload)(MonoDomain* domain) = nullptr;
MonoMethodDesc* (*mono_method_desc_new)(const char* name, int include_namespace) = nullptr;
MonoMethod* (*mono_method_desc_search_in_class)(MonoMethodDesc* desc, MonoClass* klass) = nullptr;
void (*mono_method_desc_free)(MonoMethodDesc* desc) = nullptr;
MonoObject* (*mono_object_new)(MonoDomain* domain, MonoClass* klass) = nullptr;
MonoObject* (*mono_object_new_specific)(MonoVTable* vtable) = nullptr;//mono_object_get_class
MonoClass* (*mono_object_get_class)(MonoObject* obj) = nullptr;
MonoObject* (*mono_vtable_get_static_field_data)(MonoVTable* vt) = nullptr;
void* (*mono_object_unbox)(MonoObject* obj) = nullptr;
int(*ioctl)(int, int, void*) = nullptr;
int (*sceRegMgrGetInt)(long, int*) = nullptr;