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

#include "HookedFuncs.hpp"
#include "RemotePlay.h"
#include "Detour.h"
#include "ipc.hpp"
#include <climits>
#include <msg.hpp>
#include <pthread.h>
#include <sys/_pthreadtypes.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <fstream>
#include <unistd.h>
#include <util.hpp>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
extern "C"{
#include <ps5/kernel.h>
}

extern bool is_6xx, is_3xx;
/* ================================= ORIG HOOKED MONO FUNCS ============================================= */
int (*oOnPress)(MonoObject* Instance, MonoObject* element, MonoObject* e) = nullptr;
int (*oOnPreCreate)(MonoObject* Instance, MonoObject* element) = nullptr;
MonoString* (*CxmlUri)(MonoObject* obj, MonoString* uri) = nullptr;
uint64_t(*GetManifestResourceStream_Original)(uint64_t inst, MonoString* FileName) = nullptr;
uint64_t(*GetManifestResourceInternal_Orig)(MonoObject* instance, MonoString* name, int* size, MonoObject& module) = nullptr;
void (*UpdateImposeStatusFlag_Orig)(MonoObject* Instance, MonoObject* a) = nullptr;
bool (*CheckRemotePlayRestriction_Orig)(MonoObject* instance) = nullptr;
void (*oTerminate)(void) = nullptr;
GamePadData (*GetData)(int deviceIndex) = nullptr;

int (*GetHwSerialNumber)(MonoArray* serial) = nullptr;
int (*GetHwModelName)(MonoArray* serial) = nullptr;
int (*PupExpirationGetStatus)(PupStatus& status, uint32_t& time) = nullptr;
MonoString* (*getIpMacHost)(uint64_t inst, SceNetIfName name) = nullptr;
bool (*boot_orig)(MonoString* uri, int opt, MonoString* titleIdForBootAction) = nullptr;
void (*OnShareButton_orig)(MonoObject* data) = nullptr;
bool (*boot_orig_2)(MonoString* uri, int opt) = nullptr;

void (*CaptureScreen_orig_old)(MonoObject * inst, int userId, long deviceId, int capType, MonoObject* capacityInfo) = nullptr;
void (*CaptureScreen_orig_new)(MonoObject * inst, int userId, long deviceId, int capType, MonoString* format, MonoObject* capacityInfo) = nullptr;
void(*CallDecrypt_orig)(unsigned char* bundleData, int bundleOffset, int bundleSize, int* payloadOffset, int* realPayloadSize) = nullptr;

void (*createJson)(MonoObject*, MonoObject* array, MonoString* id, MonoString* label, MonoString* actionUrl, MonoString* actionId, MonoString* messageId, MonoObject* subMenu, bool enable) = nullptr;

int (*__sys_regmgr_call)(long, long, int*, int*, long) = nullptr;

MonoString *(*oGetString)(MonoObject *Instance, MonoString *str) = nullptr;
int (*LaunchApp_orig)(MonoString* titleId, uint64_t* args, int argsSize, LaunchAppParam *param) = nullptr;

// Store original function pointer
DecryptRnpsBundle_t DecryptRnpsBundle = NULL;



/* ================================= HOOKED GLOBAL VARS ============================================= */
MonoClass* MemoryStream_IO = nullptr;

/*
      <list id="id_activate_dumper" title="Activate Itemzflow Game Dumper"  confirm="The Game Dumper has been activated and will automatically dump the next Game Launched (decryption not included)" confirm_phrase="OK" >
        <list_item id="id_dump_all" title="Dump Based Game + Patch" value="0"/>
        <list_item id="id_dump_base" title="Dump Base Game Only" value="1"/>
        <list_item id="id_dump_patch" title="Dump Game Patch Only" value="2"/>
        <list_item id="id_fuck_uu" title="Placeholder" value="90"/>
      </list>


            <toggle_switch id="id_ps5debug_service" title="PS5Debug (Dizz)" second_title="PS5Debug on Port 9027 (Requires Dizz's PS5Debug Plugin)" value="0"/>

*/
std::atomic_bool install_thread_in_progress(false);
std::atomic_bool cheat_action_in_progress(false);
std::atomic_bool download_kstuff_thread_in_progress(false);

static std::string current_menu_tid;
int usbpath();
#define MAX_CHEATS 256

bool is_plugin = false;
bool is_su_menu = false;
bool is_custom_pkg = false;
bool is_debug_settings = false;
bool is_cheats = false;
bool is_auto_plugin = false;
bool is_tk_menu = false;
bool is_remote_play = false;
bool is_hb_loader = false;
bool is_plapps = false;
bool cheats_shortcut_activated = false;
bool cheats_shortcut_activated_not_open = false;
bool game_shortcut_activated = false;
bool game_shortcut_activated_media = false;

extern int cheatEnabledMap[MAX_CHEATS]; // holds the current activated/deactivated cheats, used for onPreCreateHook
std::string currentCheatTID; // holds current title ID being cheated, this is used to reset the map above

void RemoveGameWidget(RemoveWidget widget) {

    // Helper lambda to remove widgets by name
    auto removeWidgets = [](const std::vector<const char*>& widgetNames) {
        MonoClass* widgetClass = mono_class_from_name(pui_img, "Sce.PlayStation.PUI.UI2", "Widget");
        MonoObject* rootWidget = Get_Property<MonoObject*>(pui_img, "Sce.PlayStation.PUI.UI2", "Scene", Game, "RootWidget");
        for (const char* name : widgetNames) {
            MonoObject* child = Invoke<MonoObject*>(pui_img, widgetClass, rootWidget, "FindWidgetByName", mono_string_new(Root_Domain, name));
            if (child) {
                Invoke<void>(pui_img, widgetClass, child, "RemoveFromParent");
            }
        }
    };

    switch (widget) {
    case REMOVE_GPU_OVERLAY:
        removeWidgets({ "id_gpu_temp_value", "id_gpu_usage_value", "id_gpu_label" });
        break;
    case REMOVE_CPU_OVERLAY:
        removeWidgets({ "id_cpu_label", "id_cpu_temp_value", "id_cpu_usage_value" });
        break;
    case REMOVE_RAM_OVERLAY:
        removeWidgets({ "id_ram_label", "id_ram_value" });
        break;
    case REMOVE_FPS_OVERLAY:
        removeWidgets({ "id_fps_label", "id_fps_value" });
        break;
    case REMOVE_IP_OVERLAY:
		removeWidgets({ "id_ip_label", "id_ip_value" });
		break;
    case REMOVE_ALL_OVERLAYS:
        removeWidgets({ "id_gpu_temp_value", "id_gpu_usage_value", "id_gpu_label",
                        "id_cpu_label", "id_cpu_temp_value", "id_cpu_usage_value",
                        "id_ram_label", "id_ram_value",
                        "id_fps_label", "id_fps_value", 
                        "id_ip_label", "id_ip_value" });
		break;
    case REMOVE_KSTUFF_DISABLED:
		removeWidgets({ "id_kstuff_disabled_label" });
		break;
    }
}

void CreateGameWidget(CreateWidget widget) {
    MonoObject* font = CreateUIFont(22, 0, 0);
    MonoObject* rootWidget = Get_Property<MonoObject*>(pui_img, "Sce.PlayStation.PUI.UI2", "Scene", Game, "RootWidget");

    std::vector<WidgetConfig> configs;

    switch (widget) {
    case CREATE_GPU_OVERLAY:
        configs = {
            {"id_gpu_label", global_conf.overlay_gpu_x, global_conf.overlay_gpu_y, "GPU", 1, 0.0f, 1.0f, 0.0f, 1.0f},        // Green + Bold
            {"id_gpu_temp_value", global_conf.overlay_gpu_x + 70.0f, global_conf.overlay_gpu_y, "--C", 0, 1.0f, 0.6f, 0.0f, 1.0f},   // Orange
            {"id_gpu_usage_value", global_conf.overlay_gpu_x + 115.0f, global_conf.overlay_gpu_y, "--%", 0, 1.0f, 0.6f, 0.0f, 1.0f}  // Orange
        };
        break;

    case CREATE_CPU_OVERLAY:
        configs = {
            {"id_cpu_label", global_conf.overlay_cpu_x, global_conf.overlay_cpu_y, "CPU", 1, 0.0f, 1.0f, 1.0f, 1.0f},        // Cyan + Bold
            {"id_cpu_temp_value", global_conf.overlay_cpu_x + 70.0f, global_conf.overlay_cpu_y, "--C", 0, 1.0f, 0.6f, 0.0f, 1.0f},   // Orange
            {"id_cpu_usage_value", global_conf.overlay_cpu_x + 115.0f, global_conf.overlay_cpu_y, "--%", 0, 1.0f, 0.6f, 0.0f, 1.0f}  // Orange
        };
        break;

    case CREATE_RAM_OVERLAY:
        configs = {
            {"id_ram_label", global_conf.overlay_ram_x, global_conf.overlay_ram_y, "RAM", 1, 0.0f, 1.0f, 1.0f, 1.0f},        // Cyan + Bold
            {"id_ram_value", global_conf.overlay_ram_x + 70.0f, global_conf.overlay_ram_y, "----- MB", 0, 1.0f, 0.6f, 0.0f, 1.0f}    // Orange
        };
        break;

    case CREATE_FPS_OVERLAY:
        configs = {
            {"id_fps_label", global_conf.overlay_fps_x, global_conf.overlay_fps_y, "FPS:", 1, 1.0f, 0.0f, 1.0f, 1.0f},       // Magenta + Bold
            {"id_fps_value", global_conf.overlay_fps_x + 70.0f, global_conf.overlay_fps_y, "--- FPS", 0, 1.0f, 1.0f, 1.0f, 1.0f}     // White
        };
        break;
    case CREATE_IP_OVERLAY:
		configs = {
           { "id_ip_label", global_conf.overlay_ip_x, global_conf.overlay_ip_y, "PS5 IP:", 1, 0.0f, 1.0f, 0.0f, 1.0f},       // Green + Bold
		   { "id_ip_value", global_conf.overlay_ip_x + 70.0f, global_conf.overlay_ip_y, "---.---.---.---", 0, 1.0f, 1.0f, 1.0f, 1.0f }     // White
	     };
	     break;
    case CREATE_ALL_OVERLAYS:
        configs = {
            // GPU Overlay
            {"id_gpu_label", global_conf.overlay_gpu_x, global_conf.overlay_gpu_y, "GPU", 1, 0.0f, 1.0f, 0.0f, 1.0f},        // Green + Bold
            {"id_gpu_temp_value", global_conf.overlay_gpu_x + 70.0f, global_conf.overlay_gpu_y, "--C", 0, 1.0f, 0.6f, 0.0f, 1.0f},   // Orange
            {"id_gpu_usage_value", global_conf.overlay_gpu_x + 115.0f, global_conf.overlay_gpu_y, "--%", 0, 1.0f, 0.6f, 0.0f, 1.0f},  // Orange
            // CPU Overlay
            {"id_cpu_label", global_conf.overlay_cpu_x, global_conf.overlay_cpu_y, "CPU", 1, 0.0f, 1.0f, 1.0f, 1.0f},        // Cyan + Bold
            {"id_cpu_temp_value", global_conf.overlay_cpu_x + 70.0f, global_conf.overlay_cpu_y, "--C", 0, 1.0f, 0.6f, 0.0f, 1.0f},   // Orange
            {"id_cpu_usage_value", global_conf.overlay_cpu_x + 115.0f, global_conf.overlay_cpu_y, "--%", 0, 1.0f, 0.6f, 0.0f, 1.0f},  // Orange
            // RAM Overlay
            {"id_ram_label", global_conf.overlay_ram_x, global_conf.overlay_ram_y, "RAM", 1, 0.0f, 1.0f, 1.0f, 1.0f},        // Cyan + Bold
            {"id_ram_value", global_conf.overlay_ram_x + 70.0f, global_conf.overlay_ram_y, "----- MB", 0, 1.0f, 0.6f, 0.0f, 1.0f},    // Orange
            // FPS Overlay
			{"id_fps_label", global_conf.overlay_fps_x, global_conf.overlay_fps_y, "FPS:", 1, 1.0f, 0.0f, 1.0f, 1.0f},       // Magenta + Bold
            {"id_fps_value", global_conf.overlay_fps_x + 70.0f, global_conf.overlay_fps_y, "--- FPS", 0, 1.0f, 1.0f, 1.0f, 1.0f},     // White

            { "id_ip_label", global_conf.overlay_ip_x, global_conf.overlay_ip_y, "IP:", 1, 0.0f, 1.0f, 0.0f, 1.0f },       // Green + Bold
            { "id_ip_value", global_conf.overlay_ip_x + 70.0f, global_conf.overlay_ip_y, "---.---.---.---", 0, 1.0f, 1.0f, 1.0f, 1.0f }     // White
		};
        break;
      case CREATE_KSTUFF_DISABLED:
          configs = {
             {"id_kstuff_disabled_label", 850.0f, 20.0f, "KStuff is Disabled via Shortcut", 1, 1.0f, 0.0f, 0.0f, 1.0f} // Red + Bold
          };
		break;
}



    // Create and append all widgets
    for (const auto& config : configs) {
        MonoObject* label = CreateLabel(config.id, config.x, config.y, config.text, font,
            config.bold, 0, config.r, config.g, config.b, config.a);
        Widget_Append_Child(rootWidget, label);
    }
}

extern "C"{
int sceShellCoreUtilIsUsbMassStorageMounted(int num);
int sceNetCtlGetInfo(int number,  SceNetCtlInfo *info);
int sceNetSend(int sockfd, const void *buf, size_t len, int flags);
}

MonoString *GetString_Hook(MonoObject *Instance, MonoString *str) {
    if (!str || !Instance) {
      shellui_log("GetString_Hook: Invalid Parameters");
      return nullptr;
    }
    std::string resourceName = Mono_to_String(str);
    shellui_log("Resource Name: %s", resourceName.c_str());
    if (resourceName == "msg_options") {
      return mono_string_new(Root_Domain, "PKG Installer Options");
    } else if (resourceName == "msg_installing") {
      return mono_string_new(Root_Domain,
                             "etaHEN is currently installing the selected PKG");
    } else if (resourceName == "msg_yes") {
      return mono_string_new(Root_Domain, "Yes");
    } else if (resourceName == "msg_no") {
      return mono_string_new(Root_Domain, "No");
    } else if (resourceName == "msg_sort") {
      return mono_string_new(Root_Domain, "etaHEN PKG Sort");
    } else if (resourceName == "msg_sort_name_az") {
      return mono_string_new(Root_Domain, "Name (A-Z)");
    } else if (resourceName == "msg_sort_name_za") {
      return mono_string_new(Root_Domain, "Name (Z-A)");
    } else if (resourceName == "msg_updated") {
      return mono_string_new(Root_Domain, "Updated");
    } else if (resourceName == "msg_wait") {
      return mono_string_new(Root_Domain, "Please wait...");
    }
    else if (resourceName == "msg_ok"){
      return mono_string_new(Root_Domain, "OK");
    }
    else if (resourceName == "msg_cancel_vb"){
        return mono_string_new(Root_Domain, "Cancel");
    }
    //else if (resourceName == "msg_deselect_all") {
   //   return mono_string_new(Root_Domain, "Deselect All"); // IDK WHY BUT ONLY 1 CAN BE ACTIVE OR SHELLUI CRASHES
  //  }
    else if (resourceName == "msg_select_all") {
      return mono_string_new(Root_Domain, "Select All");
    }
    
    return oGetString(Instance, str);
  }
  

bool if_exists(const char* path) {
	struct stat buffer;
	return (stat(path, &buffer) == 0);
}

int get_ip_address(char* ip_address)
{
    unsigned int ret = 0;
    SceNetCtlInfo info;

    ret = sceNetCtlGetInfo(14, &info);
    if (ret < 0) {
        goto error;
    }

    memcpy(ip_address, info.ip_address, sizeof(info.ip_address));

    return ret;

error:
    memcpy(ip_address, "IP NOT FOUND", sizeof(info.ip_address));
    return -1;
}

void patch_bundle_strings(unsigned char* buffer, int* size_ptr, int actual_size) {
  if (!buffer || !size_ptr) {
      return;
  }
  
  // Replace "Debug Settings" with "etaHEN Toolbox"
  int count = replace_all(buffer, size_ptr, actual_size, "Debug Settings", "etaHEN Toolbox");
#if SHELL_DEBUG == 1
  if (count > 0) {
      shellui_log("patch_bundle_strings: Replaced %d occurrences of 'Debug Settings' with 'etaHEN Toolbox'", count);
  } else {
      shellui_log("patch_bundle_strings: No occurrences of 'Debug Settings' found");
  }
#else
  (void)count;
#endif
  
  // Replace "icon_setting" with "etahen_sicon"
  replace_all(buffer, size_ptr, actual_size, "icon_setting", "etahen_sicon");
}

int ioctl_hook(int fd, unsigned long request, void *argp) {
  const int IOCTL_SYSCALL = 0x36;
  const unsigned long  DECRYPT_RNPS_BUNDLE = 0xC0105203; // RNPS request code for ioctl

  int ret = __syscall(IOCTL_SYSCALL, fd, request, argp);
  if (ret == 0 && request == DECRYPT_RNPS_BUNDLE) {
      ioctl_C0105203_args *args = (ioctl_C0105203_args *)argp;
#if SHELL_DEBUG == 1
      shellui_log("ioctl_hook called with fd: %d, request: 0x%X, argp: %p", fd, request, argp);
#endif
      patch_bundle_strings((unsigned char*)args->buffer, &args->size, args->size);
  }
  return ret;
}

void CallDecrypt(unsigned char* bundleData, int bundleOffset, int bundleSize, int* payloadOffset, int* realPayloadSize) {
#if SHELL_DEBUG == 1
  shellui_log("CallDecrypt: bundleData: %p, bundleOffset: %d, bundleSize: %d, payloadOffset: %p, realPayloadSize: %p", 
      bundleData, bundleOffset, bundleSize, payloadOffset, realPayloadSize);
#endif
  
  if (!bundleData || !payloadOffset || !realPayloadSize) {
#if SHELL_DEBUG == 1
      shellui_log("CallDecrypt: Invalid Parameters");
#endif
      return;
  }
  
  CallDecrypt_orig(bundleData, bundleOffset, bundleSize, payloadOffset, realPayloadSize);
  patch_bundle_strings(bundleData, realPayloadSize, *realPayloadSize);
}



void pause_resume_kstuff(KstuffPauseStatus opt, bool notify_user)
{
  intptr_t sysentvec = 0;
  intptr_t sysentvec_ps4 = 0;
  bool success = false;
  switch(kernel_get_fw_version() & 0xffff0000) {
  case 0x1000000:
  case 0x1010000:
  case 0x1020000:
  case 0x1050000:
  case 0x1100000:
  case 0x1110000:
  case 0x1120000:
  case 0x1130000:
  case 0x1140000:
  case 0x2000000:
  case 0x2200000:
  case 0x2250000:
  case 0x2260000:
  case 0x2300000:
  case 0x2500000:
  case 0x2700000:
  if(notify_user)
    notify("1.xx-2.xx doesnt use kstuff, aborting...");
  return;       
  case 0x3000000:
  case 0x3100000:
  case 0x3200000:
  case 0x3210000:
    sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xca0cd8;
    sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xca0e50;
    success = true;
    break;
 
  case 0x4000000:
  case 0x4020000:
  case 0x4030000:
  case 0x4500000:
  case 0x4510000:
    sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xd11bb8;
    sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xd11d30;
    success = true;
    break;
 
  case 0x5000000:
  case 0x5020000:
  case 0x5100000:
  case 0x5500000:
    sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xe00be8;
    sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe00d60;
    success = true;
    break;
 
  case 0x6000000:
  case 0x6020000:
  case 0x6500000:
    sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xe210a8;
    sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe21220;
    success = true;
    break;

  case 0x7000000:
  case 0x7010000:
     sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xe21ab8;
     sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe21c30;
     success = true;
     break;
  case 0x7200000:
  case 0x7400000:
  case 0x7600000:
  case 0x7610000:
     sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xe21b78;
     sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe21cf0;
     success = true;
     break;

  case 0x8000000:
  case 0x8200000:
  case 0x8400000:
  case 0x8600000:
    sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xe21ca8;
    sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe21e20;
    success = true;
    break;

  case 0x9000000:
  case 0x9050000:
  case 0x9200000:
  case 0x9400000:
  case 0x9600000:
      sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xdba648;
      sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xdba7c0;
    success = true;
    break;

  case 0x10000000:
  case 0x10010000:
  case 0x10200000:
  case 0x10400000:
  case 0x10600000:
      sysentvec = KERNEL_ADDRESS_DATA_BASE + 0xdba6d8;
      sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xdba850;
    success = true;
    break;
 
  default:
    notify("Unsupported firmware");
  }

  if(!success){
      notify("Failed to get sysentvec address, aborting...");
      return;
  }

  global_conf.kstuff_pause_opt = opt;

  if(opt == NOT_PAUSED){
    bool ps4_unpaused = false;
    bool ps5_unpaused = false;
    if(kernel_getshort(sysentvec_ps4 + 14) == 0xffff) {
        kernel_setshort(sysentvec_ps4 + 14, 0xdeb7);
        ps4_unpaused = true;
    }
    if(kernel_getshort(sysentvec + 14) == 0xffff) {
        kernel_setshort(sysentvec + 14, 0xdeb7);
        ps5_unpaused = true;
    }

    if(notify_user){
        if (ps5_unpaused && ps4_unpaused) {
            if (global_conf.overlay_kstuff) {
                RemoveGameWidget(REMOVE_KSTUFF_DISABLED);
                global_conf.overlay_kstuff_active = false;
            }
            else {
                notify("[Kstuff] both sysentvecs unpaused");
            }
        }
        else if(ps5_unpaused)
           notify("[Kstuff] PS5 sysentvec unpaused");
        else if(ps4_unpaused)
           notify("[Kstuff] PS4 sysentvec unpaused");
    } 
  }
  else if (opt == PS5_ONLY) // pause ps5 only
  {
    if(kernel_getshort(sysentvec_ps4 + 14) != 0xffff) {
        kernel_setshort(sysentvec_ps4 + 14, 0xffff);
      
        if(notify_user)
           notify("[Kstuff] PS4 sysentvec paused");
      } 
  }
  else if (opt == PS4_ONLY) // pause ps4 only
  {
    if(kernel_getshort(sysentvec + 14) != 0xffff) {
        kernel_setshort(sysentvec + 14, 0xffff);

        if(notify_user)
           notify("[Kstuff] PS5 sysentvec paused");
      } 
  }
  else if (opt == BOTH_PAUSED) // pause both
  {
    kernel_setshort(sysentvec + 14, 0xffff);
    kernel_setshort(sysentvec_ps4 + 14, 0xffff);

    if (notify_user) {
        if (global_conf.overlay_kstuff) {
            CreateGameWidget(CREATE_KSTUFF_DISABLED);
            global_conf.overlay_kstuff_active = true;
        }
		else
            notify("[Kstuff] both sysentvec paused");
    } 
      
  }

}

void* kstuff_pause_thread(void* arg){
    sleep(2);
    sleep(global_conf.pause_kstuff_on_open_secs);

    if(!if_exists("/user/data/etaHEN/no_kstuff") && !if_exists("/usb0/etaHEN/no_kstuff")){
        pause_resume_kstuff(BOTH_PAUSED, true);
    }
    return nullptr;
}

extern "C" int sceKernelGetSocSensorTemperature(int numb, int *temp);

extern "C" int sceNetGetIfList(SceNetIfName ifName_num, SceNetIfList* ifListArray, int n);

MonoString* Hook_getIpMacHost(uint64_t inst, SceNetIfName name) {

    char ip_address[32];
    char full_text[400];
    int temp = 0;


    if(!inst) {
        shellui_log("inst is null");
    }

  //  shellui_log("Hook_getIpMacHost: inst: %llx, name: %d", inst, name);

    if (global_conf.kit_panel_info == 3) { // OFF

        return getIpMacHost(inst, name);
    }

    SceNetIfList ifArray[1];
    sceNetGetIfList(name, ifArray, 1);
    
    // Extract IP address bytes from the s_addr value
    uint8_t bytes[4];
    bytes[0] = (ifArray[0].addrs[0].addr.s_addr) & 0xFF;
    bytes[1] = (ifArray[0].addrs[0].addr.s_addr >> 8) & 0xFF;
    bytes[2] = (ifArray[0].addrs[0].addr.s_addr >> 16) & 0xFF;
    bytes[3] = (ifArray[0].addrs[0].addr.s_addr >> 24) & 0xFF;
    
    // Format the IP address as a string
    sprintf(ip_address, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

    if(name == SCE_NET_IF_NAME_DBG0 ){
        return mono_string_new(Root_Domain, std::string(std::string("IP (DEV): ") + std::string(ip_address) + "\n").c_str());
    }

    //SCE_NET_IF_NAME_PHYSICAL

    snprintf(full_text, sizeof(full_text), "etaHEN Version: %s\nIP: %s", etaHEN_VERSION, ip_address);
    if (global_conf.kit_panel_info == 0 || sceKernelGetSocSensorTemperature(0, &temp)) { // ON (ONLY)
        return mono_string_new(Root_Domain, full_text);
    }


    snprintf(full_text, sizeof(full_text), "%s\nAPU Temp: %d °C", full_text, temp);
    if (global_conf.kit_panel_info == 1) { // ON + temp
        return mono_string_new(Root_Domain, full_text);
    }

    snprintf(full_text, sizeof(full_text), "%s\nFTP: 1337\nDPI: 9090\nELF Loader: 9021", full_text);
    return mono_string_new(Root_Domain, full_text);
}


int PupExpirationGetStatus_hook(PupStatus& status, uint32_t& time) {
    int opt = global_conf.trial_soft_expire_time;

    time = 0;
    if (opt == TRIAL_EXPIREING_OFF) {
        status = PUP_EXPIRATION_STATUS_OK;
    }
    else if (opt == TRIAL_EXPIREING_1_DAY) {
        status = PUP_EXPIRATION_STATUS_EXPIRING;
        time = PUP_EXPIRATION_1_DAY;
    }
    else if (opt == TRIAL_EXPIREING_2_DAYS) {
        status = PUP_EXPIRATION_STATUS_EXPIRING;
        time = PUP_EXPIRATION_MAX_EXPIRING_TIME;
    }
    else if (opt == TRIAL_EXPIRED) {
        status = PUP_EXPIRATION_STATUS_EXPIRED;
    }

    return 0;
}

int Hook_GetHwSerialNumber(MonoArray* serial) {
    // Ensure there's an array to work with

 //   shellui_log("Hook_GetHwSerialNumber: serial: %llx", serial);
    mono_array_set(serial, uint8_t, 0, '1');
    mono_array_set(serial, uint8_t, 1, '3');
    mono_array_set(serial, uint8_t, 2, '3');
    mono_array_set(serial, uint8_t, 3, '7');

    // Return a success status
    return SCE_OK;
}


int Hook_GetHwModelName(MonoArray* serial) {
    // Ensure there's an array to work with


   // shellui_log("Hook_GetHwModelName: serial: %p", serial);
    mono_array_set(serial, uint8_t, 0, 'e');
    mono_array_set(serial, uint8_t, 1, 't');
    mono_array_set(serial, uint8_t, 2, 'a');
    mono_array_set(serial, uint8_t, 3, 'H');
    mono_array_set(serial, uint8_t, 4, 'E');
    mono_array_set(serial, uint8_t, 5, 'N');
    mono_array_set(serial, uint8_t, 6, ' ');
    
#if SHELL_DEBUG == 1
    mono_array_set(serial, uint8_t, 7, '(');
    mono_array_set(serial, uint8_t, 8, 'D');
    mono_array_set(serial, uint8_t, 9, 'E');
    mono_array_set(serial, uint8_t, 10, 'V');
    mono_array_set(serial, uint8_t, 11, ')');
#else
    mono_array_set(serial, uint8_t, 7, '(');
    mono_array_set(serial, uint8_t, 8, 'K');
    mono_array_set(serial, uint8_t, 9, 'I');
    mono_array_set(serial, uint8_t, 10,'T');
    mono_array_set(serial, uint8_t, 11, ')');
#endif

    // Return a success status
    return SCE_OK;
}


/*================================NOT USED ================================*/
int (*GetIfList)(SceNetIfName name, MonoArray* ifListArray, int n) = nullptr;

int Hook_GetIfList(SceNetIfName name, MonoArray* ifListArray, int n) {

   // shellui_log("Hook_GetIfList: name: %d, n: %d", name, n);
    if(!ifListArray){
        shellui_log("ifListArray is null");
    
    }

    if(global_conf.kit_panel_info == 3) // OFF
       return -1;
    else
		return GetIfList(name, ifListArray, n);
}

extern MonoString* (*getIpMacHost)(uint64_t inst, SceNetIfName name);

MonoString* Hook_getIpMacHost(uint64_t inst, SceNetIfName name);

bool Toggle_Devkit_Panel(int pot) {

    // leaving this here but it crashes past 3.00
    if (false) {
        MonoAssembly* SysBridge_Assembly = mono_domain_assembly_open(Root_Domain, "/system_ex/common_ex/lib/Sce.Vsh.SysBridge.dll");
        if(!SysBridge_Assembly){
            shellui_log("Failed to open SysBridge Assembly");
            return false;
        }
        MonoImage* SysBridge_img = mono_assembly_get_image(SysBridge_Assembly);
        if (!SysBridge_img) {
           shellui_log("Failed to get ReactNativeShellApp image");
           return false;
        }
    
        GetIfList = (int (*)(SceNetIfName name, MonoArray * ifListArray, int n))DetourFunction(Get_Address_of_Method(SysBridge_img, "Sce.Vsh.SysBridge", "Net", "GetIfList", 3), (void*)&Hook_GetIfList);
        if (!GetIfList) {
            notify("Failed to detour Func GetIfList");
            return false;
        }
    }
    
    if(!getIpMacHost){
        
        MonoAssembly* Assembly = mono_domain_assembly_open(Root_Domain, "/system_ex/common_ex/lib/Sce.Vsh.ShellUI.ReactNativeShellApp.dll");
        if(!Assembly) {
            shellui_log("Failed to open ReactNativeShellApp Assembly");
            return false;
        }

        MonoImage* ReactNativeShellApp_image = mono_assembly_get_image(Assembly);

        if (!ReactNativeShellApp_image) {
           shellui_log("Failed to get ReactNativeShellApp image");
           return false;
        }


        getIpMacHost = (MonoString * (*)(uint64_t inst, SceNetIfName name))DetourFunction(Get_Address_of_Method(ReactNativeShellApp_image, "ReactNative.Components.ShellUI.HomeUI", "DebugInfoView", "getIpMacHost", 1), (void*)&Hook_getIpMacHost);
        if (!getIpMacHost) {
            notify("Failed to detour Func getIpMacHost");
            return false;
        }

    }

	global_conf.kit_panel_info = pot;

    return true;

}
int DevActGetRemainingTime(int* time){
    *time = INT_MAX-1;
    return 0;
} 

//GetHwModelNam
bool Start_Kit_Hooks() {
    //Sce.Vsh.SysBridge.dll
    MonoAssembly* KernelSysWrapper_Assembly = mono_domain_assembly_open(Root_Domain, "/system_ex/common_ex/lib/Sce.Vsh.KernelSysWrapper.dll");

    MonoImage* KernelSysWrapper_img = mono_assembly_get_image(KernelSysWrapper_Assembly);

    if (!KernelSysWrapper_img) {
        shellui_log("Failed to get ReactNativeShellApp image");
        return false;
    }

    if(if_exists("/system_tmp/actipatched")){
       void* unused = DetourFunction(Get_Address_of_Method(KernelSysWrapper_img, "Sce.Vsh", "KernelSysWrapperSbl", "DevActGetRemainingTime", 1), (void*)&DevActGetRemainingTime);
       if (!unused) {
           notify("Failed to detour Func DevActGetRemainingTime");
           return false;
       }
    }



    PupExpirationGetStatus = (int (*)(PupStatus & status, uint32_t & time))DetourFunction(Get_Address_of_Method(KernelSysWrapper_img, "Sce.Vsh", "KernelSysWrapperSbl", "PupExpirationGetStatus", 2), (void*)&PupExpirationGetStatus_hook);
    if (!PupExpirationGetStatus) {
        notify("Failed to detour Func PupExpirationGetStatus");
        return false;
    }

    MonoAssembly* SysBridge_Assembly = mono_domain_assembly_open(Root_Domain, "/system_ex/common_ex/lib/Sce.Vsh.SysBridge.dll");
    MonoImage* SysBridge_img = mono_assembly_get_image(SysBridge_Assembly);
    if (!SysBridge_img) {
        shellui_log("Failed to get ReactNativeShellApp image");
        return false;
    }


#if SHELL_DEBUG == 1
    GetHwSerialNumber = (int (*)(MonoArray * serial))DetourFunction(Get_Address_of_Method(SysBridge_img, "Sce.Vsh.SysBridge", "Kernel", "GetHwSerialNumber", 1), (void*)&Hook_GetHwSerialNumber);
    if (!GetHwSerialNumber) {
        notify("Failed to detour Func GetHwSerialNumber");
        return false;
    }
#endif

  //GetManufacturingMode

    GetHwModelName = (int (*)(MonoArray * serial))DetourFunction(Get_Address_of_Method(SysBridge_img, "Sce.Vsh.SysBridge", "Kernel", "GetHwModelName", 1), (void*)&Hook_GetHwModelName);
    if (!GetHwModelName) {
        notify("Failed to detour Func GetHwModelName");
        return false;
    }

    MonoAssembly* Assembly = mono_domain_assembly_open(Root_Domain, "/system_ex/common_ex/lib/Sce.Vsh.ShellUI.ReactNativeShellApp.dll");

    MonoImage* ReactNativeShellApp_image = mono_assembly_get_image(Assembly);

    if (!ReactNativeShellApp_image) {
        shellui_log("Failed to get ReactNativeShellApp image");
        return false;
    }

    getIpMacHost = (MonoString * (*)(uint64_t inst, SceNetIfName name))DetourFunction(Get_Address_of_Method(ReactNativeShellApp_image, "ReactNative.Components.ShellUI.HomeUI", "DebugInfoView", "getIpMacHost", 1), (void*)&Hook_getIpMacHost);
    if (!getIpMacHost) {
        notify("Failed to detour Func getIpMacHost");
        return false;
    }

    Toggle_Devkit_Panel(global_conf.kit_panel_info);
	shellui_log("We are all set captain!");
	return true;

}
std::atomic_int sockfd = -1;

int connect_to_host(int port) {
    int fd = -1;
    // Configure the address structure
    struct sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    memset(address.sin_zero, 0, sizeof(address.sin_zero));

    // Convert IP address to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) <= 0) {
        fprintf(stderr, "inet_pton failed");
        return -1;
    }

    // Create the socket
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        shellui_log("socket creation failed");
        return -1;
    }

    // Connect to the server
    if (connect(fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        shellui_log("connect failed");
        close(fd);
        return -1;
    }

    shellui_log("Connected to host %d",  port);
    return fd;
}

bool Try_connect_to_host(int port) {
    sockfd = connect_to_host(port);
    if (sockfd.load() >= 0) {
        close(sockfd.load()), sockfd = -1; // Close the socket after successful connection
        return true; // Successfully connected
    }
    return false; // Failed to connect after retries
}
bool send_payload(const unsigned char *payload, size_t size) {
  int fd = connect_to_host(9021);
  int ret = sceNetSend(fd, payload, size, MSG_NOSIGNAL);
  shellui_log("sceNetSend ret: 0x%08X", ret);
  close(fd), fd = -1; // Close the socket after sending the payload
  return ret >= 0;
}

bool read_and_send_file(const std::string& filePath) {
    // Open the file in binary mode and seek to the end to get the size
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file) {
        shellui_log("Failed to open file: %s", filePath.c_str());
        return false;
    }

    // Get the file size
    std::streamsize size = file.tellg();
    if (size <= 0) {
        shellui_log("File is empty or failed to determine size: %s", filePath.c_str());
        return false;
    }

    file.seekg(0, std::ios::beg);

    // Read the file into a buffer
    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        shellui_log("Failed to read file: %s", filePath.c_str());
        return false;
    }

    file.close();
    shellui_log("File read successfully: %s, size: %zu bytes", filePath.c_str(), size);
    // Send the payload using the provided function
    if(!send_payload(buffer.data(), buffer.size())){
        shellui_log("Failed to send payload from file: %s", filePath.c_str());
        return false;
    }
    return true;
}
void* launch_thr(void*) {
    pause_resume_kstuff(NOT_PAUSED, false);

    if(!read_and_send_file("/user/data/etaHEN/etaHEN.bin")){
        notify("Failed to send etaHEN payload!, failed to exit lite mode");
        return nullptr;
    }

    GoToHome();
    shellui_log("launch_thr exiting");
    notify("Lite Mode is disabled, relaunching the home menu in 3 secs, remember to relaunch your plugins after");
    sleep(3);
    kill(getpid(), SIGKILL); // Forcefully exit the process
    global_conf.lite_mode = !global_conf.lite_mode;
    pthread_exit(nullptr);
    return nullptr;
}

void* switch_to_lite(void*) {
    int sec = 0;
    notify("Verifiying the elfldr is running (max 15 secs), please wait...");
    while((!Try_connect_to_host(9021))){
        if(sec > 15){
            notify("Failed to connect to Johns elf loader on port 9021, unable to enter lite mode");
            return nullptr;
        }
        sleep(1);
        sec++;
    }
    global_conf.lite_mode = !global_conf.lite_mode;
    GoToHome();
    touch_file("/system_tmp/lite_mode");

    // kill etaHEN
    IPC_Client& util_ipc = IPC_Client::getInstance(true);
    util_ipc.KillDaemon();
    IPC_Client& main_ipc = IPC_Client::getInstance(false);
    main_ipc.KillDaemon();

    notify("Lite mode is active!");
    pthread_exit(nullptr);
	return nullptr;

}

void ParseCheatID(const char* id, char* tid, int* cheat_id)
{
    sscanf(id, "id_cheat_%[^_]_%d", tid, cheat_id);
}

//
// Scene has changed, stop Remote Play thread if is running
//
void UpdateImposeStatusFlag_hook(MonoObject* scene, MonoObject* frontActiveScene)
{
    if(!frontActiveScene || !scene) {
        shellui_log("Scene or frontActiveScene is null, returning...");
        return;
    }
    if (!is_remote_play && IsRunningConfirmRegistLoop)
    {
        StopConfirmRegistLoop();
    }

    if (is_remote_play)
    {
        //
        // If the scene is switching, means that we exiting from the current state, a state machine would be good here
        // otherwise we would need to reverse the SceneBase     
        //
        is_remote_play = false; 
    }

    UpdateImposeStatusFlag_Orig(scene, frontActiveScene);
}

void* load_plugin_thread(void* args) {
    Plugins *plugin = (Plugins*)args;

    notify("Loading Plugin %s ...", plugin->path.c_str());
    IPC_Client& util_ipc = IPC_Client::getInstance(true);
    if (util_ipc.LaunchPlugin(plugin->path, plugin->tid) != IPC_Ret::NO_ERROR) {
        notify("Failed to launch plugin %s (%s)", plugin->path.c_str(), plugin->tid.c_str());
    }

    delete plugin;
    pthread_exit(nullptr);
    return nullptr;
}
extern std::string remote_play_info;
void* store_install_thread(void* args) {
    if(install_thread_in_progress){
        notify("Install action already in progress, please wait for it to complete...");
        pthread_exit(nullptr);
        return nullptr;
    }
    install_thread_in_progress = true;
    IPC_Client& main_ipc = IPC_Client::getInstance(false);
    shellui_log("Ret: 0x%X", main_ipc.DownloadTheStore());
    install_thread_in_progress = false;
    pthread_exit(nullptr);
    return nullptr;
}

void* load_ps5debug_thr(void*){
    IPC_Client& main_ipc = IPC_Client::getInstance(false);
    if(!main_ipc.Toggle_ps5debug()){
        notify("Failed to toggle PS5Debug");
    }
    pthread_exit(nullptr);
    return nullptr;
}
void* download_cheats_thr(void*){
    if(cheat_action_in_progress){
        notify("Cheat action already in progress, please wait for it to complete...");
        pthread_exit(nullptr);
        return nullptr;
    }
    cheat_action_in_progress = true;
    notify("Preparing to download the %s cheats repo...", global_conf.selected_cheats_repo == CHEATS_REPO_ETAHEN ? "etaHEN PS5" : "GoldHEN PS4");
    IPC_Client& util_ipc = IPC_Client::getInstance(true);
    // daemon shows notification when done
    util_ipc.Cheats_Action(DOWNLOAD_CHEATS, global_conf.selected_cheats_repo);
    
    cheat_action_in_progress = false;
    pthread_exit(nullptr);
    return nullptr;
}

void* reload_cheats_thr(void*){
    if(cheat_action_in_progress){
        notify("Cheat action already in progress, please wait for it to complete...");
        pthread_exit(nullptr);
        return nullptr;
    }
    cheat_action_in_progress = true;
    IPC_Client& util_ipc = IPC_Client::getInstance(true);
    if (util_ipc.Cheats_Action(RELOAD_CHEATS, 0)) 
       notify("The Cheats have been Cache and cheats list has been successfully reloaded");

    cheat_action_in_progress = false;
    pthread_exit(nullptr);
    return nullptr;
}

void* kstuff_download_thread(void* args) {
    if (download_kstuff_thread_in_progress) {
        notify("Download action already in progress, please wait for it to complete...");
        pthread_exit(nullptr);
        return nullptr;
    }
    download_kstuff_thread_in_progress = true;
    IPC_Client& util_ipc = IPC_Client::getInstance(true);
    shellui_log("Ret: 0x%X", util_ipc.DownloadKstuff());
    download_kstuff_thread_in_progress = false;
    pthread_exit(nullptr);
    return nullptr;
}

int OnPress_Hook(MonoObject* Instance, MonoObject* element, MonoObject* e)
{
    bool& FTP = global_conf.FTP;
    bool& Klog = global_conf.Klog;
    bool& DPI = global_conf.DPI;
    bool& Auto_ItemzFlow = global_conf.launch_itemzflow;
    bool& Data_SB = global_conf.allow_data_sandbox;
    bool& FTP_Dev_Access = global_conf.ftp_dev_access;
    int& StartOption = global_conf.start_option;
    bool& lite_mode = global_conf.lite_mode;
    bool& sis_PS5Debug = global_conf.PS5Debug;
    bool& util_rest_kill = global_conf.util_rest_kill;
    bool& game_rest_kill = global_conf.game_rest_kill;
    int& trial_expire = global_conf.trial_soft_expire_time;
    int& kit_panel = global_conf.kit_panel_info;
    uint64_t& delay_secs = global_conf.rest_delay_seconds;
    bool& DPI_v2 = global_conf.DPI_v2;
    int& kstuff_pause_opt = global_conf.kstuff_pause_opt;
    bool& dis_tids = global_conf.display_tids;
    cheats_repo_source& selected_cheats_repo = global_conf.selected_cheats_repo;

    // Define the array of IDs to exclude (you can put this at the top of your function or as a static/global)
    const std::vector<std::string> excludedIds = {
        "id_download_store",
        "id_dl_cheats",
        "id_reload_cheats",
        "id_save_rp_info",
        "id_download_kstuff",
        "id_delete_kstuff"
    };


    // shellui_log("OnPress_Hook: %p, %p, %p", Instance, element, e);
    if (!Instance || !element)
    {
#if SHELL_DEBUG==1
        shellui_log("[LM HOOK] OnPress_Hook: args are null");
#endif
        return oOnPress(Instance, element, e);
    }

    std::string id = GetPropertyValue(element, "Id");
    std::string value = GetPropertyValue(element, "Value");
    std::string title = GetPropertyValue(element, "Title");

    bool is_game = (id.rfind("id_etahen_game_loader_") != std::string::npos);
    bool is_cust_pkg = (id.rfind("id_pkg_") != std::string::npos);

    if (id.rfind("id_cheat_") != std::string::npos && !is_current_game_open) {
        notify("The Game is not running, to activate cheats launch the game first");
#if SHELL_DEBUG==1
        shellui_log("Failed to activate %s, game is not running", id.c_str());
#endif
        return oOnPress(Instance, element, e);
    }

    // Check if id is in the excluded list
    bool isExcludedId = std::find(excludedIds.begin(), excludedIds.end(), id) != excludedIds.end();
    if (value.empty() && !isExcludedId && !is_game && !is_cust_pkg) {
#if SHELL_DEBUG==1
        shellui_log("[LM HOOK] OnPress_Hook: Id: %s has no value set", id.c_str());
#endif
        return oOnPress(Instance, element, e);
    }


    bool reload_main_settings = false;
    bool reload_util_settings = false;

#if SHELL_DEBUG==1
    shellui_log("[LM HOOK] OnPress_Hook: Id: %s, Value: %s", id.c_str(), value.c_str());
#endif
    if (id == "id_download_kstuff") {
        pthread_t thr;
        pthread_create(&thr, nullptr, kstuff_download_thread, nullptr);
        pthread_detach(thr);
    }
    else if (id == "id_overlay_gpu") {
		if (atoi(value.c_str()) == global_conf.overlay_gpu) {
			return oOnPress(Instance, element, e);
		}
        if (!atoi(value.c_str())) {
            RemoveGameWidget(REMOVE_GPU_OVERLAY);
        }
        else {
			CreateGameWidget(CREATE_GPU_OVERLAY);
        }

        global_conf.overlay_gpu = !global_conf.overlay_gpu;
    }
    else if (id == "id_overlay_cpu") {
		if (atoi(value.c_str()) == global_conf.overlay_cpu) {
			return oOnPress(Instance, element, e);
		}
        if (!atoi(value.c_str())) {
            if (!global_conf.all_cpu_usage) {
				RemoveGameWidget(REMOVE_CPU_OVERLAY);
            }
            else {
				notify("To disable CPU overlay, please disable the All CPU usage option first");
				return oOnPress(Instance, element, e);
            }
        }
        else {
			CreateGameWidget(CREATE_CPU_OVERLAY);
            
        }

        global_conf.overlay_cpu = !global_conf.overlay_cpu;
    }
    else if (id == "id_overlay_ram") {
		if (atoi(value.c_str()) == global_conf.overlay_ram) {
			return oOnPress(Instance, element, e);
		}
        if (!atoi(value.c_str())) {
			RemoveGameWidget(REMOVE_RAM_OVERLAY);
        }
        else {
			CreateGameWidget(CREATE_RAM_OVERLAY);   
        }

        global_conf.overlay_ram = !global_conf.overlay_ram;
    }
    else if (id == "id_overlay_fps") {
		if (atoi(value.c_str()) == global_conf.overlay_fps) {
			return oOnPress(Instance, element, e);
		}
        if (!atoi(value.c_str())) {
			RemoveGameWidget(REMOVE_FPS_OVERLAY);
            unlink("/system_tmp/fps_enabled");
            
        }
        else {
			CreateGameWidget(CREATE_FPS_OVERLAY);
            touch_file("/system_tmp/fps_enabled");
        }

        global_conf.overlay_fps = !global_conf.overlay_fps;
    }
    else if (id == "id_overlay_ip") {
		if (atoi(value.c_str()) == global_conf.overlay_ip) {
			return oOnPress(Instance, element, e);
		}
        if (!atoi(value.c_str())) {
            RemoveGameWidget(REMOVE_IP_OVERLAY);
        }
        else {
            CreateGameWidget(CREATE_IP_OVERLAY);
        }

        global_conf.overlay_ip = !global_conf.overlay_ip;
	}
    else if (id == "id_overlay_kstuff") {
        if (atoi(value.c_str()) == global_conf.overlay_kstuff) {
            return oOnPress(Instance, element, e);
        }
        global_conf.overlay_kstuff = !global_conf.overlay_kstuff;
        if(!global_conf.overlay_kstuff && global_conf.overlay_kstuff_active){
            RemoveGameWidget(REMOVE_KSTUFF_DISABLED);
            global_conf.overlay_kstuff_active = false;
		}
    }
    else if (id == "id_all_cpu_usage") {
        if (global_conf.all_cpu_usage == atoi(value.c_str())) {
            return oOnPress(Instance, element, e);
		}
        if(!global_conf.overlay_cpu){
            notify("To change CPU overlay mode, please enable the CPU overlay first");
            return oOnPress(Instance, element, e);
		}
        global_conf.all_cpu_usage = !global_conf.all_cpu_usage;
    }
    else if (id == "id_overlay_change_pos") {

        if((overlay_positions)atoi(value.c_str()) == global_conf.overlay_pos){
            return oOnPress(Instance, element, e);
		}

        global_conf.overlay_pos = (overlay_positions)atoi(value.c_str());

        if (global_conf.overlay_pos == OVERLAY_POS_TOP_LEFT) {
            global_conf.overlay_fps_x = 10.0f;
            global_conf.overlay_fps_y = 10.0f;

            global_conf.overlay_gpu_x = 10.0f;
            global_conf.overlay_gpu_y = 35.0f;

            global_conf.overlay_cpu_x = 10.0f;
            global_conf.overlay_cpu_y = 60.0f;

            global_conf.overlay_ram_x = 10.0f;
            global_conf.overlay_ram_y = 85.0f;

            global_conf.overlay_ip_x = 10.0f;
            global_conf.overlay_ip_y = 110.0f;
        }
        else if (global_conf.overlay_pos == OVERLAY_POS_BOTTOM_LEFT) {
            global_conf.overlay_ram_x = 10.0f;
            global_conf.overlay_ram_y = 970.0f;
            global_conf.overlay_cpu_x = 10.0f;
            global_conf.overlay_cpu_y = 990.0f;
            global_conf.overlay_gpu_x = 10.0f;
            global_conf.overlay_gpu_y = 1010.0f;
            global_conf.overlay_fps_x = 10.0f;
            global_conf.overlay_fps_y = 1030.0f;
            global_conf.overlay_ip_x = 10.0f;
            global_conf.overlay_ip_y = 1050.0f;
        }
        else if (global_conf.overlay_pos == OVERLAY_POS_TOP_RIGHT) {
            global_conf.overlay_fps_x = 1720.0f;
            global_conf.overlay_fps_y = 10.0f;
            global_conf.overlay_gpu_x = 1720.0f;
            global_conf.overlay_gpu_y = 35.0f;
            global_conf.overlay_cpu_x = 1720.0f;
            global_conf.overlay_cpu_y = 60.0f;
            global_conf.overlay_ram_x = 1720.0f;
            global_conf.overlay_ram_y = 85.0f;
            global_conf.overlay_ip_x = 1670.0f;;
            global_conf.overlay_ip_y = 110.0f;
        }
        else if (global_conf.overlay_pos == OVERLAY_POS_BOTTOM_RIGHT) {
            global_conf.overlay_ram_x = 1720.0f;
            global_conf.overlay_ram_y = 970.0f;
            global_conf.overlay_cpu_x = 1720.0f;
            global_conf.overlay_cpu_y = 990.0f;
            global_conf.overlay_gpu_x = 1720.0f;
            global_conf.overlay_gpu_y = 1010.0f;
            global_conf.overlay_fps_x = 1720.0f;
            global_conf.overlay_fps_y = 1030.0f;
            global_conf.overlay_ip_x = 1670.0f;
            global_conf.overlay_ip_y = 1050.0f;
        }
       
        if (global_conf.overlay_cpu) {
            RemoveGameWidget(REMOVE_CPU_OVERLAY);
            CreateGameWidget(CREATE_CPU_OVERLAY);
		}
        if (global_conf.overlay_ram) {
            RemoveGameWidget(REMOVE_RAM_OVERLAY);
			CreateGameWidget(CREATE_RAM_OVERLAY);
        }
		if (global_conf.overlay_gpu) {
			RemoveGameWidget(REMOVE_GPU_OVERLAY);
			CreateGameWidget(CREATE_GPU_OVERLAY);
        }
        if (global_conf.overlay_fps) {
            RemoveGameWidget(REMOVE_FPS_OVERLAY);
            CreateGameWidget(CREATE_FPS_OVERLAY);
        }
        if (global_conf.overlay_ip) {
            RemoveGameWidget(REMOVE_IP_OVERLAY);
            CreateGameWidget(CREATE_IP_OVERLAY);
		}
    }
    else if (id == "id_enable_kstuff_on_close"){
        global_conf.enable_kstuff_on_close = atoi(value.c_str());
    }
    else if (id == "id_pause_kstuff_on_open"){
        global_conf.pause_kstuff_on_open = atoi(value.c_str());
    }
    else if (id == "id_pause_kstuff_on_open_secs") {
        global_conf.pause_kstuff_on_open_secs = atol(value.c_str());
    }
    else if (id == "id_kstuff_autoload") {
       // if(atoi(value.c_str()) == if_exists("/user/data/etaHEN/no_kstuff")) {
		//	return oOnPress(Instance, element, e);
		//}
        if(atol(value.c_str())){
			unlink("/user/data/etaHEN/no_kstuff");
            notify("Kstuff will be loaded on next boot");
        }
        else{
            touch_file("/user/data/etaHEN/no_kstuff");
            notify("Kstuff will NOT be loaded on next boot");
		}
    }
    else if (id == "id_delete_kstuff") {
       unlink("/user/data/etaHEN/kstuff.elf");
	   notify("The external kstuff download has been deleted");
    }
    else if (id == "id_change_custom_pkg_path") {
		custom_pkg_path.path = value;
	}
    else if (id == "id_auto_eject") {
        global_conf.auto_eject_disc = atol(value.c_str());
    }
      else if (id.rfind("id_plugin") != std::string::npos)
    {
        if (!plugins_list.empty())
        {
            for (auto plugin : plugins_list)
            {
                if (plugin.id == id)
                {
                    int pid = -1;
                    if(plugin.tid.rfind(".elf") != std::string::npos && (pid = sceSystemServiceGetAppId(plugin.tid.c_str())) > 0){
                        IPC_Client::getInstance(false).ForceKillPID(pid);
                        notify("killed payload %s", plugin.tid.c_str());
                        break;
                    }
                    char pbuf[256];
                    snprintf(pbuf, sizeof(pbuf), "/system_tmp/%s.PID", plugin.tid.c_str());

                    int f = open(pbuf, O_RDONLY);
                    if (f >= 0)
                    {
                        char t[32];
                        int r = read(f, t, sizeof(t) - 1);
                        close(f);
                        if (r > 0)
                        {
                            t[r] = 0;
                            pid = atoi(t);
                        }
                    }

                    if (pid > 0)
                    {
                        char name[32];
                        if (sceKernelGetProcessName(pid, name) < 0)
                        {
                            shellui_log("Stale plugin PID file detected for %s, removing", plugin.tid.c_str());
                            unlink(pbuf);
                            pid = -1;
                        }
                    }

                    if (pid > 0 && atol(value.c_str()) == 0)
                    {
                        shellui_log("killing pid: 0x%X", pid);
                        IPC_Client::getInstance(false).ForceKillPID(pid);

                        if (plugin.tid == "XMLS00001")
                            unlink("/system_tmp/patch_plugin");

                        unlink(pbuf);

                        notify("%s killed", plugin.tid.c_str());
                        break;
                    }
                    else if (pid <= 0 && atol(value.c_str()) == 1)
                    {
                        pthread_t thr;
                        shellui_log("Plugin %s not running", plugin.tid.c_str());
                        auto plugin_info = new Plugins(plugin);
                        pthread_create(&thr, nullptr, load_plugin_thread, (void *)plugin_info);
                    }
                }
            }
        }
    }
    else if (is_cust_pkg) {
        if (custom_pkg_list.empty()) {
            return oOnPress(Instance, element, e);
        }
        for (auto selected_pkgs : custom_pkg_list) {
            if (selected_pkgs.id == id) {
#if SHELL_DEBUG==1
                shellui_log("[Clicked %s] %s path: %s", selected_pkgs.id.c_str(), selected_pkgs.name.c_str(), selected_pkgs.shellui_path.c_str());
#endif
                std::string dl_url;
                if (is_6xx)
                    dl_url = "http://127.0.0.1:12800" + selected_pkgs.path;
                else
                    dl_url = (selected_pkgs.path.rfind("/data") != std::string::npos) ? selected_pkgs.shellui_path : selected_pkgs.path;

                playgo_info_t playgoinfo = {};
                pkg_info_t pkginfo = {};
                pkg_metadata_t metainfo;
                metainfo.playgo_scenario_id = "";
                metainfo.content_name = "";
                metainfo.content_id = "";
                metainfo.icon_url = "";
                metainfo.ex_uri = "";
                metainfo.uri = dl_url.c_str();
                

                // msgok(MSG_DIALOG::NORMAL, "trying InstallByPackage");
				shellui_log("Installing package from: %s", metainfo.uri);
                int num = sceAppInstUtilInstallByPackage(&metainfo, &pkginfo, &playgoinfo);
                if (num != 0) {
					notify("Failed to install %s\nError: 0x%X\nis DPIv2 enabled???", selected_pkgs.name.c_str(), num);
                }
                else
                {
                    notify("%s installation started successfully", selected_pkgs.name.c_str());
                }
            }
        }
    }
    else if (is_game) {
        if(IPC_Client::getInstance(true).Launch_Game_By_ID(id) && global_conf.pause_kstuff_on_open){
            pthread_t thread;
            pthread_create(&thread, nullptr, kstuff_pause_thread, nullptr);
        }
    }
    else if (id.rfind("id_auto_plugin") != std::string::npos) {
		if (!auto_list.empty()) {
			for (auto plugin : auto_list) {
				if (plugin.id == id) {
                    std::string auto_path = plugin.shellui_path + ".auto_start";
                    shellui_log("Auto start path: %s", auto_path.c_str());
                    if (if_exists(auto_path.c_str()) && !atol(value.c_str())) {
					            	unlink(auto_path.c_str());
					           }
                    else if(atol(value.c_str())){
						int fd = open(auto_path.c_str(), O_CREAT | O_RDWR, 0777);
						if (fd < 0) {
							notify("Failed to create auto start file");
						}
						else {
							close(fd);
						}
					}
				}
			}
		}
	}
    else if (id.rfind("id_cheat_") != std::string::npos) {
        if(!is_current_game_open){
            notify("The Game is not running, to activate cheats launch the game first");
            shellui_log("Failed to activate %s, game is not running", id.c_str());
            return oOnPress(Instance, element, e);
        }
        char tid[32];
        int cheat_id;
        std::string cheat_name;
        ParseCheatID(id.c_str(), tid, &cheat_id);
        shellui_log("Getting PID for %s", id.c_str());
        int pid = find_pid(tid, false, true, true);
        if(pid < 0) {
            notify("[ERROR] Failed to activate %s\nfailed to find game pid", cheat_name.c_str());   
            shellui_log("Failed to get pid for %s", tid);
            return oOnPress(Instance, element, e);
        }
        
        shellui_log("Got proc for %s, tid %s, pid %i", id.c_str(), tid, pid);
        
        if (IPC_Client::getInstance(true).ToggleGameCheat(pid, tid, cheat_id, cheat_name))
        {
            if (currentCheatTID != tid)
            {
                currentCheatTID = tid;
                bzero(cheatEnabledMap, MAX_CHEATS);
            }

            bool enabled = value == "1";
            cheatEnabledMap[cheat_id] = enabled;
            notify("★ %s [%s] ★", cheat_name.c_str(), enabled ? "ON" : "OFF");
        }
        else{
            notify("[ERROR] Failed to activate %s", cheat_name.c_str());   
        }
    }  //payloads_apps_list
    else if (id.rfind("id_plapp_") != std::string::npos) {
        if(payloads_apps_list.empty()){
           return oOnPress(Instance, element, e);
        }
        // Handle payloads_apps_list
        std::string plapp_id = id;
        for (const auto& plapp : payloads_apps_list) {
            if (plapp.id == plapp_id) {
                // Do something with the matching payload
                break;
            }
        }
    }
    else if (id == "id_save_rp_info"){
      if(usbpath() == -1){
        notify("Failed to save Remote Play info, USB not found");
        return oOnPress(Instance, element, e);
      }

      std::string usb_rp_path = "/usb" + std::to_string(usbpath()) + "/remote_play_info.txt";
      shellui_log("Saving Remote Play info to %s", usb_rp_path.c_str());
      std::ofstream rp_file(usb_rp_path);
      if (!rp_file.is_open()) {
          notify("Failed to open Remote Play info file");
          return oOnPress(Instance, element, e);
      }
      rp_file << remote_play_info;
      rp_file.close();
      notify("Remote Play info saved to /mnt%s", usb_rp_path.c_str());

    }
    else if (id == "id_disp_titleids"){
        if (atol(value.c_str()) == dis_tids) {
            shellui_log("Display TIDs already %s", dis_tids ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        dis_tids = !dis_tids;
        ReloadRNPSApp("NPXS40002");
    }
    else if (id == "id_enable_fan_speed") {
        if (atol(value.c_str()) == global_conf.enable_fan_speed) {
            shellui_log("Fan speed control already %s", global_conf.enable_fan_speed ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        global_conf.enable_fan_speed = !global_conf.enable_fan_speed;
        IPC_Client::getInstance(false).Set_Fan_Threshold(global_conf.fan_threshold, global_conf.enable_fan_speed);

    }
    else if (id == "id_lm_test")
    {
        shellui_log("LM's Test Button Pressed");
        //call_show_alert(element, "msg_error_remoteplay_use_feature");
        //SendShelluiNotify();
        // notify("LM's Test Button Pressed (123)");
    }
    else if (id == "id_ftp_service") {
        if (atol(value.c_str()) == FTP) {
#if SHELL_DEBUG==1
            shellui_log("FTP already %s", FTP ? "Enabled" : "Disabled");
#endif
            return oOnPress(Instance, element, e);
        }
        FTP = !FTP;
        if (IPC_Client::getInstance(true).ToggleSetting(BREW_UTIL_TOGGLE_FTP, FTP) != IPC_Ret::NO_ERROR) {
            notify(FTP ? "FTP Server Failed to Start ..." : "FTP Server Failed to Stop ...");
            FTP = !FTP;
        }
    }
    else if (id == "id_etahen_credits") {
        // notify("Home Menu Button Pressed");
        return oOnPress(Instance, element, e);
    }//
    else if (id == "id_dl_cheats") {
        pthread_t thr;
        pthread_create(&thr, nullptr, download_cheats_thr, nullptr);
        pthread_detach(thr);
        return oOnPress(Instance, element, e);
    }//
    else if (id == "id_reload_cheats") {
        pthread_t thr;
        pthread_create(&thr, nullptr, reload_cheats_thr, nullptr);
        pthread_detach(thr);
        return oOnPress(Instance, element, e);
    }//
    else if (id == "id_klog_service") {
        // see if the resaults agress
        if (atoi(value.c_str()) == Klog) {
            shellui_log("Klog already %s", Klog ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        Klog = !Klog;
        if (IPC_Client::getInstance(true).ToggleSetting(BREW_UTIL_TOGGLE_KLOG, Klog) != IPC_Ret::NO_ERROR) {
            notify(Klog ? "Klog Server Failed to Start ..." : "Klog Server Failed to Stop ...");
            Klog = !Klog;
        }//
    }
    else if (id == "id_dpi_service") {
        if (atoi(value.c_str()) == DPI) {
            shellui_log("DPI already %s", DPI ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        DPI = !DPI;
        if (!IPC_Client::getInstance(true).ToggleDPI(DPI, false)) {
            notify(DPI ? "DPI Server Failed to Start ..." : "DPI Server Failed to Stop ...");
            DPI = !DPI;
        }
    }
    else if (id == "id_DPI_v2_service") {
        if (atoi(value.c_str()) == DPI_v2) {
            shellui_log("DPI_v2 already %s", DPI_v2 ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        DPI_v2 = !DPI_v2;
        if (!IPC_Client::getInstance(true).ToggleDPI(DPI_v2, true)) {
            notify(DPI_v2 ? "DPI_v2 Server Failed to Start ..." : "DPI_v2 Server Failed to Stop ...");
            DPI_v2 = !DPI_v2;
        }
    }
    else if (id == "id_download_store") {
        pthread_t thr;
        pthread_create(&thr, nullptr, store_install_thread, nullptr);
        pthread_detach(thr);

    }
    else if (id == "id_auto_itemzflow") {
        if (atoi(value.c_str()) == Auto_ItemzFlow) {
            shellui_log("ItemzFlow auto launch already %s", Auto_ItemzFlow ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
		}
        Auto_ItemzFlow = !Auto_ItemzFlow;
        //(global_conf.launch_itemzflow ? "ItemzFlow will automatically be opened after" : "ItemzFlow will not be launched on boot");
    }
    else if (id == "id_debug_jb") {
        if (atoi(value.c_str()) == global_conf.debug_app_jb_msg) {
            shellui_log("Debug JB already %s", global_conf.debug_app_jb_msg ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        global_conf.debug_app_jb_msg = !global_conf.debug_app_jb_msg;
        reload_main_settings = true;
    }
    else if (id == "id_debug_legacy_cmd") {
        if (atoi(value.c_str()) == global_conf.debug_legacy_cmd_server) {
            shellui_log("Debug cmd already %s", global_conf.debug_legacy_cmd_server ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        global_conf.debug_legacy_cmd_server = !global_conf.debug_legacy_cmd_server;

        if (IPC_Client::getInstance(true).ToggleSetting(BREW_UTIL_TOGGLE_LEGACY_CMD_SERVER, global_conf.debug_legacy_cmd_server) != IPC_Ret::NO_ERROR) {
            notify(global_conf.debug_legacy_cmd_server ? "cmd Failed to Start ..." : "CMD Server Failed to Stop ...");
            global_conf.debug_legacy_cmd_server = !global_conf.debug_legacy_cmd_server;
        }//
    }
    else if (id == "id_activate_dumper") {
        int dump_option = atoi(value.c_str());
        shellui_log("Dump option: %d", dump_option);
    }
    else if (id == "id_custom_game_opts") {
        if (atoi(value.c_str()) == global_conf.etaHEN_game_opts) {
            shellui_log("etaHEN Game Options already %s", global_conf.etaHEN_game_opts ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        global_conf.etaHEN_game_opts = !global_conf.etaHEN_game_opts;
        shellui_log("etaHEN Game Options: %s", global_conf.etaHEN_game_opts ? "Enabled" : "Disabled");
    }
    else if (id == "id_start_opt") {
        StartOption = atoi(value.c_str());
        Auto_ItemzFlow = false;
        shellui_log("Start option: %d", StartOption);
    }
    else if (id == "id_selected_cheats_repo") {
        selected_cheats_repo = static_cast<cheats_repo_source>(atoi(value.c_str()));
        shellui_log("Selected cheats repo: %s", selected_cheats_repo == CHEATS_REPO_ETAHEN ? "etaHEN PS5" : "GoldHEN PS4");
    }
    else if (id == "id_lite_mode") {
        if (atoi(value.c_str()) == lite_mode) {
            shellui_log("Lite Mode already %s", lite_mode ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        lite_mode = !lite_mode;
    }
    else if (id == "id_trial_soft") {
	      	trial_expire = atoi(value.c_str());
    }
    else if (id == "id_kit_panel") {
	    	kit_panel = atoi(value.c_str());
        shellui_log("Kit Panel: %d", kit_panel);

        if (!Toggle_Devkit_Panel(kit_panel)) {
		      	notify("Failed to toggle devkit panel");
        }
    }
    else if (id == "id_data_sb") {
        if (atoi(value.c_str()) == Data_SB) {
            shellui_log("Data Sandbox already %s", Data_SB ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        Data_SB = !Data_SB;
    }
    else if (id == "id_ftp_dev_access") {
        if (atoi(value.c_str()) == FTP_Dev_Access) {
            shellui_log("FTP Dev Access already %s", FTP_Dev_Access ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        FTP_Dev_Access = !FTP_Dev_Access;
    }
    else if(id == "id_toolbox_auto_start"){
        if (atoi(value.c_str()) == global_conf.toolbox_auto_start) {
            shellui_log("toolbox Access already %s", global_conf.toolbox_auto_start ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        global_conf.toolbox_auto_start = !global_conf.toolbox_auto_start;

    }
    else if (id == "id_sistro_ps5debug") {
        if (atoi(value.c_str()) == sis_PS5Debug) {
            shellui_log("PS5Debug already %s", sis_PS5Debug ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
      
        pthread_t thr;
        pthread_create(&thr, nullptr, load_ps5debug_thr, nullptr);
        pthread_detach(thr);

        sis_PS5Debug = !sis_PS5Debug;
    }
    else if (id == "id_rest_1") {
        delay_secs = atol(value.c_str());
    }
    else if (id == "id_fan_speed") {
        int &fan_speed = global_conf.fan_threshold;
        fan_speed = atoi(value.c_str());
        if(!global_conf.enable_fan_speed){
            notify("Manual Fan speed threshold is not enabled");
            return oOnPress(Instance, element, e);
        }
        shellui_log("Setting fan speed to %d%%", fan_speed);
        IPC_Client::getInstance(false).Set_Fan_Threshold(fan_speed, global_conf.enable_fan_speed);
    }
    else if (id == "id_rest_2") {
        if (atoi(value.c_str()) == util_rest_kill) {
            shellui_log("util_rest_kill already %s", util_rest_kill ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        util_rest_kill = !util_rest_kill;
    }
    else if (id == "id_rest_3") {
        if (atoi(value.c_str()) == game_rest_kill) {
            shellui_log("game_rest_kill already %s", game_rest_kill ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        game_rest_kill = !game_rest_kill; 
    }
    else if (id == "id_rest_4") {
      bool &disable_for_rest_mode = global_conf.disable_toolbox_auto_start_for_rest_mode ;
      if (atoi(value.c_str()) == disable_for_rest_mode) {
          shellui_log("game_rest_kill already %s", disable_for_rest_mode ? "Enabled" : "Disabled");
          return oOnPress(Instance, element, e);
      }
      disable_for_rest_mode = !disable_for_rest_mode; //global_conf.disable_toolbox_auto_start_for_rest_mode 
    }
    else if (id == "id_pause_kstuff"){
        if (atoi(value.c_str()) == kstuff_pause_opt) {
            shellui_log("kstuff_pause_opt already %s", kstuff_pause_opt ? "Enabled" : "Disabled");
            return oOnPress(Instance, element, e);
        }
        kstuff_pause_opt = atoi(value.c_str());
        pause_resume_kstuff((KstuffPauseStatus)kstuff_pause_opt, true);
            
    }
    else if (id == "id_cheats_shortcut") {
      if (atoi(value.c_str()) == global_conf.cheats_shortcut_opt) {
          shellui_log("Cheats_shortcut already %i", global_conf.cheats_shortcut_opt);
          return oOnPress(Instance, element, e);
      }
      Cheats_Shortcut opt = (Cheats_Shortcut)atoi(value.c_str());
  
      if(opt == CHEATS_SINGLE_SHARE ){
         if(global_conf.kstuff_shortcut_opt == KSTUFF_SINGLE_SHARE){
              shellui_log("Kstuff and Cheats shortcuts cannot be the same, current selection will NOT be saved");
              notify("Kstuff and Cheats shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.toolbox_shortcut_opt == TOOLBOX_SINGLE_SHARE){
              shellui_log("Toolbox and Cheats shortcuts cannot be the same, current selection will NOT be saved");
              notify("Toolbox and Cheats shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.games_shortcut_opt == GAMES_SINGLE_SHARE){
              shellui_log("Games and Cheats shortcuts cannot be the same, current selection will NOT be saved");
              notify("Games and Cheats shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
      }
      else if(opt == CHEATS_LONG_SHARE ){
         if(global_conf.kstuff_shortcut_opt == KSTUFF_LONG_SHARE){
              shellui_log("Kstuff and Cheats long shortcuts cannot be the same, current selection will NOT be saved");
              notify("Kstuff and Cheats long shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.toolbox_shortcut_opt == TOOLBOX_LONG_SHARE){
              shellui_log("Toolbox and Cheats long shortcuts cannot be the same, current selection will NOT be saved");
              notify("Toolbox and Cheats long shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.games_shortcut_opt == GAMES_LONG_SHARE){
              shellui_log("Games and Cheats long shortcuts cannot be the same, current selection will NOT be saved");
              notify("Games and Cheats long shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
      }
      global_conf.cheats_shortcut_opt = opt;
  }
  else if (id == "id_kstuff_shortcut") {
      if (atoi(value.c_str()) == global_conf.kstuff_shortcut_opt) {
          shellui_log("kstuff_shortcut_opt already %i", global_conf.kstuff_shortcut_opt);
          return oOnPress(Instance, element, e);
      }
      Kstuff_Shortcut opt = (Kstuff_Shortcut)atoi(value.c_str());
  
      if(opt == KSTUFF_SINGLE_SHARE ){
         if(global_conf.cheats_shortcut_opt == CHEATS_SINGLE_SHARE){
              shellui_log("Cheats and Kstuff shortcuts cannot be the same, current selection will NOT be saved");
              notify("Cheats and Kstuff shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.toolbox_shortcut_opt == TOOLBOX_SINGLE_SHARE){
              shellui_log("Toolbox and Kstuff shortcuts cannot be the same, current selection will NOT be saved");
              notify("Toolbox and Kstuff shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.games_shortcut_opt == GAMES_SINGLE_SHARE){
              shellui_log("Games and Kstuff shortcuts cannot be the same, current selection will NOT be saved");
              notify("Games and Kstuff shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
      }
      else if(opt == KSTUFF_LONG_SHARE ){
         if(global_conf.cheats_shortcut_opt == CHEATS_LONG_SHARE){
              shellui_log("Cheats and Kstuff long shortcuts cannot be the same, current selection will NOT be saved");
              notify("Cheats and Kstuff long shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.toolbox_shortcut_opt == TOOLBOX_LONG_SHARE){
              shellui_log("Toolbox and Kstuff long shortcuts cannot be the same, current selection will NOT be saved");
              notify("Toolbox and Kstuff long shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.games_shortcut_opt == GAMES_LONG_SHARE){
              shellui_log("Games and Kstuff long shortcuts cannot be the same, current selection will NOT be saved");
              notify("Games and Kstuff long shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
      }
      global_conf.kstuff_shortcut_opt = opt;
  }
  else if (id == "id_toolbox_shortcut" ){
      if (atoi(value.c_str()) == global_conf.toolbox_shortcut_opt) {
          shellui_log("toolbox_shortcut_opt already %i", global_conf.toolbox_shortcut_opt);
          return oOnPress(Instance, element, e);
      }
      Toolbox_Shortcut opt = (Toolbox_Shortcut)atoi(value.c_str());
  
      if(opt == TOOLBOX_SINGLE_SHARE ){
         if(global_conf.cheats_shortcut_opt == CHEATS_SINGLE_SHARE){
              shellui_log("Cheats and Toolbox shortcuts cannot be the same, current selection will NOT be saved");
              notify("Cheats and Toolbox shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.kstuff_shortcut_opt == KSTUFF_SINGLE_SHARE){
              shellui_log("Kstuff and Toolbox shortcuts cannot be the same, current selection will NOT be saved");
              notify("Kstuff and Toolbox shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.games_shortcut_opt == GAMES_SINGLE_SHARE){
              shellui_log("Games and Toolbox shortcuts cannot be the same, current selection will NOT be saved");
              notify("Games and Toolbox shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
      }
      else if(opt == TOOLBOX_LONG_SHARE ){
         if(global_conf.cheats_shortcut_opt == CHEATS_LONG_SHARE){
              shellui_log("Cheats and Toolbox long shortcuts cannot be the same, current selection will NOT be saved");
              notify("Cheats and Toolbox long shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.kstuff_shortcut_opt == KSTUFF_LONG_SHARE){
              shellui_log("Kstuff and Toolbox long shortcuts cannot be the same, current selection will NOT be saved");
              notify("Kstuff and Toolbox long shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.games_shortcut_opt == GAMES_LONG_SHARE){
              shellui_log("Games and Toolbox long shortcuts cannot be the same, current selection will NOT be saved");
              notify("Games and Toolbox long shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
      }
      global_conf.toolbox_shortcut_opt = opt;
  }
  else if (id == "id_games_shortcut" ){
      if (atoi(value.c_str()) == global_conf.games_shortcut_opt) {
          shellui_log("games_shortcut_opt already %i", global_conf.games_shortcut_opt);
          return oOnPress(Instance, element, e);
      }
      Games_Shortcut opt = (Games_Shortcut)atoi(value.c_str());
  
      if(opt == GAMES_SINGLE_SHARE ){
         if(global_conf.cheats_shortcut_opt == CHEATS_SINGLE_SHARE){
              shellui_log("Cheats and Games shortcuts cannot be the same, current selection will NOT be saved");
              notify("Cheats and Games shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.kstuff_shortcut_opt == KSTUFF_SINGLE_SHARE){
              shellui_log("Kstuff and Games shortcuts cannot be the same, current selection will NOT be saved");
              notify("Kstuff and Games shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.toolbox_shortcut_opt == TOOLBOX_SINGLE_SHARE){
              shellui_log("Toolbox and Games shortcuts cannot be the same, current selection will NOT be saved");
              notify("Toolbox and Games shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
      }
      else if(opt == GAMES_LONG_SHARE ){
         if(global_conf.cheats_shortcut_opt == CHEATS_LONG_SHARE){
              shellui_log("Cheats and Games long shortcuts cannot be the same, current selection will NOT be saved");
              notify("Cheats and Games long shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.kstuff_shortcut_opt == KSTUFF_LONG_SHARE){
              shellui_log("Kstuff and Games long shortcuts cannot be the same, current selection will NOT be saved");
              notify("Kstuff and Games long shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
          else if(global_conf.toolbox_shortcut_opt == TOOLBOX_LONG_SHARE){
              shellui_log("Toolbox and Games long shortcuts cannot be the same, current selection will NOT be saved");
              notify("Toolbox and Games long shortcuts cannot be the same, current selection will NOT be saved");
              return oOnPress(Instance, element, e);
          }
      }
      global_conf.games_shortcut_opt = opt;
  }
    else if (id == "id_lite_mode") {
        pthread_t thr = 0;
        if (!lite_mode) {
            shellui_log("ACTIVATING LITE MODE");
            if (plugins_list.empty()) {
                std::string new_xml_string;
                generate_plugin_xml(new_xml_string, true); // gen plugin list if its empty to be sure all the plugins are looked at
                if (plugins_list.empty()){
					         notify("No running plugins to kill");
			         	}
            }
        
            for (auto plugin : plugins_list) {
                int pid = sceSystemServiceGetAppId(plugin.tid.c_str());
                if (pid > 0) {
                    shellui_log("killing pid: 0x%X", pid);
                    IPC_Client::getInstance(false).ForceKillPID(pid);
                    notify("%s killed", plugin.tid.c_str());
                }
            }
            if(!Try_connect_to_host(9021) && !IPC_Client::getInstance(true).Launch_Elfldr()){
                notify("Failed to Launch Johns Elfldr, failed to enter lite mode");
                return oOnPress(Instance, element, e);
            }

            scePthreadCreate(&thr, NULL, switch_to_lite, NULL, "Switch to LITE thr");
            pthread_detach(thr);
        }
		else {
            if(!if_exists("/user/data/etaHEN/etaHEN.bin")){
                notify("/data/etaHEN/etaHEN.bin payload not found, please install it first");
                return oOnPress(Instance, element, e);
            }

            scePthreadCreate(&thr, NULL, launch_thr, NULL, "Switch to Normal thr");
            pthread_detach(thr);
		}

        
	} else {
        shellui_log("Not a toolbox item!");
    }

    SaveSettings();
    if(reload_main_settings){
       IPC_Client::getInstance(false).Reload_Daemon_Settings();
    }
    if(reload_util_settings){
       IPC_Client::getInstance(true).Reload_Daemon_Settings();
    }
   // shellui_log("[LM HOOK] OnPress_Hook: Id: %s, Value: %s", id.c_str(), value.c_str());

    return oOnPress(Instance, element, e);

}

extern std::string running_tid;
MonoString * CxmlUri_Hook(MonoObject * Instance, MonoString * uri) {

  if (!Instance || !uri) {
    #if SHELL_DEBUG==1 
    shellui_log("CxmlUri_Hook: args are null");
    #endif
    return CxmlUri(Instance, uri);
  }
  std::string uri_string = Mono_to_String(uri);
  #if SHELL_DEBUG==1 
  shellui_log("uri_string: %s", uri_string.c_str());
  #endif
  ///shellui_log("CxmlUri_Hook: %s", uri_string.c_str());
  if (uri_string.rfind("tex_store_icon") != std::string::npos) {
    //shellui_log("CxmlUri_Hook: Returning store icon");
    return mono_string_new(Root_Domain, "/user/data/etaHEN/assets/store.png");
  } else if (uri_string.rfind("tex_game_icon") != std::string::npos) {
    //shellui_log("CxmlUri_Hook: Returning store icon");
    std::string icon = "/user/appmeta/" + running_tid + "/icon0.png";
    if(!if_exists(icon.c_str())){
        icon = "/user/appmeta/external/" + running_tid + "/icon0.png";

        if(!if_exists(icon.c_str())){ // pirated PS5 Games
           std::string game_src = "/system_ex/app/" + running_tid + "/sce_sys/icon0.png"; // shellui cant access this path
           icon = "/user/appmeta/" + running_tid;
           mkdir(icon.c_str(), 0777);
           icon = "/user/appmeta/" + running_tid + "/icon0.png";
           IPC_Client::getInstance(false).CopyFile(game_src, icon);
        }
    }
   // shellui_log("CxmlUri_Hook: %s", icon.c_str());
    return mono_string_new(Root_Domain, icon.c_str());
  }
  else if (uri_string.rfind("//usb") != std::string::npos || uri_string.rfind("//data") != std::string::npos || uri_string.rfind("//user//data") != std::string::npos){
    //replace // with//
    std::string new_uri = uri_string;
    size_t pos = 0;
    while (( pos = new_uri.find("//", pos)) != std::string::npos) {
        new_uri.replace(pos, 2, "/");
    }
    #if SHELL_DEBUG==1 
    shellui_log("CxmlUri_Hook: %s", new_uri.c_str());
    #endif
    return mono_string_new(Root_Domain, new_uri.c_str());
  }
  return CxmlUri(Instance, uri);
}
MonoObject* MemoryStream_Instance = nullptr;

uint64_t GetManifestResourceStream_Hook(uint64_t inst, MonoString* FileName) {
    
    std::string new_xml_string;
    std::string resourceName = Mono_to_String(FileName);

#if SHELL_DEBUG==1 
    shellui_log("GetManifestResourceStream_Hook: %s", resourceName.c_str());
#endif

    is_plugin = (resourceName == plugin_xml);
    is_debug_settings = (resourceName == debug_settings_xml);
    is_cheats = (resourceName == cheats_xml);
    is_auto_plugin = (resourceName == "Sce.Vsh.ShellUI.Legacy.src.Sce.Vsh.ShellUI.Settings.Plugins.auto_plugins.xml");
  	is_tk_menu = (resourceName == "Sce.Vsh.ShellUI.Legacy.src.Sce.Vsh.ShellUI.Settings.Plugins.testkit_menu.xml");
    is_hb_loader = (resourceName == "Sce.Vsh.ShellUI.Legacy.src.Sce.Vsh.ShellUI.Settings.Plugins.hb_loader.xml");
    is_plapps = (resourceName == "Sce.Vsh.ShellUI.Legacy.src.Sce.Vsh.ShellUI.Settings.Plugins.plapps.xml");
	is_custom_pkg = (resourceName == "Sce.Vsh.ShellUI.Legacy.src.Sce.Vsh.ShellUI.Settings.Plugins.custompkginstaller.xml");
	is_su_menu = (resourceName == "Sce.Vsh.ShellUI.Legacy.src.Sce.Vsh.ShellUI.Settings.Plugins.superuser.xml");
    
    is_remote_play = (resourceName == remote_play_xml);


    if(cheats_shortcut_activated || cheats_shortcut_activated_not_open){
        is_debug_settings = false;
        is_cheats = true;
    }
    else if(game_shortcut_activated){
        is_debug_settings = false;
        is_hb_loader = true;
    }

    // TEstKIt OG Debug Settings
    if((resourceName == "Sce.Vsh.ShellUI.Legacy.src.Sce.Vsh.ShellUI.Settings.Plugins.og_debug.xml")){
       // shellui_log("Sce.Vsh.ShellUI.Legacy.src.Sce.Vsh.ShellUI.Settings.Plugins.og_debug.xml 111111111");
        return GetManifestResourceStream_Original(inst, mono_string_new(Root_Domain, debug_settings_xml.c_str()));
    }

    if (!is_plugin && !is_debug_settings && !is_cheats && !is_auto_plugin && !is_tk_menu && !is_remote_play && !is_hb_loader && !is_plapps && !is_su_menu && !is_custom_pkg) {
        return GetManifestResourceStream_Original(inst, FileName);
    }


    // Don't try to open the class again if it's already open
    if (!MemoryStream_IO) {
        MonoAssembly* Assembly = mono_domain_assembly_open(Root_Domain, "/system_ex/common_ex/lib/mscorlib.dll");
        MonoImage* mscorelib_image = mono_assembly_get_image(Assembly);
        if (!mscorelib_image) {
            shellui_log("Failed to get mscorelib image");
            return GetManifestResourceStream_Original(inst, FileName);
        }

        MemoryStream_IO = mono_class_from_name(mscorelib_image, "System.IO", "MemoryStream");
        if (!MemoryStream_IO) {
            shellui_log("Failed to open class MemoryStream");
            return GetManifestResourceStream_Original(inst, FileName);
        }
    }

    if (is_debug_settings) {
        LoadSettings();
        new_xml_string = global_conf.lite_mode ? dec_list_xml_str : dec_xml_str;
       // shellui_log("Lite mode is %s", global_conf.lite_mode ? "enabled" : "disabled");
    }
    else if (is_hb_loader){
        if (!games_list.empty()) {
             games_list.clear();
           // shellui_log("games found");
        }
       
        //generate_games_xml(new_xml_string, game_shortcut_activated);
        IPC_Client::getInstance(true).GetGamesList(game_shortcut_activated, new_xml_string);
        game_shortcut_activated = false;
    }
	else if (is_tk_menu) {

        
	     	new_xml_string  = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
            "<system_settings version=\"1.0\" plugin=\"debug_settings_plugin\">\n" 
            "\n<setting_list id=\"id_testkit_menu\" title=\"TestKit Menu\">\n";

		    IPC_Client& main_ipc = IPC_Client::getInstance(false);

        if (main_ipc.IsTestKit()) {
            new_xml_string += R"(<list id="id_kit_panel" title="Console Info overlay" >)";
            new_xml_string += R"(<list_item id="id_kit_panel_1" title="On [Custom]" value="0" />)";
            new_xml_string += R"(<list_item id="id_kit_panel_2" title="On + APU Temp" value="1" />)";
            new_xml_string += R"(<list_item id="id_kit_panel_3" title="On + Service Ports + temps" value="2" />)";
            new_xml_string += R"(<list_item id="id_kit_panel_4" title="Off" value="3" />)";
            new_xml_string += R"( </list>)";

            new_xml_string += R"(<list id="id_trial_soft" title="Trial System Software Expiration overlay" >)";
            new_xml_string += R"(<list_item id="id_trial_soft_off" title="Off" value="0" />)";
            new_xml_string += R"(<list_item id="id_trial_soft_1" title="(ON) 1 Day" value="1" />)";
            new_xml_string += R"(<list_item id="id_trial_soft_2" title="(ON) 2 Days" value="2" />)";
            new_xml_string += R"(<list_item id="id_trial_soft_3" title="(ON) Expired" value="3" />)";
		      	new_xml_string += R"( </list>)";

            new_xml_string += R"( <list id="id_controller_pad_usable_ps4_device" title="Enable Controllers for PS4 in Native Games" key="/DEVENV/TOOL/pad_usable_ps4_device" confirm="You need to restart the system to reflect the setting.&#xa;The system will automatically restart when you leave from ★Debug Settings." confirm_phrase="OK,Cancel">)";
            new_xml_string += R"( <list_item id="id_controller_pad_usable_ps4_device_off" title="Off" value="0"/>)";
            new_xml_string += R"( <list_item id="id_controller_pad_usable_ps4_device_on" title="On" value="1"/>)";
            new_xml_string += R"( </list>)";
            new_xml_string += R"( <link id="id_og_debug" title="Orig. Debug Settings" file="og_debug.xml"/> )";
        }
        else {
			      new_xml_string += R"(<label id="id_testkit_494990" title="★ This Menu is not currently available on retail consoles" style="center"/>)";
        }

		    new_xml_string += "\n</setting_list>\n</system_settings>";
    }
    else if (is_plugin) {
       // shellui_log("Plugins clicked");
        if (!plugins_list.empty()) {
            plugins_list.clear();
            //shellui_log("Plugins found");
        }
        generate_plugin_xml(new_xml_string, true);
       // shellui_log("Plugins XML: %s", new_xml_string.c_str());
    }
    else if (is_custom_pkg) {

        if (!custom_pkg_list.empty()) {
            custom_pkg_list.clear();
            //shellui_log("Custom Pkg Installers found");
        }
        generate_custom_pkg_xml(new_xml_string);
       // shellui_log("Custom Pkg Installers XML: %s", new_xml_string.c_str());
	}
    else if (is_su_menu) {
#if 0
        if (!su_list.empty()) {
            su_list.clear();
            //shellui_log("Superuser apps found");
        }
        generate_su_xml(new_xml_string);
        // shellui_log("Superuser apps XML: %s", new_xml_string.c_str());
#endif
    }
    else if (is_cheats) {
        generate_cheats_xml(new_xml_string, current_menu_tid, (cheats_shortcut_activated || cheats_shortcut_activated_not_open), cheats_shortcut_activated_not_open);
        cheats_shortcut_activated_not_open = cheats_shortcut_activated = false;
    }
	else if (is_auto_plugin) {
        if (!auto_list.empty()) {
            auto_list.clear();
           // shellui_log("Plugins found");
        }
		generate_plugin_xml(new_xml_string, false);
	} 
  else if (is_remote_play) {
        //shellui_log("Generate remote play XML\n");
        generate_remote_play_xml(new_xml_string);   
  }
	else if (is_plapps) {
        //shellui_log("Generate payloads XML\n");
        if (!payloads_apps_list.empty()) {
             payloads_apps_list.clear();
            //shellui_log("Payloads found");
        }
       generate_plapps_xml(new_xml_string);
  }

    MemoryStream_Instance = New_Mono_XML_From_String(new_xml_string);
    if (!MemoryStream_Instance) {
        return GetManifestResourceStream_Original(inst, FileName);
    }

    return (uint64_t)MemoryStream_Instance;
}

extern uint8_t store_png_start[];
extern const unsigned int store_png_size;

extern "C" int sceKernelGetPs4SystemSwVersion(OrbisKernelSwVersion *);

MonoMethod* set_value_method = nullptr;
int OnPreCreate_Hook(MonoObject* Instance, MonoObject* element) {
    bool& FTP = global_conf.FTP;
    bool& Klog = global_conf.Klog;
    bool& DPI = global_conf.DPI;
    bool& DPI_v2 = global_conf.DPI_v2;
    int & kstuff_pause_opt = global_conf.kstuff_pause_opt;
    MonoString* s_MonoText = nullptr;

    char tid[32] = { 0 };
    int cheat_id = 0;

    if (!Instance || !element)
    {
#if SHELL_DEBUG==1
        shellui_log("[LM HOOK] OnPreCreate_Hook: args are null");
#endif
        return oOnPreCreate(Instance, element);
    }

    std::string id = GetPropertyValue(element, "Id");
   // shellui_log("[LM HOOK] OnPreCreate_Hook: Id: %s", id.c_str());

    if (!set_value_method) {
        MonoAssembly* Legacy_assembly = mono_domain_assembly_open(Root_Domain, legacy_dec.c_str());
        if (!Legacy_assembly) {
            shellui_log("Failed to open assembly.");
            return -1;
        }

        // Get the image
        MonoImage* leg_img = mono_assembly_get_image(Legacy_assembly);
        if (!leg_img) {
            shellui_log("Failed to get image.");
            return -1;
        }

        MonoClass* klass = mono_class_from_name(leg_img, UI3_dec.c_str(), "SettingElement");
        if (!klass) {
            sceKernelDebugOutText(0, "Failed to find class\n");
            return -1;
        }

        MonoProperty* s_Property = mono_class_get_property_from_name(klass, "Value");
        if (s_Property == NULL) {
            shellui_log("Failed to find property");
            return -1;
        }

        set_value_method = mono_property_get_set_method(s_Property);
        if (set_value_method == NULL) {
            shellui_log("Failed to find set method");
            return -1;
        }
    }


    if (!plugins_list.empty()) {
        for (auto plugin : plugins_list) {
            if (plugin.id == id) {
                s_MonoText = mono_string_new(Root_Domain, (sceSystemServiceGetAppId(plugin.tid.c_str()) > 0) ? "1" : "0");
            }
        }
    }

    if (!auto_list.empty()) {
        for (auto plugin : auto_list) {
            if (plugin.id == id) {
                std::string auto_path = plugin.shellui_path + ".auto_start";
                s_MonoText = mono_string_new(Root_Domain, if_exists(auto_path.c_str()) ? "1" : "0");
            }
        }
    }
  
    if (id == "id_lm_test") {
        s_MonoText = mono_string_new(Root_Domain, "0");
    }
    else if (id == "id_overlay_gpu") {
		s_MonoText = mono_string_new(Root_Domain, global_conf.overlay_gpu ? "1" : "0");
    }
    else if (id == "id_overlay_fps") {
		s_MonoText = mono_string_new(Root_Domain, global_conf.overlay_fps ? "1" : "0");
    }
	else if (id == "id_overlay_ip") {
        s_MonoText = mono_string_new(Root_Domain, global_conf.overlay_ip ? "1" : "0");
	}
    else if (id == "id_overlay_kstuff") {
        s_MonoText = mono_string_new(Root_Domain, global_conf.overlay_kstuff ? "1" : "0");
    }
    else if (id == "id_all_cpu_usage") {
		s_MonoText = mono_string_new(Root_Domain, global_conf.all_cpu_usage ? "1" : "0");
    }
	else if (id == "id_overlay_cpu") {
        s_MonoText = mono_string_new(Root_Domain, global_conf.overlay_cpu ? "1" : "0");
	}
    else if (id == "id_overlay_ram") {
		s_MonoText = mono_string_new(Root_Domain, global_conf.overlay_ram ? "1" : "0");
    }
    else if (id == "id_kstuff_autoload") {
		s_MonoText = mono_string_new(Root_Domain, !if_exists("/user/data/etaHEN/no_kstuff") ? "1" : "0");
    }
    else if (id == "id_enable_kstuff_on_close") {
        s_MonoText = mono_string_new(Root_Domain, global_conf.enable_kstuff_on_close ? "1" : "0");
    }
    else if (id == "id_pause_kstuff_on_open"){
        s_MonoText = mono_string_new(Root_Domain, global_conf.pause_kstuff_on_open ? "1" : "0");
    }
    else if (id == "id_pause_kstuff_on_open_secs"){
        s_MonoText = mono_string_new(Root_Domain, std::to_string(global_conf.pause_kstuff_on_open_secs).c_str());
    }
    else if (id == "id_disp_titleids"){
        s_MonoText = mono_string_new(Root_Domain, global_conf.display_tids ? "1" : "0");
    }
    else if (id == "id_enable_fan_speed"){
        s_MonoText = mono_string_new(Root_Domain, global_conf.enable_fan_speed ? "1" : "0");
    }
    else if (id == "id_ftp_service") {
        s_MonoText = mono_string_new(Root_Domain, FTP ? "1" : "0");
    }
    else if (id == "id_klog_service") {
        s_MonoText = mono_string_new(Root_Domain, Klog ?  "1" : "0");
    }
    else if (id == "id_dpi_service") {
        s_MonoText = mono_string_new(Root_Domain, DPI ?  "1" : "0");
    }
    else if (id == "id_DPI_v2_service") {
        s_MonoText = mono_string_new(Root_Domain, DPI_v2 ?  "1" : "0");
    }
    else if (id == "id_selected_cheats_repo") {
        s_MonoText = mono_string_new(Root_Domain, global_conf.selected_cheats_repo ? "1" : "0");
    }
    else if (id == "id_start_opt") {
        int opt = global_conf.start_option;
        if (global_conf.launch_itemzflow && !global_conf.start_option) {
            opt = 4;
        }
        s_MonoText = mono_string_new(Root_Domain, std::to_string(opt).c_str());
    }
    else if (id == "id_trial_soft") {
        s_MonoText = mono_string_new(Root_Domain, std::to_string(global_conf.trial_soft_expire_time).c_str());
    }
    else if (id == "id_kit_panel") {
        s_MonoText = mono_string_new(Root_Domain, std::to_string(global_conf.kit_panel_info).c_str());
    }
    else if (id == "id_data_sb") {
        s_MonoText = mono_string_new(Root_Domain, global_conf.allow_data_sandbox ? "1" : "0");
	  }
    else if (id == "id_ftp_dev_access") {
		    s_MonoText = mono_string_new(Root_Domain, global_conf.ftp_dev_access ? "1" : "0");
 	  }
    else if (id == "id_sistro_ps5debug") {
		    s_MonoText = mono_string_new(Root_Domain, global_conf.PS5Debug ? "1" : "0");
	  }
    else if (id == "id_rest_1") {
         s_MonoText = mono_string_new(Root_Domain, std::to_string(global_conf.rest_delay_seconds).c_str());
    }
    else if (id == "id_fan_speed") {
        s_MonoText = mono_string_new(Root_Domain, std::to_string(global_conf.fan_threshold).c_str());
    }
    else if (id == "id_rest_2") {
        s_MonoText = mono_string_new(Root_Domain, global_conf.util_rest_kill ? "1" : "0");
    }
    else if (id == "id_rest_3") {
        s_MonoText = mono_string_new(Root_Domain, global_conf.game_rest_kill ? "1" : "0");
    }
    else if (id == "id_rest_4") {
        s_MonoText = mono_string_new(Root_Domain, global_conf.disable_toolbox_auto_start_for_rest_mode ? "1" : "0");
    }
    else if (id == "id_lite_mode") {
	      s_MonoText = mono_string_new(Root_Domain, global_conf.lite_mode ? "1" : "0");
	  } 
    else if (id == "id_pause_kstuff") {
        s_MonoText = mono_string_new(Root_Domain, std::to_string(kstuff_pause_opt).c_str());
    }
    else if (id.rfind("id_cheat_") != std::string::npos) {
        if(is_current_game_open){
           ParseCheatID(id.c_str(), tid, &cheat_id);
           bool enabled = cheatEnabledMap[cheat_id];
           s_MonoText = mono_string_new(Root_Domain, enabled ? "1" : "0");
        }
    }
    else if (id.rfind("id_toolbox_shortcut") != std::string::npos){
        s_MonoText = mono_string_new(Root_Domain, std::to_string(global_conf.toolbox_shortcut_opt).c_str());
    }
    else if (id == "id_cheats_shortcut") {
        s_MonoText = mono_string_new(Root_Domain, std::to_string(global_conf.cheats_shortcut_opt).c_str());
    }
    else if (id == "id_games_shortcut") {
        s_MonoText = mono_string_new(Root_Domain, std::to_string(global_conf.games_shortcut_opt).c_str());
    }
    else if (id == "id_kstuff_shortcut") {
        s_MonoText = mono_string_new(Root_Domain, std::to_string(global_conf.kstuff_shortcut_opt).c_str());
    }
    else if (id == "id_toolbox_auto_start") {
        s_MonoText = mono_string_new(Root_Domain, global_conf.toolbox_auto_start ? "1" : "0");
    }
    else if (id == "id_debug_jb"){
       s_MonoText = mono_string_new(Root_Domain, global_conf.debug_app_jb_msg ? "1" : "0");
    }
    else if (id == "id_debug_legacy_cmd") {
        s_MonoText = mono_string_new(Root_Domain, global_conf.debug_legacy_cmd_server ? "1" : "0");
    }
    else if (id == "id_custom_game_opts"){
       s_MonoText = mono_string_new(Root_Domain, global_conf.etaHEN_game_opts ? "1" : "0");
    }
    else if (id == "id_auto_eject") {
        s_MonoText = mono_string_new(Root_Domain, global_conf.auto_eject_disc ? "1" : "0");
    }
    else if (id == "id_overlay_change_pos") {
        s_MonoText = mono_string_new(Root_Domain, std::to_string(global_conf.overlay_pos).c_str());
	}

    if(s_MonoText)
       mono_runtime_invoke(set_value_method, element, (void**)&s_MonoText, NULL);

    return oOnPreCreate(Instance, element);
}

void CheckRunningOnMainThread() {
	//notify("Main thread check called!");
}
void Patch_Main_thread_Check(MonoImage * image_core) {

    uint64_t real_addr = Get_Address_of_Method(image_core, "Sce.PlayStation.Core.Runtime", "Diagnostics", "CheckRunningOnMainThread", 0);
    if (!real_addr) {
#if SHELL_DEBUG==1
        shellui_log("Failed to get method address");
#endif
        return;
    }
#if SHELL_DEBUG==1
    shellui_log("changing permissions on (%p).", real_addr);
#endif
    
	DetourFunction(real_addr, (void*)&CheckRunningOnMainThread);
#if SHELL_DEBUG==1
    shellui_log("Main thread check patched\n");
#endif

}
// Common logic function
bool handle_uri_boot_common(MonoString* uri, int opt, MonoString* titleIdForBootAction) {
    std::string uri_string = Mono_to_String(uri);
    std::string titleId = titleIdForBootAction ? Mono_to_String(titleIdForBootAction) : "";
    
#if SHELL_DEBUG==1
    shellui_log("Boot: %s (%s), OPT %i", 
                uri_string.c_str(), 
                !titleId.empty() ? titleId.c_str() : "NULL", 
                opt);
#endif
  
    if(uri_string == "etaHEN?webMAN_Games") {
#if SHELL_DEBUG==1
      shellui_log("webMAN Games URI detected");
#endif
      game_shortcut_activated = true;
      return true; // Signal to redirect
    }
    else if(uri_string == "etaHEN?webMAN_Games_media") {
#if SHELL_DEBUG==1
        shellui_log("webMAN Games URI detected");
#endif
        game_shortcut_activated_media = game_shortcut_activated = true;
        return true; // Signal to redirect
    }
    else if(uri_string == "etaHEN?Cheats") {
#if SHELL_DEBUG==1
      shellui_log("cheats_shortcut URI detected");
#endif
      cheats_shortcut_activated = true;
      return true; // Signal to redirect
    }
    else if(uri_string == "etaHEN?Cheats_not_open") {
#if SHELL_DEBUG==1
      shellui_log("cheats_shortcut (not open) URI detected");
#endif
      cheats_shortcut_activated_not_open = true;
      return true;
    }
    else if (uri_string == "etaHEN?Dump") {
#if SHELL_DEBUG==1
        shellui_log("Dump URI detected");
#endif
        IPC_Client::getInstance(false).Launch_Dumper();
        return true; // Signal to redirect
    }
    else if (uri_string == "etaHEN?DL_UPDATE") {
#if SHELL_DEBUG==1
        shellui_log("DL_UPDATE URI detected");
#endif
        
        return true; // Signal to redirect
    }

    return false; // No redirect needed
  }
  
  bool uri_boot_hook(MonoString* uri, int opt, MonoString* titleIdForBootAction) {
    if(handle_uri_boot_common(uri, opt, titleIdForBootAction)) {
        if(global_conf.lite_mode) {
            // In lite mode, we don't want to handle any shortcuts
            notify("Lite mode is enabled, shortcuts are disabled");
            return boot_orig(uri, opt, titleIdForBootAction);
        }

        std::string uri_string = Mono_to_String(uri);
        if(uri_string == "etaHEN?Dump") {
          return boot_orig(mono_string_new(Root_Domain, "pshomeui:navigateToHome?bootCondition=psButton"),  opt, titleIdForBootAction);
        }
      // Redirect to debug settings
      return boot_orig(mono_string_new(Root_Domain, "pssettings:play?mode=settings&function=debug_settings"), opt, titleIdForBootAction);
    }
    
    return boot_orig(uri, opt, titleIdForBootAction);
  }
  
  bool uri_boot_hook_2(MonoString* uri, int opt) {
  #if SHELL_DEBUG==1
    shellui_log("uri_boot_hook_2: %s, opt: %i", Mono_to_String(uri).c_str(), opt);
  #endif
    if(handle_uri_boot_common(uri, opt, nullptr)) {
      // Redirect to debug settings (no titleId parameter for older fw)
      if(global_conf.lite_mode) {
        // In lite mode, we don't want to handle any shortcuts
        notify("Lite mode is enabled, shortcuts are disabled");
        return boot_orig_2(uri, opt);
      }

      std::string uri_string = Mono_to_String(uri);
      if(uri_string == "etaHEN?Dump") {
        return boot_orig_2(mono_string_new(Root_Domain, "pshomeui:navigateToHome?bootCondition=psButton"),  opt);
      }

      return boot_orig_2(mono_string_new(Root_Domain, "pssettings:play?function=debug_settings"),  opt);
    }
    
    return boot_orig_2(uri, opt);
  }

  GamePadData GetData_hook(int deviceIndex) {
    GamePadData result;
    bool cheas_sc_activated = false;
    bool game_sc_activated = false;
    bool kstuff_sc_activated = false;
    bool toolbox_sc_activated = false;
  
    const std::chrono::milliseconds LONG_PRESS_DURATION(1000); // 1 second
  
    // Static variables for Cheats shortcut hold detection
    static bool cheats_pressed = false;
    static std::chrono::steady_clock::time_point cheats_press_start;
    static bool cheats_long_press_triggered = false;
  
    // Static variables for Games shortcut hold detection
    static bool games_pressed = false;
    static std::chrono::steady_clock::time_point games_press_start;
    static bool games_long_press_triggered = false;
  
    // Static variables for Kstuff shortcut hold detection
    static bool kstuff_pressed = false;
    static std::chrono::steady_clock::time_point kstuff_press_start;
    static bool kstuff_long_press_triggered = false;
  
    // Static variables for Toolbox shortcut hold detection
    static bool toolbox_pressed = false;
    static std::chrono::steady_clock::time_point toolbox_press_start;
    static bool toolbox_long_press_triggered = false;

  
    result = GetData(deviceIndex);

    // Cheats Shortcut
    if (global_conf.cheats_shortcut_opt != CHEATS_SC_OFF) {
      bool cheats_buttons_held = false;
  
      switch (global_conf.cheats_shortcut_opt) {
      case R3_L3:
        cheats_buttons_held = (result.Buttons & R3) && (result.Buttons & L3);
        break;
      case L2_TRIANGLE:
        cheats_buttons_held = (result.Buttons & L2) && (result.Buttons & Triangle);
        break;
      case LONG_OPTIONS:
        cheats_buttons_held = (result.Buttons & Option);
        break;
      default:
        break;
      }
  
      if (cheats_buttons_held) {
        if (!cheats_pressed) {
          cheats_pressed = true;
          cheats_press_start = std::chrono::steady_clock::now();
          cheats_long_press_triggered = false;
          #if SHELL_DEBUG == 1
          shellui_log("Cheats buttons pressed - starting timer");
          #endif
        } else {
          auto current_time = std::chrono::steady_clock::now();
          auto hold_duration = std::chrono::duration_cast < std::chrono::milliseconds > (
            current_time - cheats_press_start
          );
  
          // Log every 500ms to track progress
          static auto last_log_time = std::chrono::steady_clock::now();
          if (std::chrono::duration_cast < std::chrono::milliseconds > (
              current_time - last_log_time) >= std::chrono::milliseconds(500)) {
              #if SHELL_DEBUG == 1
              shellui_log("Cheats buttons held for %lld ms (need %lld ms)",
              hold_duration.count(),
              LONG_PRESS_DURATION.count());
              #endif
            last_log_time = current_time;
          }
  
          if (hold_duration >= LONG_PRESS_DURATION && !cheats_long_press_triggered) {
            #if SHELL_DEBUG == 1
            shellui_log("Cheats long press threshold reached! Duration: %lld ms",
              hold_duration.count());
            #endif
            cheas_sc_activated = true;
            cheats_long_press_triggered = true;
          }
        }
      } else {
        if (cheats_pressed) {
          #if SHELL_DEBUG == 1
          auto current_time = std::chrono::steady_clock::now();
          auto hold_duration = std::chrono::duration_cast < std::chrono::milliseconds > (
            current_time - cheats_press_start
          );
          shellui_log("Cheats buttons released after %lld ms (needed %lld ms)",
            hold_duration.count(),
            LONG_PRESS_DURATION.count());
          #endif
        }
        cheats_pressed = false;
        cheats_long_press_triggered = false;
      }
  
      if (cheas_sc_activated) {
#if SHELL_DEBUG == 1
        shellui_log("Cheats Shortcut Activated");
#endif
        GoToURI("etaHEN?Cheats");
        result.Buttons = None; // Clear the Select button to prevent triggering other actions
        cheas_sc_activated = false; // Reset the flag
      }
    }
  
    // Games Shortcut
    if (global_conf.games_shortcut_opt != GAMES_SC_OFF) {
      bool games_buttons_held = false;
  
      switch (global_conf.games_shortcut_opt) {
      case R1_L1:
        games_buttons_held = (result.Buttons & R1) && (result.Buttons & L1);
        break;
      case L2_O:
        games_buttons_held = (result.Buttons & L2) && (result.Buttons & Circle);
        break;
      default:
        break;
      }
  
      if (games_buttons_held) {
        if (!games_pressed) {
          games_pressed = true;
          games_press_start = std::chrono::steady_clock::now();
          games_long_press_triggered = false;
        } else {
          auto current_time = std::chrono::steady_clock::now();
          auto hold_duration = std::chrono::duration_cast < std::chrono::milliseconds > (
            current_time - games_press_start
          );
  
          if (hold_duration >= LONG_PRESS_DURATION && !games_long_press_triggered) {
            game_sc_activated = true;
            games_long_press_triggered = true;
          }
        }
      } else {
        games_pressed = false;
        games_long_press_triggered = false;
      }
  
      if (game_sc_activated) {
#if SHELL_DEBUG == 1
        shellui_log("Games Shortcut Activated");
#endif
        GoToURI("etaHEN?webMAN_Games");
        result.Buttons = None; // Clear the Select button to prevent triggering other actions
      }
    }
  
    // Kstuff Shortcut
    if (global_conf.kstuff_shortcut_opt != KSTUFF_SC_OFF) {
      bool kstuff_buttons_held = false;
  
      switch (global_conf.kstuff_shortcut_opt) {
      case R2_L2:
        kstuff_buttons_held = (result.Buttons & R2) && (result.Buttons & L2);
        break;
      case L2_SQUARE:
        kstuff_buttons_held = (result.Buttons & L2) && (result.Buttons & Square);
        break;
      default:
        break;
      }
  
      if (kstuff_buttons_held) {
        if (!kstuff_pressed) {
          kstuff_pressed = true;
          kstuff_press_start = std::chrono::steady_clock::now();
          kstuff_long_press_triggered = false;
        } else {
          auto current_time = std::chrono::steady_clock::now();
          auto hold_duration = std::chrono::duration_cast < std::chrono::milliseconds > (
            current_time - kstuff_press_start
          );
  
          if (hold_duration >= LONG_PRESS_DURATION && !kstuff_long_press_triggered) {
            kstuff_sc_activated = true;
            kstuff_long_press_triggered = true;
          }
        }
      } else {
        kstuff_pressed = false;
        kstuff_long_press_triggered = false;
      }
  
      if (kstuff_sc_activated) {
        //  shellui_log("Kstuff Shortcut Activated");
        if(if_exists("/user/data/etaHEN/no_kstuff") || if_exists("/usb0/etaHEN/no_kstuff")){
            notify("Kstuff auto-start is disabled, shortcut unable to continue...");
            return result;
		}
        pause_resume_kstuff(((global_conf.kstuff_pause_opt != NOT_PAUSED) ? NOT_PAUSED : BOTH_PAUSED), true);
        result.Buttons = None; // Clear the Select button to prevent triggering other actions
        //shellui_log("kstuff_pause_opt %d, %s", global_conf.kstuff_pause_opt, global_conf.kstuff_pause_opt != NOT_PAUSED ? "Resuming kstuff" : "Pausing kstuff");
      }
    }
  
    // Toolbox Shortcut
    if (global_conf.toolbox_shortcut_opt != TOOLBOX_SC_OFF) {
      bool toolbox_buttons_held = false;
  
      switch (global_conf.toolbox_shortcut_opt) {
      case L2_R3:
        toolbox_buttons_held = (result.Buttons & L2) && (result.Buttons & R3);
        break;
      default:
        break;
      }
  
      if (toolbox_buttons_held) {
        if (!toolbox_pressed) {
          toolbox_pressed = true;
          toolbox_press_start = std::chrono::steady_clock::now();
          toolbox_long_press_triggered = false;
        } else {
          auto current_time = std::chrono::steady_clock::now();
          auto hold_duration = std::chrono::duration_cast < std::chrono::milliseconds > (
            current_time - toolbox_press_start
          );
  
          if (hold_duration >= LONG_PRESS_DURATION && !toolbox_long_press_triggered) {
            toolbox_sc_activated = true;
            toolbox_long_press_triggered = true;
          }
        }
      } else {
        toolbox_pressed = false;
        toolbox_long_press_triggered = false;
      }
  
      if (toolbox_sc_activated) {
#if SHELL_DEBUG == 1
        shellui_log("Toolbox Shortcut Activated");
#endif
        GoToURI("pssettings:play?mode=settings&function=debug_settings");
        result.Buttons = None; // Clear the Select button to prevent triggering other actions
      }
    }
  
#if SHELL_DEBUG==1
    if (result.Buttons & Option) {
      shellui_log("Option button pressed");
    }
#endif
  
    return result;
  }

bool CaptureScreen(){
   
  if (global_conf.lite_mode) {
    return false;
  }

  if(global_conf.cheats_shortcut_opt == CHEATS_LONG_SHARE){
    //shellui_log("CaptureScreen: Long Share Shortcut activated");
    GoToURI("etaHEN?Cheats");
    return true;
  }
  else if (global_conf.games_shortcut_opt == GAMES_LONG_SHARE){
    //shellui_log("CaptureScreen: Long Share Shortcut activated");
    GoToURI("etaHEN?webMAN_Games");
    return true;
  }
  else if (global_conf.kstuff_shortcut_opt == KSTUFF_LONG_SHARE){
    //shellui_log("CaptureScreen: Long Share Shortcut activated");
    pause_resume_kstuff(((global_conf.kstuff_pause_opt != NOT_PAUSED) ? NOT_PAUSED : BOTH_PAUSED), true);
    return true;
  }
  else if (global_conf.toolbox_shortcut_opt == TOOLBOX_LONG_SHARE){
    //shellui_log("CaptureScreen: Long Share Shortcut activated");
    GoToURI("pssettings:play?mode=settings&function=debug_settings");
    return true;
  }

  return false;
}
void CaptureScreen_old(MonoObject *inst, int userId, long deviceId, int capType, MonoObject* capInfo){
#if SHELL_DEBUG == 1
  shellui_log("CaptureScreen: userId: %d, deviceId: %ld, capType: %d", userId, deviceId, capType);
#endif

  if(CaptureScreen()){
#if SHELL_DEBUG == 1
    shellui_log("CaptureScreen: Shortcut activated, redirecting");
#endif
    return;
  }
  CaptureScreen_orig_old(inst, userId, deviceId, capType, capInfo);

}

void CaptureScreen_new(MonoObject * inst, int userId, long deviceId, int capType, MonoString* format, MonoObject* capInfo) {
#if SHELL_DEBUG == 1
  shellui_log("CaptureScreen_new: userId: %d, deviceId: %ld, capType: %d", userId, deviceId, capType);
#endif
  if(CaptureScreen()){
#if SHELL_DEBUG == 1
    shellui_log("CaptureScreen_new: Shortcut activated, redirecting");
#endif
    return;
  }
  CaptureScreen_orig_new(inst, userId, deviceId, capType, format, capInfo);
}

void OnShareButton(MonoObject * data) {
#if SHELL_DEBUG == 1
  shellui_log("OnShareButton: data: %p", data);
#endif

  if (global_conf.lite_mode) {
    OnShareButton_orig(data);
    return;
  }

  if( global_conf.cheats_shortcut_opt == CHEATS_SINGLE_SHARE) {
    // shellui_log("Share Shortcut: Redirecting to Cheats");
    GoToURI("etaHEN?Cheats");
    return;
  }
  else if (global_conf.games_shortcut_opt == GAMES_SINGLE_SHARE) {
    // shellui_log("Share Shortcut: Redirecting to Games");
    GoToURI("etaHEN?webMAN_Games");
    return;
  }
  else if (global_conf.kstuff_shortcut_opt == KSTUFF_SINGLE_SHARE) {
    // shellui_log("Share Shortcut: Pausing Kstuff");
    pause_resume_kstuff(((global_conf.kstuff_pause_opt != NOT_PAUSED) ? NOT_PAUSED : BOTH_PAUSED), true);
    //shellui_log("kstuff_pause_opt %d, %s", global_conf.kstuff_pause_opt, global_conf.kstuff_pause_opt != NOT_PAUSED ? "Resuming kstuff" : "Pausing kstuff");
    return;
  }
  else if (global_conf.toolbox_shortcut_opt == TOOLBOX_SINGLE_SHARE) {
    // shellui_log("Share Shortcut: Redirecting to Toolbox");
    GoToURI("pssettings:play?mode=settings&function=debug_settings");
    return;
  }

  OnShareButton_orig(data);
}

void save_appid(int value, const char* filename) {
    std::ofstream file(filename);
    file << value;
}
bool app_launched = false;
int LaunchApp(MonoString* titleId, uint64_t* args, int argsSize, LaunchAppParam *param){
#if 1
   if(!if_exists("/system_tmp/patch_plugin")) {
      #if SHELL_DEBUG == 1
      shellui_log("patch plugin not running .. returning with orig");
      #endif
	  unsigned int ret = LaunchApp_orig(titleId, args, argsSize, param);
      if (ret < 0) {
         #if SHELL_DEBUG == 1
         notify("LaunchApp failed with error code: %d", ret);
         #endif
         return ret;
      }

      app_launched = true;
      if(global_conf.pause_kstuff_on_open && Mono_to_String(titleId) != "ITEM00001" && Mono_to_String(titleId).rfind("NPXS") == std::string::npos){
         pthread_t thread;
         shellui_log("Pausing Kstuff on app launch for %s in %d seconds", mono_string_to_utf8(titleId), global_conf.pause_kstuff_on_open_secs);
         pthread_create(&thread, nullptr, kstuff_pause_thread, nullptr);
      }

      return ret;

   }
#endif
#if SHELL_DEBUG == 1
  shellui_log("LaunchApp called with titleId: %s, argsSize: %d, param->size: %d", mono_string_to_utf8(titleId), argsSize, param->size);
#endif
  notify("Launching app: %s checking for patches ...", mono_string_to_utf8(titleId));

  unsigned int ret = LaunchApp_orig(titleId, args, argsSize, param);
  if (ret < 0) {
    #if SHELL_DEBUG == 1
    notify("LaunchApp failed with error code: %d", ret);
    #endif
    return ret;
  }

  app_launched = true;
  if(global_conf.pause_kstuff_on_open && Mono_to_String(titleId) != "ITEM00001" && Mono_to_String(titleId).rfind("NPXS") == std::string::npos){
    pthread_t thread;
     shellui_log("Pausing Kstuff on app launch for %s in %d seconds", mono_string_to_utf8(titleId), global_conf.pause_kstuff_on_open_secs);
    pthread_create(&thread, nullptr, kstuff_pause_thread, nullptr);
  }

 #if SHELL_DEBUG == 1
  notify("LaunchApp returned: %d", ret);
  #endif

  save_appid(ret, "/system_tmp/app_launched");
  return ret;

}

int sceRegMgrGetInt_hook(long regid, int* out_val){
  bool dis_tids = global_conf.display_tids;

  if(dis_tids && regid == SCE_REGMGR_ENT_KEY_DEVENV_TOOL_SHELLUI_disp_titleid){
    if (out_val) {
       *out_val = 1;
    }
#if SHELL_DEBUG==1
    shellui_log("RegMGR lookup called for SHELLUI_disp_titleid, spoofing out_var to 1");
#endif
    return 0;
  }

  #define visualize_fps_range 2013460994
  #define visualize_fps_en 2013460993
  #define visualize_fps_pos 2013460995
  #define visualize_fps_port 2013460996
  static int (*crash)() = nullptr;

  if(regid == visualize_fps_range) {
      crash();
    shellui_log("visualize_fps_range regid %lx", regid);
    if (out_val) {
      *out_val = 2;
    }
    return 0;
  }
  else if(regid == visualize_fps_en) {

	  crash();
    shellui_log("visualize_fps_en regid %lx", regid); 
    if (out_val) {
      *out_val = 3;
    }
    return 0;
  }
  else if(regid == visualize_fps_pos) {
      crash();
    shellui_log("visualize_fps_pos regid %lx", regid);
    if (out_val) {
      *out_val = 1;
    }
    return 0;
  }
  else if(regid == visualize_fps_port) {
      crash();
    shellui_log("visualize_fps_port regid %lx", regid);
    if (out_val) {
      *out_val = 0;
    }

    return 0;
  }

  //shellui_log("sceRegMgrGetInt_hook: regid %lx", regid);

  int ret = 0;
  if(__sys_regmgr_call(2, regid, &ret, out_val, SCE_REGMGR_INT_SIZE)){
#if SHELL_DEBUG==1
    shellui_log("sceRegMgrGetInt_hook: Failed to get regid 0x%lx, ret %d", regid, ret);
#endif
    ret = SCE_REGMGR_ERROR_PRM_REGID;
  }

  return ret;
}
static std::string extractTIDFromURI(const std::string& url) {
    const std::string prefix = "titleId=";
    size_t pos = url.find(prefix);
    
    if (pos != std::string::npos) {
        pos += prefix.length();
        size_t end = url.find('&', pos);
        if (end == std::string::npos) {
            return url.substr(pos);
        } else {
            return url.substr(pos, end - pos);
        }
    }
    return std::string(); // Not found
}

void createJson_hook(MonoObject* inst, MonoObject* array, MonoString* id, MonoString* label, MonoString* actionUrl, MonoString* actionId, MonoString* messageId, MonoObject* subMenu, bool enable) {

    std::string id_str = Mono_to_String(id);

#if SHELL_DEBUG==1
    shellui_log("createJson_hook: %lx id: %s, label: %s, actionUrl: %s, actionId: %s, messageId: %s", 
               inst, id_str.c_str(), 
               Mono_to_String(label).c_str(), 
               Mono_to_String(actionUrl).c_str(), 
               Mono_to_String(actionId).c_str(), 
               Mono_to_String(messageId).c_str());
#endif

    if(global_conf.lite_mode || !global_conf.etaHEN_game_opts) {
        createJson(inst, array, id, label, actionUrl, actionId, messageId, subMenu, enable);
        return;
    }

    // Only extract and update titleId if one is found in the current URL
    std::string extracted_tid = extractTIDFromURI(Mono_to_String(actionUrl));
    if (!extracted_tid.empty() && extracted_tid != current_menu_tid) {
        current_menu_tid = extracted_tid;
#if SHELL_DEBUG==1
        //notify("Current menu titleId: %s", current_menu_tid.c_str());
        shellui_log("Updated menu titleId: %s", current_menu_tid.c_str());
#endif
    }
#if 1
    if(id_str == "MENU_ID_SAVE_DATA_MANAGEMENT_PS4_MANUAL" || id_str == "MENU_ID_SAVE_DATA_MANAGEMENT_PS5_MANUAL" || (id_str == "MENU_ID_UPDATE_HISTORY" && 0)){
       createJson(inst, array, mono_string_new(Root_Domain, "MENU_ID_CUST_UPDATES"), mono_string_new(Root_Domain, "★ (Beta) Dump Game/App"), mono_string_new(Root_Domain, "etaHEN?Dump"), actionId, nullptr, subMenu, enable);
       return;
    }
#endif
    if(id_str == "MENU_ID_CHECK_PATCH"){  
      //createJson_hook: 8815fec90 id: MENU_ID_CHECK_PATCH, label: , actionUrl: pspatchcheck:check-for-update?titleid=CUSA01127, actionId: , messageId: msgid_check_update
        createJson(inst, array, mono_string_new(Root_Domain, "MENU_ID_CHEATS"), mono_string_new(Root_Domain, "★ etaHEN Cheats"), mono_string_new(Root_Domain, "etaHEN?Cheats_not_open"), actionId, nullptr, subMenu, enable);
        return;
    }

    if(id_str == "MENU_ID_INTELLECTUAL_PROPERTY_NOTICES"){
        std::string uri = "psappinst:pat-uninstall?titleid=" + current_menu_tid;
        createJson(inst, array, mono_string_new(Root_Domain, "MENU_ID_REMOVE_UPDATE"), mono_string_new(Root_Domain, "★ Delete"), mono_string_new(Root_Domain, uri.c_str()), actionId, nullptr, subMenu, enable);
        return;
    }

    createJson(inst, array, id, label, actionUrl, actionId, messageId, subMenu, enable);
}

void Terminate() {
    shellui_log("******************************\nShellUI is exiting\n*****************************");
    shellui_log("Sending Action");
    IPC_Client& main_ipc = IPC_Client::getInstance(false);
    if(global_conf.game_rest_kill) {
	    	shellui_log("Killing Game");
        int pid = find_pid("NA", false, true);
        if(pid > 0)
           main_ipc.ForceKillPID(pid);
    }
    //dont send the command if the util is already dead
    if(global_conf.util_rest_kill) {
        shellui_log("Killing Util");
        KillAllWithName("Utility", SIGKILL);
    }
    else {
        IPC_Client& ipc = IPC_Client::getInstance(true);
        ipc.SendRestModeAction();
    }
    pause_resume_kstuff(NOT_PAUSED, true);
    oTerminate();
}