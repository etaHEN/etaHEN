
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

#include "Detour.h"
#include "HookedFuncs.hpp"
#include "defs.h"
#include "external_symbols.hpp"
#include "ipc.hpp"
#include "proc.h"
#include "ps5/kernel.h"
#include "ucred.h"
#include <cstdint>
#include <iostream>


#include <unistd.h>
#include <util.hpp>

std::string dec_xml_str;
std::string dec_list_xml_str;
std::string UI3_dec;
std::string legacy_dec;
std::string appsystem_dll;
std::string uilib;
std::string Sysinfo;
std::string display_info;
std::string uilib_dll;

std::string plugin_xml;
std::string remote_play_xml;
std::string debug_settings_xml;
std::string cheats_xml;

MonoImage * react_common_img = nullptr;

bool hooked = false;
bool has_hv_bypess = false;
bool is_testkit = false;

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

void (*Orig_ReloadApp)(MonoString *str) = nullptr;

void ReloadApp(MonoString *str){
     std::string tid = mono_string_to_utf8(str);
     shellui_log("Reloading %s scenes", tid.c_str());
     notify("Reloading %s scenes", tid.c_str());
     Orig_ReloadApp(str);
}

int main(int argc, char const *argv[]) {
  OrbisKernelSwVersion sw;
  char buz[100];
  if (hooked) {
    return 0;
  }

  pid_t pid = getpid();
  uintptr_t old_authid = set_ucred_to_debugger();
  

  int libkernelsys_handle = get_module_handle(pid, "libkernel_sys.sprx");

  KERNEL_DLSYM(libkernelsys_handle, sceKernelDebugOutText);
  KERNEL_DLSYM(libkernelsys_handle, sceKernelMkdir);
  KERNEL_DLSYM(libkernelsys_handle, scePthreadCreate);
  KERNEL_DLSYM(libkernelsys_handle, sceKernelMprotect);
  KERNEL_DLSYM(libkernelsys_handle, sceKernelSendNotificationRequest);
  KERNEL_DLSYM(libkernelsys_handle, sceKernelGetProsperoSystemSwVersion);
  KERNEL_DLSYM(libkernelsys_handle, sceKernelGetAppInfo);
  KERNEL_DLSYM(libkernelsys_handle, sceKernelGetProcessName);

  shellui_log("Starting ShellUI Module ....");
  // int native_handle = get_module_handle(pid, "libNativeExtensions.sprx");
  //KERNEL_DLSYM(native_handle, DecryptRnpsBundle);
  
  // KERNEL_DLSYM(libSceKernelHandle, sceKernelGetSocSensorTemperature);
  //
  //  JIT
  //
  KERNEL_DLSYM(libSceKernelHandle, sceKernelJitCreateSharedMemory);
  KERNEL_DLSYM(libSceKernelHandle, sceKernelJitCreateAliasOfSharedMemory);
  KERNEL_DLSYM(libSceKernelHandle, sceKernelJitMapSharedMemory);
  KERNEL_DLSYM(libSceKernelHandle, ioctl);
  KERNEL_DLSYM(libSceKernelHandle, __sys_regmgr_call);

  // get the yscall address for the ioctl hook
  static __attribute__ ((used)) long getpid = 0;
  KERNEL_DLSYM(libSceKernelHandle, getpid);
  ptr_syscall = getpid;
  ptr_syscall += 0xa; // jump directly to the syscall instruction

  //
  // Mono is already loaded into the SceShellUI process
  //
  int libmono_handle = get_module_handle(pid, "libmonosgen-2.0.sprx");

  KERNEL_DLSYM(libmono_handle, mono_object_to_string);
  KERNEL_DLSYM(libmono_handle, mono_get_root_domain);
  KERNEL_DLSYM(libmono_handle, mono_property_get_get_method);
  KERNEL_DLSYM(libmono_handle, mono_property_get_set_method);
  KERNEL_DLSYM(libmono_handle, mono_class_get_property_from_name);
  KERNEL_DLSYM(libmono_handle, mono_class_from_name);
  KERNEL_DLSYM(libmono_handle, mono_raise_exception);
  KERNEL_DLSYM(libmono_handle, mono_runtime_invoke);
  KERNEL_DLSYM(libmono_handle, mono_array_new);
  KERNEL_DLSYM(libmono_handle, mono_string_new);
  KERNEL_DLSYM(libmono_handle, mono_jit_set_aot_only);
  KERNEL_DLSYM(libmono_handle, mono_jit_init_version);
  KERNEL_DLSYM(libmono_handle, mono_object_new);
  KERNEL_DLSYM(libmono_handle, mono_object_unbox);
  KERNEL_DLSYM(libmono_handle, mono_set_dirs);
  KERNEL_DLSYM(libmono_handle, mono_compile_method);
  KERNEL_DLSYM(libmono_handle, mono_assembly_get_image);
  KERNEL_DLSYM(libmono_handle, mono_domain_assembly_open);
  KERNEL_DLSYM(libmono_handle, mono_get_byte_class);
  KERNEL_DLSYM(libmono_handle, mono_thread_attach);
  KERNEL_DLSYM(libmono_handle, mono_object_get_class);
  KERNEL_DLSYM(libmono_handle, mono_vtable_get_static_field_data);
  KERNEL_DLSYM(libmono_handle, mono_class_get_method_from_name);
  KERNEL_DLSYM(libmono_handle, mono_class_get_field_from_name);
  KERNEL_DLSYM(libmono_handle, mono_aot_get_method);
  KERNEL_DLSYM(libmono_handle, mono_field_static_set_value);
  KERNEL_DLSYM(libmono_handle, mono_assembly_setrootdir);
  KERNEL_DLSYM(libmono_handle, mono_free);
  KERNEL_DLSYM(libmono_handle, mono_gchandle_new);
  KERNEL_DLSYM(libmono_handle, mono_image_open_from_data);
  KERNEL_DLSYM(libmono_handle, mono_runtime_object_init);
  KERNEL_DLSYM(libmono_handle, mono_domain_get);
  KERNEL_DLSYM(libmono_handle, mono_assembly_load_from);
  KERNEL_DLSYM(libmono_handle, mono_method_desc_new);
  KERNEL_DLSYM(libmono_handle, mono_method_desc_search_in_class);
  KERNEL_DLSYM(libmono_handle, mono_method_desc_free);
  KERNEL_DLSYM(libmono_handle, mono_object_new_specific);
  KERNEL_DLSYM(libmono_handle, mono_thread_detach);
  KERNEL_DLSYM(libmono_handle, mono_array_addr_with_size);
  KERNEL_DLSYM(libmono_handle, mono_thread_current);
  KERNEL_DLSYM(libmono_handle, mono_class_vtable);
  KERNEL_DLSYM(libmono_handle, mono_domain_unload);
  KERNEL_DLSYM(libmono_handle, mono_string_to_utf8);

  if (!mono_object_to_string || !mono_get_root_domain ||
      !mono_property_get_get_method || !mono_property_get_set_method ||
      !mono_class_get_property_from_name || !mono_class_from_name ||
      !mono_runtime_invoke || !mono_array_new || !mono_string_new ||
      !mono_jit_set_aot_only || !mono_jit_init_version || !mono_object_new ||
      !mono_object_unbox || !mono_set_dirs || !mono_compile_method ||
      !mono_assembly_get_image || !mono_domain_assembly_open ||
      !mono_get_byte_class || !mono_thread_attach || !mono_object_get_class ||
      !mono_vtable_get_static_field_data || !mono_class_get_method_from_name ||
      !mono_class_get_field_from_name || !mono_aot_get_method ||
      !mono_field_static_set_value || !mono_assembly_setrootdir || !mono_free ||
      !mono_gchandle_new || !mono_image_open_from_data ||
      !mono_runtime_object_init || !mono_domain_get ||
      !mono_assembly_load_from || !mono_method_desc_new ||
      !mono_method_desc_search_in_class || !mono_method_desc_free ||
      !mono_object_new_specific || !mono_thread_detach ||
      !mono_array_addr_with_size || !mono_thread_current ||
      !mono_class_vtable || !mono_domain_unload || !mono_string_to_utf8) {
    shellui_log("Failed to resolve mono symbols");
    return -1;
  }

  int libscesystem_service_handle =
      get_module_handle(pid, "libSceSystemService.sprx");

  KERNEL_DLSYM(libscesystem_service_handle,
               sceSystemServiceGetAppIdOfRunningBigApp);
  KERNEL_DLSYM(libscesystem_service_handle, sceSystemServiceGetAppTitleId);


  void *sceSystemServiceLaunchApp = nullptr;
  KERNEL_DLSYM(libscesystem_service_handle, sceSystemServiceLaunchApp);
  if (!sceSystemServiceLaunchApp) {
    shellui_log("Failed to resolve sceSystemServiceLaunchApp");
  }

  int libRemotePlay_handle = get_module_handle(pid, "libSceRemoteplay.sprx");

  KERNEL_DLSYM(libRemotePlay_handle, sceRemoteplayNotifyPinCodeError);
  KERNEL_DLSYM(libRemotePlay_handle, sceRemoteplayInitialize);
  KERNEL_DLSYM(libRemotePlay_handle, sceRemoteplayGeneratePinCode);
  KERNEL_DLSYM(libRemotePlay_handle, sceRemoteplayConfirmDeviceRegist);

  
  int libReg_handle = get_module_handle(pid, "libSceRegMgr.sprx");
  KERNEL_DLSYM(libReg_handle, sceRegMgrGetInt);

  /*
  "Sce.Vsh.UILib", "SystemSoftwareVersionInfo");
  */
  std::string SettingsPage_dec = base64_decode("U2V0dGluZ1BhZ2U=");
  std::string SettingsPlugin_dec = base64_decode("U2V0dGluZ3NQbHVnaW4=");
  std::string cxml_dec = base64_decode("Q3htbFVyaQ==");
  std::string GetManifestResourceStream_dec = base64_decode("R2V0TWFuaWZlc3RSZXNvdXJjZVN0cmVhbQ==");
  std::string RuntimeAssembly_dec = base64_decode("UnVudGltZUFzc2VtYmx5");
  std::string sys_reflection_dec = base64_decode("U3lzdGVtLlJlZmxlY3Rpb24==");
  std::string key_base64 = "U0lTVFIwX0lfU0VFX1lPVQ==";
  legacy_dec = base64_decode("U2NlLlZzaC5TaGVsbFVJLkxlZ2FjeS5kbGw=");
  UI3_dec = base64_decode("U2NlLlZzaC5TaGVsbFVJLlNldHRpbmdzLkNvcmVVSTM=");
  plugin_xml = base64_decode("U2NlLlZzaC5TaGVsbFVJLkxlZ2FjeS5zcmMuU2NlLlZzaC5Ta"
                             "GVsbFVJLlNldHRpbmdzLlBsdWdpbnMucGx1Z2lucy54bWw=");
  cheats_xml = base64_decode("U2NlLlZzaC5TaGVsbFVJLkxlZ2FjeS5zcmMuU2NlLlZzaC5Ta"
                             "GVsbFVJLlNldHRpbmdzLlBsdWdpbnMuY2hlYXRzLnhtbA==");
  remote_play_xml =  base64_decode("U2NlLlZzaC5TaGVsbFVJLkxlZ2FjeS5zcmMuU2NlLlZzaC5TaGVsbFVJLlNldHRpbmdzLlBsdWdpbnMucmVtb3RlX3BsYXkueG1s");
  debug_settings_xml = base64_decode(
      "U2NlLlZzaC5TaGVsbFVJLkxlZ2FjeS5zcmMuU2NlLlZzaC5TaGVsbFVJLlNldHRpbmdzLlBs"
      "dWdpbnMuRGVidWdTZXR0aW5ncy5kYXRhLmRlYnVnX3NldHRpbmdzLnhtbA==");
  appsystem_dll = base64_decode("U2NlLlZzaC5TaGVsbFVJLkFwcFN5c3RlbS5kbGw=");
  uilib = base64_decode("U2NlLlZzaC5VSUxpYg==");
  Sysinfo = base64_decode("U3lzdGVtU29mdHdhcmVWZXJzaW9uSW5mbw==");
  display_info = base64_decode("c2V0X0Rpc3BsYXlWZXJzaW9u");
  uilib_dll = base64_decode("L3N5c3RlbV9leC9jb21tb25fZXgvbGliL1NjZS5Wc2guVUlMaWIuZGxs");

  // Base64 decoded strings
  std::string mscorlib_dll = base64_decode("bXNjb3JsaWIuZGxs"); // "mscorlib.dll"
  std::string reactpui_dll = base64_decode("UmVhY3ROYXRpdmUuUFVJLmRsbA=="); // "ReactNative.PUI.dll"
  std::string appsystem_dll_name = base64_decode("U2NlLlZzaC5TaGVsbFVJLkFwcFN5c3RlbS5kbGw="); // "Sce.Vsh.ShellUI.AppSystem.dll"
  std::string core_dll = base64_decode("U2NlLlBsYXlTdGF0aW9uLkNvcmUuZGxs"); // "Sce.PlayStation.Core.dll"
  std::string capture_menu_dll = base64_decode("U2NlLlZzaC5TaGVsbFVJLkNhcHR1cmVNZW51LmRsbA=="); // "Sce.Vsh.ShellUI.CaptureMenu.dll"

  // Namespace and class names
  std::string appsystem_namespace = base64_decode("U2NlLlZzaC5TaGVsbFVJLkFwcFN5c3RlbQ=="); // "Sce.Vsh.ShellUI.AppSystem"
  std::string layer_manager = base64_decode("TGF5ZXJNYW5hZ2Vy"); // "LayerManager"
  std::string update_impose_flag = base64_decode("VXBkYXRlSW1wb3NlU3RhdHVzRmxhZw=="); // "UpdateImposeStatusFlag"
  std::string input_namespace = base64_decode("U2NlLlBsYXlTdGF0aW9uLkNvcmUuSW5wdXQ="); // "Sce.PlayStation.Core.Input"
  std::string gamepad_class = base64_decode("R2FtZVBhZA=="); // "GamePad"
  std::string getdata_method = base64_decode("R2V0RGF0YQ=="); // "GetData"
  std::string security_namespace = base64_decode("UmVhY3ROYXRpdmUuUGxheVN0YXRpb24uU2VjdXJpdHk="); // "ReactNative.PlayStation.Security" 
  std::string bundle_decryptor = base64_decode("SmF2YVNjcmlwdEJ1bmRsZURlY3J5cHRvcg=="); // "JavaScriptBundleDecryptor"
  std::string decrypt_method = base64_decode("RGVjcnlwdA=="); // "Decrypt"
  std::string onpressed_method = base64_decode("T25QcmVzc2Vk"); // "OnPressed"
  std::string boot_helper = base64_decode("Qm9vdEhlbHBlcg=="); // "BootHelper"
  std::string boot_method = base64_decode("Qm9vdA=="); // "Boot"
  std::string capture_namespace = base64_decode("U2NlLlZzaC5TaGVsbFVJLkNhcHR1cmVNZW51"); // "Sce.Vsh.ShellUI.CaptureMenu"
  std::string capture_controller = base64_decode("Q2FwdHVyZUNvbnRyb2xsZXI="); // "CaptureController"
  std::string capture_screen = base64_decode("Q2FwdHVyZVNjcmVlbg=="); // "CaptureScreen"
  std::string event_manager = base64_decode("RXZlbnRNYW5hZ2Vy"); // "EventManager" 
  std::string onshare_button = base64_decode("T25TaGFyZUJ1dHRvbg=="); // "OnShareButton"
  std::string oncreating_method = base64_decode("T25DcmVhdGluZw=="); // "OnCreating"
  std::string getstring_method = base64_decode("R2V0U3RyaW5n"); // "GetString"
  std::string term = base64_decode("VGVybWluYXRl"); // "Terminate"

  sceKernelGetProsperoSystemSwVersion(&sw);
  bool is_3xx = (sw.version < 0x4000042);
  shellui_log("System Software Version: %s is_3xx: %s", sw.version_str, is_3xx ? "Yes" : "No");

#if 0
  sceLncUtilLaunchApp_dyn = reinterpret_cast<SceLncUtilLaunchAppType>(reinterpret_cast<uintptr_t>(sceSystemServiceLaunchApp) + is_3xx ? 0x1250 : 0x1260));
#endif

  if (mono_get_root_domain) {
    shellui_log("loading settings");
    if (!LoadSettings()) {
      shellui_log("Failed to load settings");
      return -1;
    } else {
      shellui_log("Settings loaded successfully");
    }

    Root_Domain = mono_get_root_domain();
    if (!Root_Domain) {
      shellui_log( "failed to get shellui root domain");
      return -1;
    } else {
      shellui_log("Shellui Root Domain: %p", Root_Domain);
    }

    mono_thread_attach(Root_Domain);

    const char *enc_ver = "\x30\x44\x0d\x1c\x13\x08\x69\x35\x3d\x44\x0d\x46";
    std::vector<unsigned char> dev_ver_string = encrypt_decrypt((unsigned char *)enc_ver, strlen(enc_ver), key_base64);
    std::string dec_ver = std::string(dev_ver_string.begin(), dev_ver_string.end());
    dec_ver += etaHEN_VERSION;
    std::string final_ver;
#if PUBLIC_TEST == 1
    final_ver = dec_ver + " -PUBLIC_-TEST" + " (" + sw.version_str + " )";
#elif PRE_RELEASE == 1
    final_ver = dec_ver + " PRE_RELEASE" + " (" + sw.version_str + " )";
#else
    final_ver = dec_ver + " (" + sw.version_str + " )";
#endif
    shellui_log("Decrypted Version: %s", final_ver.c_str());

    if (!SetVersionString(final_ver.c_str())) {
      shellui_log("Failed to set func556");
      return -1;
    }

    int size = ((uint64_t)&toolbox_end - (uint64_t)&toolbox_start);
    int lite_size = ((uint64_t)&toolbox_lite_end - (uint64_t)&toolbox_lite_start);
    std::vector<unsigned char> decrypted_data = encrypt_decrypt(toolbox_start, size, key_base64);
    // Convert decrypted data to a string
    dec_xml_str = std::string(decrypted_data.begin(), decrypted_data.end());
    decrypted_data = encrypt_decrypt(toolbox_lite_start, lite_size, key_base64);
    dec_list_xml_str = std::string(decrypted_data.begin(), decrypted_data.end());
    // Load the assembly    
    std::string PowerManager = base64_decode("UG93ZXJNYW5hZ2Vy");
    std::string term = base64_decode("VGVybWluYXRl");

    MonoImage * leg_img = getDLLimage(legacy_dec.c_str());
    if (!leg_img) {
      notify("Failed to get legacy image");
      return -1;
    }

    MonoImage * mscorelib_image = getDLLimage(mscorlib_dll.c_str());
    if (!mscorelib_image) {
      notify("Failed to get mscorelib image");
      return -1;
    }

    MonoImage * REACTPUI_img = getDLLimage(reactpui_dll.c_str());
    if (!REACTPUI_img) {
      notify("Failed to get image 0.");
      return -1;
    }

    MonoImage * AppSystem_img = getDLLimage(appsystem_dll_name.c_str());
    if (!AppSystem_img) {
      notify("Failed to get image 1.5.");
      return -1;
    }

    MonoImage * image_core = getDLLimage(core_dll.c_str());
    if (!image_core) {
      notify("Failed to get image 1.");
      return -1;
    }

    MonoImage * appsystem_img = getDLLimage(appsystem_dll.c_str());
    if (!appsystem_img) {
      notify("Failed to get image 2.");
      return -1;
    }

    MonoImage * capture_menu = getDLLimage(capture_menu_dll.c_str());
    if (!capture_menu) {
      notify("Failed to get image 3.");
      return -1;
    }

    MonoImage * lnc_img = getDLLimage("Sce.Vsh.LncUtilWrapper.dll");
    if (!lnc_img) {
      notify("Failed to get image 4.");
     // return -1;
    }

    react_common_img = getDLLimage("ReactNative.Vsh.Common.dll");
    if (!react_common_img) {
      notify("Failed to get image 5.");
      return -1;
    }

    
    MonoImage * ReactNativeShellAppReactNativeShellApp_img = getDLLimage("Sce.Vsh.ShellUI.ReactNativeShellApp.dll");
    if (!ReactNativeShellAppReactNativeShellApp_img) {
      notify("Failed to get image 6.");
      return -1;
    }

    Patch_Main_thread_Check(image_core);

    // System.Reflection.RuntimeAssembly.GetManifestResourceStream
    uint64_t method = Get_Address_of_Method(mscorelib_image, sys_reflection_dec.c_str(), is_3xx ? "Assembly" : RuntimeAssembly_dec.c_str(), GetManifestResourceStream_dec.c_str(), 1);
    if (!method) {
      notify("Failed to get master address");
      return -1;
    }

    shellui_log("Starting hooking...");
    if (if_exists("/system_tmp/kstuff_paused")) {
      shellui_log("Kstuff Paused, resuming kstuff");
      pause_resume_kstuff(NOT_PAUSED, false);
      unlink("/system_tmp/kstuff_paused");
    }

    has_hv_bypess = (sceKernelMprotect( & buz[0], 100, 0x7) == 0);

    if(sceRegMgrGetInt) {
      sceRegMgrGetInt = (int( * )(long, int * )) DetourFunction((uintptr_t)sceRegMgrGetInt, (void *)&sceRegMgrGetInt_hook);
      if (!sceRegMgrGetInt) {
        notify("Failed to detour int func");
        return -1;
      }
    }

    void* createJson_addr =  DetourFunction(Get_Address_of_Method(ReactNativeShellAppReactNativeShellApp_img, "ReactNative.Modules.ShellUI.HomeUI", "OptionMenu", "createJson", 8), (void * )&createJson_hook);
    createJson = (void( * )(MonoObject *, MonoObject * , MonoString * , MonoString * , MonoString * , MonoString * , MonoString * , MonoObject * , bool)) createJson_addr;
    if (!createJson_addr) {
      shellui_log("Failed to detour Func Set -3");
      return -1;
    }

    LaunchApp_orig = (int( * )(MonoString * , uint64_t * , int, LaunchAppParam * )) DetourFunction(Get_Address_of_Method(lnc_img, "Sce.Vsh.LncUtil", "LncUtilWrapper", "LaunchApp", 4), (void * )&LaunchApp);
    if (!LaunchApp_orig) {
      shellui_log("Failed to detour Func Set -2");
     // return -1;
    }

    UpdateImposeStatusFlag_Orig = (void( * )(MonoObject * , MonoObject * )) DetourFunction(Get_Address_of_Method(AppSystem_img, appsystem_namespace.c_str(), layer_manager.c_str(), update_impose_flag.c_str(), 2), (void * )&UpdateImposeStatusFlag_hook);
    if (!UpdateImposeStatusFlag_Orig) {
      notify("Failed to detour Func Set -1");
    }

    GetData = (GamePadData( * )(int)) DetourFunction(Get_Address_of_Method(image_core, input_namespace.c_str(), gamepad_class.c_str(), getdata_method.c_str(), 1), (void * )&GetData_hook);
    if (!GetData) {
      notify("Failed to detour Func Set0");
      return -1;
    }

    CxmlUri = (MonoString * ( * )(MonoObject * , MonoString * )) DetourFunction(Get_Address_of_Method(leg_img, UI3_dec.c_str(), SettingsPlugin_dec.c_str(), cxml_dec.c_str(), 1), (void * )&CxmlUri_Hook);
    if (!CxmlUri) {
      notify("Failed to detour Func Set1");
    }

#if 1
    CallDecrypt_orig = (void( * )(unsigned char * , int, int, int * , int * )) DetourFunction(Get_Address_of_Method(REACTPUI_img, security_namespace.c_str(), bundle_decryptor.c_str(), decrypt_method.c_str(), 5), (void * )&CallDecrypt);
    if (!CallDecrypt_orig) {
      if (ioctl) {
         shellui_log("Found ioctl at %p", ioctl);
         DetourFunction((uintptr_t)ioctl, (void *)&ioctl_hook);
         shellui_log("Detoured ioctl to ioctl_Hook");
       } else {
         notify("Failed to find func workaround");
         return -1;
       }
    }
#endif
    oOnPress = (int( * )(MonoObject * , MonoObject * , MonoObject * )) DetourFunction(Get_Address_of_Method(leg_img, UI3_dec.c_str(), SettingsPage_dec.c_str(), onpressed_method.c_str(), 2), (void * )&OnPress_Hook);
    if (!oOnPress) {
      shellui_log("Failed to detour Func Set3");
    }

    boot_orig = (bool( * )(MonoString * , int, MonoString * )) DetourFunction(Get_Address_of_Method(AppSystem_img, appsystem_namespace.c_str(), boot_helper.c_str(), boot_method.c_str(), 3), (void * )&uri_boot_hook);
    if (!boot_orig) {
      boot_orig_2 = (bool( * )(MonoString * , int)) DetourFunction(Get_Address_of_Method(AppSystem_img, appsystem_namespace.c_str(), boot_helper.c_str(), boot_method.c_str(), 2), (void * )&uri_boot_hook_2);
      if (!boot_orig_2) {
        notify("failed to detour Func Set4");
      }
    }

    CaptureScreen_orig_old = (void( * )(MonoObject *, int, long, int, MonoObject * )) DetourFunction(Get_Address_of_Method(capture_menu, capture_namespace.c_str(), capture_controller.c_str(), capture_screen.c_str(), 4), (void * )&CaptureScreen_old);
    if (!CaptureScreen_orig_old) {
        CaptureScreen_orig_new = (void( * )(MonoObject *, int, long, int, MonoString * , MonoObject * )) DetourFunction(Get_Address_of_Method(capture_menu, capture_namespace.c_str(), capture_controller.c_str(), capture_screen.c_str(), 5), (void * )&CaptureScreen_new);
        if(!CaptureScreen_orig_new) {
           notify("Failed to detour Func Set5");
        }
    }

    OnShareButton_orig = (void( * )(MonoObject * )) DetourFunction(Get_Address_of_Method(capture_menu, capture_namespace.c_str(), event_manager.c_str(), onshare_button.c_str(), 1), (void * )&OnShareButton);
    if (!OnShareButton_orig) {
      notify("Failed to detour Func Set6");
    }

    oOnPreCreate = (int( * )(MonoObject * , MonoObject * )) DetourFunction(Get_Address_of_Method(leg_img, UI3_dec.c_str(), SettingsPage_dec.c_str(), oncreating_method.c_str(), 1), (void * )&OnPreCreate_Hook);
    if (!oOnPreCreate) {
      notify("Failed to detour Func Set7");
    }

    oGetString = (MonoString * ( * )(MonoObject * , MonoString * )) DetourFunction(Get_Address_of_Method(leg_img, UI3_dec.c_str(), SettingsPlugin_dec.c_str(), getstring_method.c_str(), 1), (void * )&GetString_Hook);
    if (!oGetString) {
      notify("Failed to detour Func Set8");
      return -1;
    }

    GetManifestResourceStream_Original = (uint64_t( * )(uint64_t, MonoString * ))(DetourFunction(method, (void * ) & GetManifestResourceStream_Hook));
    if (!GetManifestResourceStream_Original) {
      notify("Failed to detour Func Set9");
    }

    shellui_log("Performing Magic ....");
    // rest mode without a network
    oTerminate = (void( * )(void))(DetourFunction(Get_Address_of_Method(AppSystem_img, appsystem_namespace.c_str(), PowerManager.c_str(), term.c_str(), 0), (void * )&Terminate));
    if (!oTerminate) {
      notify("Failed to detour Func Set 10");
    }

    //
    // Restore normal authid
    //
    set_proc_authid(pid, old_authid);
    //
    // Continue
    //
    if(global_conf.display_tids)
       ReloadRNPSApp("NPXS40002"); // home screen tid

    // shellui_log("Decrypted Data: %s", dec_xml_str.c_str());
    shellui_log("Performed Magic");

    hooked = true;

    // file to let the main daemon know that its finished loading
    touch_file("/system_tmp/toolbox_online");

    while (true) {
      shellui_log("sleeping ....");
      sleep(0x100000);
    }
    return 0;
    }
}
