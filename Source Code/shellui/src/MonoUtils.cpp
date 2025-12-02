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
#include "ipc.hpp"
#include "defs.h"
#include "RemotePlay.h"
#include <cstdint>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/signal.h>
#include <unistd.h>
#include <vector>
#include <dirent.h>
#include <json.hpp>
#include <map>
#include "external_symbols.hpp"
#include "../../extern/tiny-json/tiny-json.hpp"
#include "proc.h"

#include <json.hpp>
#include <fstream>
#include <ctime>
#include <iostream>
#include <random>
#include <sys/mount.h>
#include <sstream>
using json = nlohmann::json;

#define PIN_CODE_SIZE 30
#define ACCOUNT_ID_BASE64_SIZE 16

etaHENSettings global_conf;

std::vector<GameEntry> games_list;
std::vector<Plugins> plugins_list, auto_list;
std::vector<Payloads_Apps> payloads_apps_list, custom_pkg_list;
Payloads_Apps custom_pkg_path = { .path = "/data/etaHEN/pkgs" };

std::string running_tid;
bool is_game_open = true;
bool is_current_game_open = true;
int cheatEnabledMap[256];

static const char *INI_PATH = "/user/data/etaHEN/config.ini";
extern bool game_shortcut_activated_media;


// #include <user_service.h>

extern "C"{
int sceShellCoreUtilIsUsbMassStorageMounted(int num);
}


unsigned int usbpath()
{
   // std::lock_guard<std::mutex> lock(disc_lock);
    unsigned int usb_index = -1;
    for (int i = 0; i < 8; i++) {
        if (sceShellCoreUtilIsUsbMassStorageMounted((unsigned int)i)) {
            usb_index = i;
            //log_info("[UTIL] USB %i is mounted, SceAutoMountUsbMass: %i", i, usb_number);
            break;
        }
    }
    return usb_index;
}

std::vector<unsigned char> encrypt_decrypt(const unsigned char *data, size_t size, const std::string &key) {
  std::vector<unsigned char> result(size);
  size_t key_len = key.size();

  for (size_t i = 0; i < size; ++i) {
    result[i] = data[i] ^ key[i % key_len];
  }
  return result;
}

static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_decode(const std::string &encoded_string) {
  int in_len = encoded_string.size();
  int i = 0, j = 0, in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && (encoded_string[in_] != '=') &&
         is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_];
    in_++;
    if (i == 4) {
      for (i = 0; i < 4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] =
          (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] =
          ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i) {
    for (j = i; j < 4; j++)
      char_array_4[j] = 0;

    for (j = 0; j < 4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] =
        ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++)
      ret += char_array_3[j];
  }

  return ret;
}


void notify(const char *text, ...)
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

  shellui_log("Sending notification: %s", req.message);
  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}


MonoImage * getDLLimage(const char* dll_file){
  
  std::string dll_path = "/system_ex/common_ex/lib/" + std::string(dll_file);
  MonoAssembly * Assembly = mono_domain_assembly_open(Root_Domain, dll_path.c_str());
  if (!Assembly) {
    shellui_log("Failed to open assembly %s.", dll_path.c_str());
    return nullptr;
  }

  MonoImage * img = mono_assembly_get_image(Assembly);
  if (!img) {
    shellui_log("Failed to get image %s.", dll_path.c_str());
    return nullptr;
  }
  return img;
}


MonoObject* New_Object(MonoClass* Klass)
{
    if (Klass == nullptr)
    {
        return nullptr;
    }

    return mono_object_new(Root_Domain, Klass);
}

MonoObject* CreateUIColor(float r, float g, float b, float a)
{
    MonoClass* uIColor = mono_class_from_name(pui_img, "Sce.PlayStation.PUI", "UIColor");

    // Allocates memory for our new instance of a class.
    MonoObject* uIColorInstance = New_Object(uIColor);
    MonoObject* realInstance = (MonoObject*)mono_object_unbox(uIColorInstance);

    Invoke<void>(pui_img, uIColor, realInstance, ".ctor", r, g, b, a);

    return realInstance;
}

MonoObject* CreateUIFont(int size, int style, int weight)
{
    MonoClass* uIFont = mono_class_from_name(pui_img, "Sce.PlayStation.PUI.UI2", "UIFont");

    // Allocates memory for our new instance of a class.
    MonoObject* uIFontInstance = New_Object(uIFont);
    MonoObject* realInstance = (MonoObject*)mono_object_unbox(uIFontInstance);

    Invoke<void>(pui_img, uIFont, realInstance, ".ctor", size, style, weight);

    return realInstance;
}

MonoObject* CreateLabel(const char* name, float x, float y, const char* text, MonoObject* font, int horzAlign, int vertAlign, float r, float g, float b, float a)
{
    MonoClass* labelClass = mono_class_from_name(pui_img, "Sce.PlayStation.PUI.UI2", "Label");

    // Allocates memory for our new instance of a class.
    MonoObject* labelInstance = New_Object(labelClass);

    // Call Constructor.
    mono_runtime_object_init(labelInstance);

    Set_Property(labelClass, labelInstance, "Name", mono_string_new(Root_Domain, name));
    Set_Property(labelClass, labelInstance, "X", x);
    Set_Property(labelClass, labelInstance, "Y", y);
    Set_Property(labelClass, labelInstance, "Text", mono_string_new(Root_Domain, text));
    Set_Property_Invoke(labelClass, labelInstance, "Font", font);
    Set_Property(labelClass, labelInstance, "HorizontalAlignment", horzAlign);
    Set_Property(labelClass, labelInstance, "VerticalAlignment", vertAlign);
    Set_Property_Invoke(labelClass, labelInstance, "TextColor", CreateUIColor(r, g, b, a));

    Set_Property(labelClass, labelInstance, "FitWidthToText", true);
    Set_Property(labelClass, labelInstance, "FitHeightToText", true);

    return labelInstance;
}

void Widget_Append_Child(MonoObject* widget, MonoObject* child)
{
    MonoClass* widgetClass = mono_class_from_name(pui_img, "Sce.PlayStation.PUI.UI2", "Widget");
    MonoMethod* appendChild = mono_class_get_method_from_name(widgetClass, "AppendChild", 1);

    void* args[1];
    args[0] = child;

    mono_runtime_invoke(appendChild, widget, args, nullptr);
}



int endswith(const char *string, const char *suffix)
{
  size_t suffix_len = strlen(suffix);
  size_t string_len = strlen(string);

  if (string_len < suffix_len)
  {
    return 0;
  }

  return strncmp(string + string_len - suffix_len, suffix, suffix_len) != 0;
}

int chmod_bins(const char *path)
{
  char buf[PATH_MAX + 1];
  struct dirent *entry;
  struct stat st;
  DIR *dir;

  if (stat(path, &st) != 0)
  {
    return -1;
  }

  if (endswith(path, ".prx") || endswith(path, ".sprx") || endswith(path, "/eboot.bin"))
  {
    chmod(path, 0755);
  }

  if (S_ISDIR(st.st_mode))
  {
    dir = opendir(path);
    while (1)
    {
      entry = readdir(dir);
      if (entry == nullptr)
      {
        break;
      }

      if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      {
        continue;
      }

      sprintf(buf, "%s/%s", path, entry->d_name);
      chmod_bins(buf);
    }

    closedir(dir);
  }

  return 0;
}

int Launch_FG_Game(const char *path, const char* title_id, const char* title){
  app_launch_ctx_t ctx = {0};
  char dst[PATH_MAX + 1];

  strcpy(dst, "/system_ex/app/");
  strcat(dst, title_id);
  //mkdir(dst, 0777);

  sceUserServiceInitialize(0);
  sceUserServiceGetForegroundUser(&ctx.user_id);
  IPC_Client& main_ipc = IPC_Client::getInstance(false);
  if(!main_ipc.Remount(path, dst)){
    // shellui_log("Failed to mount app");
    return -1;
  }
  chmod_bins(path);

  char *argv[] = {(char*)title, nullptr};

  return sceSystemServiceLaunchApp(title_id, &argv[0], &ctx);
}

int find_and_replace(unsigned char * buffer, int buffer_size,
  const char * target,
    const char * replacement) {

  size_t target_len = strlen(target);
  size_t replacement_len = strlen(replacement);

  // Search for the target string in the buffer
  unsigned char * found = NULL;
  for (size_t i = 0; i <= buffer_size - target_len; i++) {
    if (memcmp(buffer + i, target, target_len) == 0) {
      found = buffer + i;
      break;
    }
  }

  if (!found) {
    return 0; // Target string not found
  }

  // If replacement and target are same length, simple replacement
  if (replacement_len == target_len) {
    memcpy(found, replacement, replacement_len);
    return 1;
  }

  // If replacement is shorter than target, need to shift data left
  if (replacement_len < target_len) {
    // Copy replacement
    memcpy(found, replacement, replacement_len);

    // Move remaining data left
    size_t bytes_after = buffer_size - (found - buffer) - target_len;
    memmove(found + replacement_len, found + target_len, bytes_after);

    return 1;
  }

  // If replacement is longer than target, need to shift data right
  // This assumes buffer has enough space allocated!
  size_t bytes_after = buffer_size - (found - buffer) - target_len;
  memmove(found + replacement_len, found + target_len, bytes_after);
  memcpy(found, replacement, replacement_len);

  return 1;
}

// Function to replace all occurrences
int replace_all(unsigned char * buffer, int * buffer_size, int buffer_capacity,
  const char * target,
    const char * replacement) {

  size_t target_len = strlen(target);
  size_t replacement_len = strlen(replacement);
  int count = 0;

  for (size_t i = 0; i <= * buffer_size - target_len; i++) {
    if (memcmp(buffer + i, target, target_len) == 0) {
      // Check if we have enough space for replacement
      size_t new_size = * buffer_size + (replacement_len - target_len);
      if (new_size > buffer_capacity) {
        fprintf(stderr, "Buffer too small for replacement\n");
        return count;
      }

      // Shift data if needed
      if (replacement_len != target_len) {
        memmove(buffer + i + replacement_len,
          buffer + i + target_len,
          * buffer_size - i - target_len);

        // Update buffer size
        * buffer_size = new_size;
      }

      // Copy replacement
      memcpy(buffer + i, replacement, replacement_len);

      // Update position
      i += replacement_len - 1;
      count++;
    }
  }

  return count;
}

pid_t find_pid(const char * name, bool needle, bool for_bigapp, bool need_eboot) {
  int mib[4] = {
    CTL_KERN,
    KERN_PROC,
    KERN_PROC_PROC,
    0
  };
  app_info_t appinfo;
  size_t buf_size;
  void * buf;

  int pid = -1, bigappid = 0;
  bool success = false;
  char tmp_buf[60] = {0};

  //shellui_log("looking for %s", name);

  if(for_bigapp){
    if((bigappid = sceSystemServiceGetAppIdOfRunningBigApp()) < 0){
        shellui_log("Failed to get bigapp id 0x%x", bigappid);
        return -1;
    }
  }

  // determine size of query response
  if (sysctl(mib, 4, NULL,&buf_size, NULL, 0)) {
    shellui_log("sysctl failed: %s", strerror(errno));
    return -1;
  }

  // allocate memory for query response
  if (!(buf = malloc(buf_size))) {
    shellui_log("malloc failed %s", strerror(errno));
    return -1;
  }

  // query the kernel for proc info
  if (sysctl(mib, 4, buf,&buf_size, NULL, 0)) {
    shellui_log("sysctl failed: %s", strerror(errno));
    free(buf);
    return -1;
  }

  for (char * ptr = static_cast < char * > (buf); ptr < (static_cast < char * > (buf) + buf_size);) {
    struct kinfo_proc * ki = reinterpret_cast < struct kinfo_proc * > (ptr);
    ptr += ki->ki_structsize;

    if (sceKernelGetAppInfo(ki->ki_pid,&appinfo)) {
      memset(&appinfo, 0, sizeof(appinfo));
    }

    if(sceKernelGetProcessName(ki->ki_pid, tmp_buf) != 0){
      // shellui_log("Failed to get process name for pid %d", ki->ki_pid);
       continue;
     }
   // shellui_log("Found process name for pid %d: %s", ki->ki_pid, tmp_buf);
    if(!for_bigapp && strlen(tmp_buf) > 2)
       success = (needle ? strstr(tmp_buf, name) != NULL : strcmp(tmp_buf, name) == 0); // procname search
    else if (need_eboot)
    {
      success = (bigappid == appinfo.app_id) && !strcmp(ki->ki_comm, tmp_buf);
    }
    else
    {
      success = (bigappid == appinfo.app_id);
    }
        //check the appid for bigapps

    if (success) {
      shellui_log("[Found] Process name: %s", tmp_buf);
      pid = ki->ki_pid;
      break;
    }
  }

  free(buf);

  return pid;
}


bool write_asset(const char *path, const void *start, uint32_t size)
{
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
  if (fd < 0)
  {
    shellui_log("failed to create trainer for %s | error: %s", path, strerror(errno));
    return false;
  }
  ssize_t written = write(fd, start, size);
  close(fd);
  if (written < 0)
  {
    shellui_log("Failed to write trainer for %s | size %u, error: %s", path, size, strerror(errno));
    return false;
  }
  else if ((unsigned int)written != size)
  {
    shellui_log("incomplete write: expected %u bytes, wrote %zd bytes", size, written);
    return false;
  }
  return true;
}

std::string remove_ps5_suffix(const std::string& filename) {
    size_t pos = filename.find("-ps5");
    if (pos == std::string::npos) {
        return filename; // No "-ps5" found, return copy
    }
    
    return filename.substr(0, pos) + filename.substr(pos + 4);
}

int sceSystemServiceGetAppId(const char * tid){
   // shellui_log("looking for tid %s", tid);
    pid_t success = find_pid(tid, false, false);
    if(success < 0){
       success = find_pid(remove_ps5_suffix(tid).c_str(), false, false);
    }
    return success;
}

void KillAllWithName(const char * name, int signal){
    int pid = -1;
    IPC_Client& main_ipc = IPC_Client::getInstance(false);
    while ((pid = find_pid(name, true, false)) > 0) {
        main_ipc.ForceKillPID(pid);
    }
}


uint64_t Get_Address_of_Method(MonoImage *Assembly_Image, const char *Name_Space, const char *Class_Name, const char *Method_Name, int Param_Count)
{
  MonoClass *klass = mono_class_from_name(Assembly_Image, Name_Space, Class_Name);
  if (!klass)
  {
#if SHELL_DEBUG == 1
    shellui_log("Get_Address_of_Method: failed to open class \"%s\" in namespace \"%s\"", Class_Name, Name_Space);
#endif
    return 0;
  }

  MonoMethod *Method = mono_class_get_method_from_name(klass, Method_Name, Param_Count);
  if (!Method)
  {
#if SHELL_DEBUG == 1
    shellui_log("Get_Address_of_Method: failed to find method \"%s\" in class \"%s\"", Method_Name, Class_Name);
#endif
    return 0;
  }

  // return (uint64_t)mono_aot_get_method(Root_Domain, Method);
  return mono_compile_method(Method);
}

uint64_t Get_Address_of_Method(MonoImage* Assembly_Image, MonoClass* klass, const char* Method_Name, int Param_Count)
{
	if (!klass)
	{
		return 0;
	}

	MonoMethod* Method = mono_class_get_method_from_name(klass, Method_Name, Param_Count);

	if (!Method)
	{
		return 0;
	}

	//return (uint64_t)mono_aot_get_method(mono_get_root_domain(), Method);
  return mono_compile_method(Method);
}

MonoObject *Get_Instance(MonoClass *klass, const char *Instance)
{

  MonoProperty *inst_prop = mono_class_get_property_from_name(klass, Instance);
  if (!inst_prop)
  {
#if SHELL_DEBUG == 1
    shellui_log("Failed to find Instance property \"%s\" in Class \"%s\".", Instance, klass->name);
#endif
    return nullptr;
  }

  MonoMethod *inst_get_method = mono_property_get_get_method(inst_prop);
  if (!inst_get_method)
  {
#if SHELL_DEBUG == 1
    shellui_log("Failed to find get method for \"%s\" in Class \"%s\".", Instance, klass->name);
#endif
    return nullptr;
  }

  MonoObject *inst = mono_runtime_invoke(inst_get_method, 0, 0, 0);
  if (!inst)
  {
#if SHELL_DEBUG == 1
    shellui_log("Failed to find get Instance \"%s\" in Class \"%s\".", Instance, klass->name);
#endif
    return nullptr;
  }

  return inst;
}

bool LoadSettings()
{
  IniParser parser;

  if (ini_parser_load(&parser, INI_PATH))
  {

    const char *FTP_str = ini_parser_get(&parser, "Settings.FTP", "1");
    const char *Klog_str = ini_parser_get(&parser, "Settings.Klog", "0");
    const char *DPI_str = ini_parser_get(&parser, "Settings.DPI", "0");
    const char *libhijacker_cheats_str = ini_parser_get(&parser, "Settings.libhijacker_cheats", "0");
    const char *PS5Debug_str = ini_parser_get(&parser, "Settings.PS5Debug", "0");
    const char *launch_itemzflow_str = ini_parser_get(&parser, "Settings.launch_itemzflow", "0");
    const char *discord_rpc_str = ini_parser_get(&parser, "Settings.discord_rpc", "0");
    const char *testkit_str = ini_parser_get(&parser, "Settings.testkit", "0");
    const char *allow_data_n_sandbox = ini_parser_get(&parser, "Settings.Allow_data_in_sandbox", "1");
    const char *ftp_dev_access = ini_parser_get(&parser, "Settings.ALLOW_FTP_DEV_ACCESS", "0");
    const char *start_option = ini_parser_get(&parser, "Settings.StartOption", "0");
    const char *Delay_seconds = ini_parser_get(&parser, "Settings.Rest_Mode_Delay_Seconds", "0");
    const char *util_rest_kill = ini_parser_get(&parser, "Settings.Util_rest_kill", "0");
    const char *game_rest_kill = ini_parser_get(&parser, "Settings.Game_rest_kill", "0");
    const char *toolbox_auto_start = ini_parser_get(&parser, "Settings.toolbox_auto_start", "1");
    const char *DPI_v2 = ini_parser_get(&parser, "Settings.DPI_v2", "0");
    const char *disable_toolbox_auto_start_for_rest_mode = ini_parser_get(&parser, "Settings.disable_toolbox_auto_start_for_rest_mode", "0");
    const char *dip_tid = ini_parser_get(&parser, "Settings.Display_tids", "0");
    const char *jb_debug_msg_str = ini_parser_get(&parser, "Settings.APP_JB_Debug_Msg", "0");
    const char *game_opts_str = ini_parser_get(&parser, "Settings.etaHEN_Game_Options", "1");
    const char *auto_eject_disc_str = ini_parser_get(&parser, "Settings.auto_eject_disc", "0");
	const char* overlay_ram = ini_parser_get(&parser, "Settings.overlay_ram", "1");
	const char* overlay_cpu = ini_parser_get(&parser, "Settings.overlay_cpu", "1");
	const char* overlay_gpu = ini_parser_get(&parser, "Settings.overlay_gpu", "1");
	const char* overlay_fps = ini_parser_get(&parser, "Settings.overlay_fps", "0");
	const char* overlay_ip = ini_parser_get(&parser, "Settings.overlay_ip", "0");
	const char* overlay_position = ini_parser_get(&parser, "Settings.Overlay_pos", "0"); // 0: Top-Left, 1: Top-Right, 2: Bottom-Left, 3: Bottom-Right
	const char* overlay_kstuff = ini_parser_get(&parser, "Settings.overlay_kstuff", "0");


    // Check if the strings are not nullptr before converting
	global_conf.overlay_kstuff = overlay_kstuff ? atoi(overlay_kstuff) : 0;
    global_conf.FTP = FTP_str ? atoi(FTP_str) : 0;
    global_conf.etaHEN_game_opts = game_opts_str ? atoi(game_opts_str) : 0;
    global_conf.display_tids = dip_tid ? atoi(dip_tid) : 0;
    global_conf.game_rest_kill = game_rest_kill ? atoi(game_rest_kill) : 0;
    global_conf.util_rest_kill = util_rest_kill ? atoi(util_rest_kill) : 0;
    global_conf.rest_delay_seconds = Delay_seconds ? atol(Delay_seconds) : 0;
    global_conf.Klog = Klog_str ? atoi(Klog_str) : 0;
    global_conf.DPI = DPI_str ? atoi(DPI_str) : 0;
    global_conf.libhijacker_cheats = libhijacker_cheats_str ? atoi(libhijacker_cheats_str) : 0;
    global_conf.PS5Debug = PS5Debug_str ? atoi(PS5Debug_str) : 0;
    global_conf.launch_itemzflow = launch_itemzflow_str ? atoi(launch_itemzflow_str) : 0;
    global_conf.discord_rpc = discord_rpc_str ? atoi(discord_rpc_str) : 0;
    global_conf.testkit = testkit_str ? atoi(testkit_str) : 0;
    global_conf.allow_data_sandbox = allow_data_n_sandbox ? atoi(allow_data_n_sandbox) : 0;
    global_conf.ftp_dev_access = ftp_dev_access ? atoi(ftp_dev_access) : 0;
    global_conf.start_option = start_option ? atoi(start_option) : 0;
    global_conf.toolbox_auto_start = toolbox_auto_start ? atoi(toolbox_auto_start) : 0;
    global_conf.DPI_v2 = DPI_v2 ? atoi(DPI_v2) : 0;
    global_conf.debug_app_jb_msg = jb_debug_msg_str ? atoi(jb_debug_msg_str) : 0;
    global_conf.disable_toolbox_auto_start_for_rest_mode = disable_toolbox_auto_start_for_rest_mode ? atoi(disable_toolbox_auto_start_for_rest_mode) : 0;
    global_conf.auto_eject_disc = auto_eject_disc_str ? atoi(auto_eject_disc_str) : 0;  
	global_conf.overlay_ram = overlay_ram ? atoi(overlay_ram) : 1;
	global_conf.overlay_cpu = overlay_cpu ? atoi(overlay_cpu) : 1;
	global_conf.overlay_gpu = overlay_gpu ? atoi(overlay_gpu) : 1;
	global_conf.overlay_fps = overlay_fps ? atoi(overlay_fps) : 0;
	global_conf.overlay_ip = overlay_ip ? atoi(overlay_ip) : 0;

    //apply ovelay pos  values


    // Shortcuts
    const char *cheats_shortcut_opt = ini_parser_get(&parser, "Settings.Cheats_shortcut_opt", "0");
    const char *toolbox_shortcut_opt = ini_parser_get(&parser, "Settings.Toolbox_shortcut_opt", "0");
    const char *games_shortcut_opt = ini_parser_get(&parser, "Settings.Games_shortcut_opt", "0");
    const char *kstuff_shortcut_opt = ini_parser_get(&parser, "Settings.Kstuff_shortcut_opt", "0");

    global_conf.cheats_shortcut_opt = cheats_shortcut_opt ? (Cheats_Shortcut)atoi(cheats_shortcut_opt) : CHEATS_SC_OFF;
    global_conf.toolbox_shortcut_opt = toolbox_shortcut_opt ? (Toolbox_Shortcut)atoi(toolbox_shortcut_opt) : TOOLBOX_SC_OFF;
    global_conf.games_shortcut_opt = games_shortcut_opt ? (Games_Shortcut)atoi(games_shortcut_opt) : GAMES_SC_OFF;
    global_conf.kstuff_shortcut_opt = kstuff_shortcut_opt ? (Kstuff_Shortcut)atoi(kstuff_shortcut_opt) : KSTUFF_SC_OFF;

    global_conf.overlay_pos = overlay_position ? (overlay_positions)atoi(overlay_position) : OVERLAY_POS_TOP_LEFT;



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
        global_conf.overlay_ip_x = 1670.0f;
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


    // global_conf.FTP = FTP;
    return true;
  }
  else
  {
    shellui_log("Failed to load settings");
  }
  return false;
}

bool SaveSettings()
{
  // Construct the settings string
  std::string buff = "[Settings]\n";
  buff += "libhijacker_cheats=" + std::to_string(global_conf.libhijacker_cheats) + "\n";
  buff += "PS5Debug=" + std::to_string(global_conf.PS5Debug) + "\n";
  buff += "FTP=" + std::to_string(global_conf.FTP) + "\n";
  buff += "launch_itemzflow=" + std::to_string(global_conf.launch_itemzflow) + "\n";
  buff += "discord_rpc=" + std::to_string(global_conf.discord_rpc) + "\n";
  buff += "testkit=" + std::to_string(global_conf.testkit) + "\n";
  buff += "Klog=" + std::to_string(global_conf.Klog) + "\n";
  buff += "DPI=" + std::to_string(global_conf.DPI) + "\n";
  buff += "Allow_data_in_sandbox=" + std::to_string(global_conf.allow_data_sandbox) + "\n";
  buff += "ALLOW_FTP_DEV_ACCESS=" + std::to_string(global_conf.ftp_dev_access) + "\n";
  buff += "StartOption=" + std::to_string(global_conf.start_option) + "\n";
  buff += "Rest_Mode_Delay_Seconds=" + std::to_string(global_conf.rest_delay_seconds) + "\n";
  buff += "Util_rest_kill=" + std::to_string(global_conf.util_rest_kill) + "\n";
  buff += "Game_rest_kill=" + std::to_string(global_conf.game_rest_kill) + "\n";
  buff += "toolbox_auto_start=" + std::to_string(global_conf.toolbox_auto_start) + "\n";
  buff += "DPI_v2=" + std::to_string(global_conf.DPI_v2) + "\n";
  buff += "disable_toolbox_auto_start_for_rest_mode=" + std::to_string(global_conf.disable_toolbox_auto_start_for_rest_mode) + "\n";
  buff += "Display_tids=" + std::to_string(global_conf.display_tids) + "\n";
  buff += "APP_JB_Debug_Msg=" + std::to_string(global_conf.debug_app_jb_msg) + "\n";
  buff += "etaHEN_Game_Options=" + std::to_string(global_conf.etaHEN_game_opts) + "\n";
  buff += "auto_eject_disc=" + std::to_string(global_conf.auto_eject_disc) + "\n";
  buff += "overlay_ram=" + std::to_string(global_conf.overlay_ram) + "\n";
  buff += "overlay_cpu=" + std::to_string(global_conf.overlay_cpu) + "\n";
  buff += "overlay_gpu=" + std::to_string(global_conf.overlay_gpu) + "\n";
  buff += "overlay_fps=" + std::to_string(global_conf.overlay_fps) + "\n";
  buff += "overlay_ip=" + std::to_string(global_conf.overlay_ip) + "\n";
  buff += "overlay_kstuff=" + std::to_string(global_conf.overlay_kstuff) + "\n";
  //shortcuts
  buff += "Cheats_shortcut_opt=" + std::to_string(global_conf.cheats_shortcut_opt) + "\n";
  buff += "Toolbox_shortcut_opt=" + std::to_string(global_conf.toolbox_shortcut_opt) + "\n";
  buff += "Games_shortcut_opt=" + std::to_string(global_conf.games_shortcut_opt) + "\n";
  buff += "Kstuff_shortcut_opt=" + std::to_string(global_conf.kstuff_shortcut_opt) + "\n";

  buff += "Overlay_pos=" + std::to_string(global_conf.overlay_pos) + "\n";
  // Open the file for writing
  int fd = open(INI_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0777);
  if (fd >= 0)
  {
    // Write the buffer to the file
    if (write(fd, buff.c_str(), buff.size()) != static_cast<ssize_t>(buff.size()))
    {
      shellui_log("Failed to write all settings to file");
      close(fd);
      return false;
    }
    close(fd);
  }
  else
  {
    shellui_log("Failed to open settings file for writing");
    return false;
  }
  shellui_log("Saved settings");
  return true;
}

std::string Mono_to_String(MonoString *str)
{
  if (!str)
  {
    return "";
  }

  const char *c_str = mono_string_to_utf8(str);
  std::string ret(c_str);
  mono_free((void *)c_str);
  return ret;
}

std::string GetPropertyValue(MonoObject *element, const char *propertyName)
{
  std::string ret_val;
  MonoClass *elementClass = element->vtable->klass;
  MonoProperty *property = mono_class_get_property_from_name(elementClass, propertyName);
  if (!property)
  {
    //  shellui_log("[LM HOOK] OnPress_Hook: Property %s not found", propertyName);
    return std::string();
  }

  MonoMethod *getter = mono_property_get_get_method(property);
  if (!getter)
  {
    // shellui_log("[LM HOOK] OnPress_Hook: Getter for property %s not found", propertyName);
    return std::string();
  }

  MonoObject *result = mono_runtime_invoke(getter, element, nullptr, nullptr);
  if (!result)
  {
    // shellui_log("[LM HOOK] OnPress_Hook: Getter for property %s returned nullptr", propertyName);
    return std::string();
  }
  return Mono_to_String((MonoString *)result);
}

MonoObject *InvokeByDesc(MonoClass *p_Class, const char *p_MethodDesc, void *p_Instance, void *p_Args)
{
  MonoMethodDesc *s_MethodDesc = mono_method_desc_new(p_MethodDesc, 1);
  auto s_ClassMethod = mono_method_desc_search_in_class(s_MethodDesc, p_Class);
  mono_method_desc_free(s_MethodDesc);
  if (s_ClassMethod == nullptr)
    return nullptr;

  return mono_runtime_invoke(s_ClassMethod, p_Instance, (void **)p_Args, nullptr);
}

bool is_valid_plugin(CustomPluginHeader &header)
{
  // Check if the prefix matches
  if (strncmp(header.prefix, "etaHEN_PLUGIN", 13) != 0)
  {
    shellui_log("Plugin header prefix does not match");
    return false;
  }

  for (int i = 0; i < 4; ++i)
  {
    if (header.titleID[i] < 'A' || header.titleID[i] > 'Z')
    {
      shellui_log("Invalid plugin file: titleID must contain 4 uppercase letters as the start");
      return false;
    }
  }
  for (int i = 4; i < 9; ++i)
  {
    if (header.titleID[i] < '0' || header.titleID[i] > '9')
    {
      shellui_log("Invalid plugin file: titleID must contain 5 numbers as the end");
      return false;
    }
  }

  // Ensure the title ID is nullptr-terminated
  if (header.titleID[9] != '\0')
  {
    shellui_log("Invalid plugin file: titleID must be nullptr-terminated");
    return false;
  }

  for (int i = 0; i < 3; ++i)
  {
    if (header.plugin_version[i] == '.')
    {
      continue;
    }
    else if (header.plugin_version[i] < '0' || header.plugin_version[i] > '9')
    {
      shellui_log("Invalid plugin file: version must be in the following format xx.xx");
      return false;
    }
  }

  return true;
}

MonoObject *New_Mono_XML_From_String(std::string xml_doc)
{
  MonoArray *Array = mono_array_new(Root_Domain, mono_get_byte_class(), xml_doc.size());
  if (!Array)
  {
    shellui_log("Failed to create array");
    return nullptr;
  }

  char *Array_addr = mono_array_addr_with_size(Array, sizeof(char), 0);
  sceKernelMprotect(Array_addr, xml_doc.size() + 1, 0x7);
  memcpy(Array_addr, xml_doc.data(), xml_doc.size());

  MonoObject *MemoryStream_Instance = mono_object_new(Root_Domain, MemoryStream_IO);
  if (!MemoryStream_Instance)
  {
    MemoryStream_IO = nullptr;
#if SHELL_DEBUG == 1
    shellui_log("Failed to create MemoryStream_Instance");
#endif
    return nullptr;
  }
  void *args[] = {Array};
  InvokeByDesc(MemoryStream_IO, ":.ctor(byte[])", MemoryStream_Instance, args);
  mono_gchandle_new(MemoryStream_Instance, 1);

  return MemoryStream_Instance;
}
std::string remote_play_info;
void generate_remote_play_xml(std::string &xml_buffer)
{
  // int pair_stat = -1, pair_err = -1, err = -1;
  char pin_code[PIN_CODE_SIZE] = {0};
  char AccountID[ACCOUNT_ID_BASE64_SIZE] = {0};
  uint64_t dec_account_id = 0;
  uint32_t pinCode = 0;
  bzero(AccountID, ACCOUNT_ID_BASE64_SIZE);
  std::stringstream ss;

  xml_buffer = R"(<?xml version="1.0" encoding="UTF-8" ?>
    <system_settings version="1.0" plugin="debug_settings_plugin">
    <setting_list id="remote_play_pin_display" title="Remote Play connection details" style="center">)";

  shellui_log("Starting remote play");
  static bool remote_play_initialized = false;
  if (!remote_play_initialized)
  {
    InitRemotePlay();
    remote_play_initialized = true;
  }

  if (IsNotActivated())
  {
    //
    // Implicit activate it
    //
    GetEncodedAccountID(AccountID, dec_account_id);
    xml_buffer += R"(<label id="id_pin_2" title="Account activated by etaHEN, please reboot your console before using Remote Play!" style="center"/>)";
    goto close;
  }

  shellui_log("Get encoded account id");
  GetEncodedAccountID(AccountID, dec_account_id);
  shellui_log("Get encoded account id ==> %s", AccountID);
  remote_play_info = "Account ID: " + std::string(AccountID);
  ss << std::hex << std::uppercase << dec_account_id;
  remote_play_info += "\nDecoded Account ID: " + ss.str();

  pinCode = GeneratePINCode();
  shellui_log("Pin code => %d", pinCode);

  sprintf(pin_code, "PIN code  : %04d %04d    ", pinCode / 10000, pinCode % 10000);
  remote_play_info += "\n" + std::string(pin_code);
  xml_buffer += R"(<label id="id_pin" title=")" + std::string(pin_code) + R"(" style="center"/>)";
  shellui_log("Pin code str => %s", pin_code);

  xml_buffer += R"(<label id="base64_account_id" title="Account ID: )";
  xml_buffer += std::string(AccountID) + R"(" style="center"/>)";

  if(usbpath() != -1)
      xml_buffer += R"(<button id="id_save_rp_info" title="Save Remote Play Details to USB" style="center"/>)";

close:
  xml_buffer += R"(</setting_list></system_settings>)";

  // shellui_log("%s\n", xml_buffer.c_str());
}

void generate_custom_pkg_xml(std::string& xml_buffer)
{
    std::string converted = custom_pkg_path.path;

    // Replace /mnt/xxx with /xxx
    size_t pos = converted.find("/mnt/");
    if (pos != std::string::npos) {
        converted.replace(pos, 5, "/");  // Replace "/mnt/" with "/"
    }

    // Replace /data with /user/data
    pos = 0;
    while ((pos = converted.find("/data", pos)) != std::string::npos) {
        converted.replace(pos, 5, "/user/data");
        pos += 10;  // Skip past the replacement
    }

    custom_pkg_path.shellui_path = converted;

    shellui_log("Custom PKG Path for ShellUI: %s", custom_pkg_path.shellui_path.c_str());

    struct dirent* entry;
    int pkg_id = 1;
    int pkg_count = 0;

    xml_buffer = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
        "<system_settings version=\"1.0\" plugin=\"debug_settings_plugin\">\n"
        "\n";

    xml_buffer += "<setting_list id=\"custom_pkg_install\" title=\"★ Custom PKG Installer ( " + custom_pkg_path.path + " )\">\n";
    xml_buffer += "<text_field id=\"id_change_custom_pkg_path\" title=\"Custom PKG Search Path\" keyboard_type=\"url\" confirm=\"Back out and re-select to refresh\" min_length=\"1\" max_length=\"255\"/>\n";

    DIR* dir = opendir(custom_pkg_path.shellui_path.c_str());
    if (!dir) {
        shellui_log("Failed to open custom PKG directory: %s", custom_pkg_path.shellui_path.c_str());
        xml_buffer += "<label id=\"id_no_pkgs\" title=\"No PKGs found - Path: " + custom_pkg_path.path + "\"/>\n";
        xml_buffer += "</setting_list>\n</system_settings>";
        return;
    }

    while ((entry = readdir(dir)) != nullptr) {
        if (strstr(entry->d_name, ".pkg") != nullptr) {
            std::string pkg_path = std::string(custom_pkg_path.path) + "/" + entry->d_name;
            std::string id = "id_pkg_" + std::to_string(pkg_id++);

            xml_buffer += "<button id=\"" + id + "\" title=\"" + entry->d_name + "\" description=\"" + pkg_path + "\"/>\n";
            pkg_count++;

            Payloads_Apps new_pkg;
            new_pkg.name = entry->d_name;
            new_pkg.path = pkg_path;
            new_pkg.shellui_path = std::string(custom_pkg_path.shellui_path) + "/" + entry->d_name;
            new_pkg.id = id;
            custom_pkg_list.push_back(new_pkg);

            shellui_log("Found PKG: %s", pkg_path.c_str());
        }
    }
    closedir(dir);

    if (pkg_count == 0) {
        xml_buffer += "<label id=\"id_no_pkgs\" title=\"No PKGs found - Path: " + custom_pkg_path.path + "\"/>\n";
    }

    xml_buffer += "</setting_list>\n</system_settings>";
}
void generate_plugin_xml(std::string &xml_buffer, bool plugins_xml)
{
  struct dirent *entry;
  int toggle_switch_id = 1;

  std::vector<std::string> directories = {
      "/user/data/etaHEN/plugins",
      "/usb0/etaHEN/plugins",
      "/usb1/etaHEN/plugins",
      "/usb2/etaHEN/plugins",
      "/usb3/etaHEN/plugins",

      "/user/data/etaHEN/payloads",
      "/usb0/etaHEN/payloads",
      "/usb1/etaHEN/payloads",
      "/usb2/etaHEN/payloads",
      "/usb3/etaHEN/payloads"
    };

  xml_buffer = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
               "<system_settings version=\"1.0\" plugin=\"debug_settings_plugin\">\n"
               "\n";

  if (plugins_xml)
    xml_buffer += "<setting_list id=\"id_plugin\" title=\"Plugins\">\n";
  else
    xml_buffer += "<setting_list id=\"id_auto_plugins\" title=\"★ Plugins - Startup Menu\">\n";

  for (const auto &directory : directories)
  {
    DIR *dir = opendir(directory.c_str());
    // Open the directory
    if (!dir)
    {
      shellui_log("Failed to open directory: %s", directory.c_str());
      continue;
    }
    // Iterate over each file in the directory
    while ((entry = readdir(dir)) != nullptr)
    {
      bool is_elf = strstr(entry->d_name, ".elf") != NULL;
      if ((strstr(entry->d_name, ".plugin") || is_elf) && strstr(entry->d_name, ".auto_start") == NULL)
      {
        Plugins new_list;
        // Store the ID in the plugin_ids array
        CustomPluginHeader header = {};
        std::string toggle_switch;
        std::string id;
        std::string path = directory + "/" + entry->d_name;

        shellui_log("Found Plugin: %s", path.c_str());

        int fd = open(path.c_str(), O_RDONLY, 0);
        if (fd < 0)
        {
          shellui_log("Failed to open Plugin file");
          continue;
        }

        if (read(fd, (void *)&header, sizeof(CustomPluginHeader)) != sizeof(CustomPluginHeader))
        {
          shellui_log("Failed to read Plugin file, %s", path.c_str());
          close(fd);
          continue;
        }

        close(fd);

        if (!is_elf && !is_valid_plugin(header))
        {
          shellui_log("Invalid plugin file.");
          continue;
        }
        else if(is_elf){
          strncpy(header.prefix, "<elf>", 5);
          strncpy(header.plugin_version, "?.??", 4);
        }
        shellui_log("Valid plugin file.");

        std::string shown_path = path; // Initialize with the original path
        //path before any edits for shellui
        new_list.shellui_path = path;

        const std::string prefix = "/user";
        if (path.find(prefix) == 0) { // Check if the path starts with "/user"
           shown_path = path.substr(prefix.length()); // Remove "/user"
        }

        shown_path = (path.substr(0, 4) == "/usb") ? "/mnt" + path : shown_path;

        id = plugins_xml ? "id_plugin_" + std::to_string(toggle_switch_id++) : "id_auto_plugin_" + std::to_string(toggle_switch_id++);
        if (plugins_xml)
          toggle_switch = "<toggle_switch id=\"" + id + "\" title=\"" + entry->d_name + " (v" + header.plugin_version + ")\" second_title=\"Start/Stop " + entry->d_name + " (Path: " + shown_path + ") (" + (is_elf ? entry->d_name : header.titleID) + ")\" value=\"0\"/>\n";
        else
          toggle_switch = "<toggle_switch id=\"" + id + "\" title=\"" + entry->d_name + " (v" + header.plugin_version + ")\" second_title=\"Enable/Disable auto start for " + entry->d_name + "  (" + shown_path + ")\" value=\"0\"/>\n";

        xml_buffer += toggle_switch;
        new_list.tid = (is_elf ? entry->d_name : header.titleID);
        new_list.path = shown_path;
        new_list.name = entry->d_name;
        new_list.version = header.plugin_version;
        new_list.id = id;
        plugins_xml ? plugins_list.push_back(new_list) : auto_list.push_back(new_list);
      }
    }
    closedir(dir);
  }

  if (plugins_xml)
  {
    xml_buffer += "<link id=\"id_auto_plugins\" title=\"★ Plugins - Startup Menu\" file=\"auto_plugins.xml\" second_title=\"Configure plugins to launch when you load etaHEN\"/>\n";
    xml_buffer += "</setting_list>\n</setting_list>\n</system_settings> ";
  }
  else
  {
    xml_buffer += "</setting_list>\n</system_settings> ";
  }
}

bool SetVersionString(const char *str)
{
  MonoAssembly *Assembly = mono_domain_assembly_open(Root_Domain, uilib_dll.c_str());
  if (!Assembly)
  {
#if SHELL_DEBUG == 1
    shellui_log("SetVersionString: Failed to open assembly.");
#endif
    return false;
  }
  MonoClass *SystemSoftwareVersionInfo = mono_class_from_name(mono_assembly_get_image(Assembly), uilib.c_str(), Sysinfo.c_str());
  if (!SystemSoftwareVersionInfo)
  {
#if SHELL_DEBUG == 1
    shellui_log("SetVersionString: Failed to open class.");
#endif
    return false;
  }

  MonoObject *SystemSoftwareVersionInfo_Instance = Get_Instance(SystemSoftwareVersionInfo, "Instance");
  if (!SystemSoftwareVersionInfo_Instance)
  {
#if SHELL_DEBUG == 1
    shellui_log("SetVersionString: Failed to open Instance.");
#endif
    return false;
  }

  MonoMethod *Set_Method = mono_class_get_method_from_name(SystemSoftwareVersionInfo, display_info.c_str(), 1);
  if (Set_Method == nullptr)
  {
#if SHELL_DEBUG == 1
    shellui_log("SetVersionString: Could not find set method.");
#endif
    return false;
  }

  MonoObject *exception = nullptr;
  void *args[] = {mono_string_new(Root_Domain, str)};
  //    MonoObject* result = mono_runtime_invoke(send_by_id_method, nullptr, args, &exception);
  mono_runtime_invoke(Set_Method, SystemSoftwareVersionInfo_Instance, args, &exception);
  if (exception)
  {
    MonoString *exc_string = mono_object_to_string(exception, nullptr);
    const char *exc_chars = mono_string_to_utf8(exc_string);
#if SHELL_DEBUG == 1
    shellui_log("Exception: %s", exc_chars);
#endif
    mono_free((void *)exc_chars);
    return false;
  }
  return true;
}

extern "C" int sceKernelLoadStartModule(const char *name, size_t argc, const void *argv, uint32_t flags, uint32_t pOpt, int *pResid);
extern "C" int sceKernelDlsym(int lib, const char *name, void **func);
int ItemzLaunchByUri(const char *uri)
{

  if (!uri)
    return -1;
  //
  SceShellUIUtilLaunchByUriParam Param;
  Param.size = sizeof(SceShellUIUtilLaunchByUriParam);
  sceShellUIUtilInitialize();
  sceUserServiceGetForegroundUser((int *)&Param.userId);

  return sceShellUIUtilLaunchByUri(uri, &Param);
}

void GoToHome()
{
  ItemzLaunchByUri("pshomeui:navigateToHome?bootCondition=psButton");
}
struct URIThreadData {
  std::string uri;  // Copy the string to avoid dangling pointers
};

void* GoToURIThread(void *arg) {
  URIThreadData* data = static_cast<URIThreadData*>(arg);
  
  ItemzLaunchByUri(data->uri.c_str());
  
  delete data;  // Clean up the allocated data
  pthread_exit(nullptr);
  return nullptr;
}

void GoToURI(const char* uri) {
  if (!uri) {
      shellui_log("GoToURI: URI is null");
      return;
  }
  
  // Create a copy of the URI data
  URIThreadData* data = new URIThreadData{std::string(uri)};
  
  pthread_t t;
  if (pthread_create(&t, nullptr, GoToURIThread, data) != 0) {
      shellui_log("Failed to create thread for GoToURI");
      delete data;  // Clean up on failure
      return;
  }
  
  // Detach the thread so it cleans up automatically
  pthread_detach(t);
}
bool Get_Running_App_TID(std::string &title_id, int &BigAppid)
{
  char tid[255];
  BigAppid = sceSystemServiceGetAppIdOfRunningBigApp();
  if (BigAppid < 0)
  {
   // shellui_log("Failed to get bigapp id 0x%x", BigAppid);
    return false;
  }
  (void)memset(tid, 0, sizeof tid);

  if (sceSystemServiceGetAppTitleId(BigAppid, &tid[0]) != 0)
  {
    //shellui_log("Failed to get title id for bigapp id 0x%x", BigAppid);
    return false;
  }

  title_id = std::string(tid);

  return true;
}

bool touch_file(const char *destfile)
{
	int fd = open(destfile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
	if (fd > 0)
	{
		close(fd);
		return true;
	}
	return false;
}

void escapeXML(std::string& input) 
{
    std::unordered_map<std::string, std::string> escapeSequences = 
    {
        {"&", "&amp;"},
        {"<", "&lt;"},
        {">", "&gt;"},
        {"\"", "&quot;"},
        {"/", "//"}
    };
    
    for (const auto& pair : escapeSequences) 
    {
        size_t pos = 0;
        while ((pos = input.find(pair.first, pos)) != std::string::npos) 
        {
            input.replace(pos, pair.first.length(), pair.second);
            pos += pair.second.length(); // Move past the replaced part
        }
    }
}

bool getContentInfofromJson(const std::string& file_path, std::string& tid, std::string& title, std::string &ver) {
  try {
      std::ifstream input_file(file_path);
      if (!input_file.is_open()) {
          shellui_log("Failed to open file for reading: %s", file_path.c_str());
          return false;
      }

      json j;
      input_file >> j;
      input_file.close();

      if (!j.contains("titleId")) {
          shellui_log("JSON does not contain a required value");
          return false;
      }

      tid = j["titleId"];

      #if SHELL_DEBUG==1 
      shellui_log("getContentInfofromJson Title ID: %s", tid.c_str());
      #endif

      if (j.contains("localizedParameters") && j["localizedParameters"].contains("defaultLanguage")) {
          std::string defaultLanguage = j["localizedParameters"]["defaultLanguage"];
          if (j["localizedParameters"].contains(defaultLanguage) && j["localizedParameters"][defaultLanguage].contains("titleName")) {
              title = j["localizedParameters"][defaultLanguage]["titleName"];
          }
      }
      else
          title = "App Title not found";

      if (j.contains("contentVersion"))
          ver = j["contentVersion"];

  }
  catch (const std::exception& e) {
    shellui_log("Exception: %s", e.what());
    return false;
}

  return true;
}
int list_directories(const char *path) {
  DIR *dir;
  struct dirent *entry;
  struct stat statbuf;
  char fullpath[1024];
  
  // Open the directory
  if ((dir = opendir(path)) == NULL) {
      perror("opendir");
      return -1;
  }
  
  shellui_log("Directories in %s:\n", path);
  
  // Read directory entries
  while ((entry = readdir(dir)) != NULL) {
      // Skip "." and ".." entries
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
          continue;
          
      // Construct the full path
      snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
      
      // Get information about the file
      if (stat(fullpath, &statbuf) == -1) {
          perror("stat");
          continue;
      }
      
      // Check if it's a directory
      if (S_ISDIR(statbuf.st_mode)) {
        shellui_log("%s", entry->d_name);
      }
  }
  
  closedir(dir);
  return 0;
}

// Function to escape a string for XML
void generate_games_xml(std::string &xml_buffer, bool game_shortcut_activated)
{
  struct dirent *entry;
  // do outside func
  // games_list.clear();

  std::vector<std::string> directories = {
    "/user/data/etaHEN/games",
    "/usb0/etaHEN/games",
    "/usb1/etaHEN/games",
    "/usb2/etaHEN/games",
    "/usb3/etaHEN/games",
    "/mnt/ext1/etaHEN/games",
    "/mnt/ext2/etaHEN/games",
    "/mnt/ext0/etaHEN/games",
  };
 // list_directories("/mnt/sandbox/NPXS40087_000");

  std::string list_id = game_shortcut_activated ? "id_debug_settings" : "id_ps5_backups";

  xml_buffer =  "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
      "<system_settings version=\"1.0\" plugin=\"debug_settings_plugin\">\n"
      "\n";

  xml_buffer += "<setting_list id=\"" + list_id + "\" title=\"(Beta) PS5 webMAN Games\">\n";


  // Initialize random number generator
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dist(1000, 9999);

  for (const auto &directory : directories)
  {
    DIR *dir = opendir(directory.c_str());
    // Open the directory
    if (!dir)
    {
      #if SHELL_DEBUG==1 
      shellui_log("Failed to open directory: %s", directory.c_str());
      #endif
      continue;
    }
    
    // Iterate over each entry in the games directory
    while ((entry = readdir(dir)) != nullptr)
    {
      // Skip . and .. directories
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        continue;
        
      std::string game_dir = directory + "/" + entry->d_name;
      
      // Check if this is a directory by trying to open it
      struct stat st;
      if (stat(game_dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        #if SHELL_DEBUG==1 
        shellui_log("Skipping non-directory: %s", game_dir.c_str());
        #endif
        continue;
      }
        
      std::string param_path = game_dir + "/sce_sys/param.json";
      std::string icon_path = game_dir + "/sce_sys/icon0.png";
      
      // Check if param.json exists
      if (access(param_path.c_str(), F_OK) != 0) {
        #if SHELL_DEBUG==1 
        shellui_log("No param.json found in: %s", game_dir.c_str());
        #endif
        continue;
      }
      #if SHELL_DEBUG==1 
      shellui_log("Found Game: %s", game_dir.c_str());
      #endif
      
      // Parse the JSON to get title_id, content_id, title, and version
      std::string title_id, title, ver;
      if (!getContentInfofromJson(param_path, title_id, title, ver)) {
        #if SHELL_DEBUG==1 
        shellui_log("Failed to parse param.json in: %s", game_dir.c_str());
        #endif
        continue;
      }
      
      std::string shown_path = game_dir; // Initialize with the original path
      
      const std::string prefix = "/user";
      if (shown_path.find(prefix) == 0) { // Check if the path starts with "/user"
         shown_path = shown_path.substr(prefix.length()); // Remove "/user"
      }
      
      shown_path = (game_dir.substr(0, 4) == "/usb") ? "/mnt" + game_dir : shown_path;
      // Generate a random number for the ID
      int random_num = dist(gen);
      
      // Escape the icon path for XML
      escapeXML(icon_path);
      
      // Create and populate a GameEntry
      GameEntry game;
      game.tid = title_id;
      game.title = title;
      game.version = ver;
      game.path = shown_path;
      game.dir_name = entry->d_name;
      game.icon_path = icon_path;
      game.id = "id_game_" + title_id + "_" + std::to_string(random_num);
      
      // Add to the games list
      games_list.push_back(game);
      
      // Format the button XML
      std::string button = "<button id=\"" + game.id + "\" title=\"(" + title_id + ") " + title + 
      "\" icon=\"" + icon_path + "\" second_title=\"" + shown_path + " | Version: " + ver + "\"/>\n";
      
      xml_buffer += button;
    }
    //shellui_log("cloaing dir %s", directory.c_str());
    closedir(dir);
  }

  xml_buffer += "</setting_list>\n</system_settings> ";
}

void ReloadRNPSApp(const char* title_id){
    void (*ReloadApp)(MonoString* tid) = (void(*)(MonoString*))Get_Address_of_Method(react_common_img, "ReactNative.Vsh.Common", "ReactApplicationSceneManager", "ReloadApp", 1);
    if (ReloadApp) {
        shellui_log("Reloading %s scenes", title_id);
        ReloadApp(mono_string_new(Root_Domain, title_id));
    } else {
        shellui_log("Failed to find reload method, not reloading scene");
    }
}

void generate_cheats_xml(std::string &new_xml, std::string& not_open_tid, bool running_as_debug_settings, bool show_while_not_open)
{
  int appid = -1;
  std::string list_id = running_as_debug_settings ? "id_debug_settings" : "id_cheat_title";

  // buttons for if nothing is found
  std::string dl_cheats = R"(<button id="id_dl_cheats" title="Download/Update Cheats" second_title="Downloads the latest cheats from the PS5_Cheats GitHub repo"/>)";
  std::string reload_cheats = R"(<button id="id_reload_cheats" title="Cache and reload Cheats list" second_title="New cheats added to /data/etaHEN/cheats/EXT_HERE will be cached and the cheats list will be reloaded"/>)";
  //

  new_xml =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
      "<system_settings version=\"1.0\" plugin=\"debug_settings_plugin\">\n"
      "\n";

  is_game_open = Get_Running_App_TID(running_tid, appid);
  is_current_game_open = (is_game_open && running_tid == (show_while_not_open ? not_open_tid : running_tid));

  if (!is_game_open && !show_while_not_open)
  {
    new_xml += "<setting_list id=\"" + list_id + "\" title=\"etaHEN Cheats - No "
               "Game is open\">\n";
    new_xml += dl_cheats;
    new_xml += reload_cheats;
    
  }
  else
  {
    std::string game_ver;
    std::string cheat_info_json;
    IPC_Client &client = IPC_Client::getInstance(true);

    running_tid = show_while_not_open ? not_open_tid : running_tid;

    if (!client.GameVerFromTid(running_tid, game_ver))
    {
      game_ver = "Unable to detect patch version";
    } 

    new_xml += "<setting_list id=\"" + list_id + "\" title=\"etaHEN Cheats - ";
    new_xml += running_tid + " - " + game_ver + "\">\n";

    if(!is_game_open && show_while_not_open)
      new_xml += R"(<label id="id_cheat_disclaimer" title=")" + running_tid + R"( is not currently running you wont be able to activate any cheats unless its open")" + R"( style="center"/>)";

    if (client.GetGameCheats(running_tid, game_ver, cheat_info_json))
    {
      struct stat st;

      if (stat(cheat_info_json.c_str(), &st) == -1)
      {
        shellui_log("Unable to stat file %s", cheat_info_json.c_str());
        goto close;
      }

      int fd = open(cheat_info_json.c_str(), O_RDONLY);

      if (fd == -1)
      {
        shellui_log("Error reading %s file!", cheat_info_json.c_str());
        goto close;
      }

      char* json_data = (char*) malloc(st.st_size);
      // Write the buffer to the file
      if (read(fd, json_data, st.st_size) == -1) 
      {
        perror("read failed");
        close(fd);
        free(json_data);
        goto close;
      }

      // Close the file descriptor
      close(fd);
      unlink(cheat_info_json.c_str());
      // Create a json object from the string data
      std::string json_string(json_data, st.st_size);
      nlohmann::json res_json;

      try 
      {
        res_json = nlohmann::json::parse(json_string); 
      } 
      catch (nlohmann::json::parse_error& e) 
      {
        shellui_log("Failed to parse json from cheat response!");
        free(json_data);
        goto close;
      }

      std::string game_name = res_json.value("name", "");
      escapeXML(game_name);

      new_xml += R"(<label id="id_cheat_title" title="★ )" + game_name + R"( ★" style="center"/>)";

      // Cheat creator credits
      new_xml += R"(<label id="credits" style="center" title="Cheats created by: )";

      std::unordered_map<std::string, bool> knownAuthors;
      if (res_json.contains("authors")) 
      {
          for (const auto& author : res_json["authors"]) 
          {
              std::string author_name = author.get<std::string>();
              
              if (knownAuthors.find(author) != knownAuthors.end())
              {
                //
                // repeated
                //
                continue;
              }
              knownAuthors[author_name] = true;
              escapeXML(author_name);
              new_xml += author_name;
              if (&author != &res_json["authors"].back()) 
              {
                  new_xml += ", ";
              }
          }
      }
      new_xml += R"(" />)";

      // Build toggle switch XML entry
      if (res_json.contains("cheats")) 
      {
          for (const auto& cheat_entry : res_json["cheats"]) 
          {
              std::string cheat_name = cheat_entry.value("name", "");
              std::string description = cheat_entry.value("description", "On/Off");
              escapeXML(cheat_name);
              escapeXML(description);

              int cheat_id = cheat_entry.value("id", 0);
              bool enabled = cheat_entry.value("enabled", false);
              std::string enabled_value = enabled ? "1" : "0";
              std::string toggle_switch;
              if(is_game_open && is_current_game_open)
                 toggle_switch = R"(<toggle_switch id="id_cheat_)" + running_tid + "_" + std::to_string(cheat_id) + R"(" icon="tex_game_icon" title=")" + cheat_name + R"(" description=")" + description + R"(" value=")" + enabled_value + R"("/>)";
              else
                  toggle_switch = R"(<button id="id_cheat_)" + running_tid + "_" + std::to_string(cheat_id) + R"(" icon="tex_game_icon" title=")" + cheat_name + R"(" description=")" + description + R"(" second_title="Enable/Disable )" + cheat_name + R"( for )" + game_name + R"(" />)";

              new_xml += toggle_switch;

              cheatEnabledMap[cheat_id] = enabled;
          }
      }

      // Cleanup
      free(json_data);
    }
    else{
      new_xml += dl_cheats;
      new_xml += reload_cheats;
    }
  }
close:
  new_xml += "</setting_list>\n</system_settings>";

//  shellui_log("Cheat UI XML => \n%s\n", new_xml.c_str());
}

void generate_plapps_xml(std::string& new_xml) {

  struct dirent *entry;

  std::vector<std::string> directories = {
    "/user/data/homebrew/games",
    "/usb0/homebrew",
    "/usb1/homebrew/games",
    "/usb2/homebrew/games",
    "/usb3/homebrew/games",
    "/mnt/ext1/homebrew/games",
    "/mnt/ext2/homebrew/games",
    "/mnt/ext0/homebrew/games",
  };

    new_xml =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
      "<system_settings version=\"1.0\" plugin=\"debug_settings_plugin\">\n"
      "\n";

    new_xml += "<setting_list id=\"id_plapps\" title=\"etaHEN Payload Homebrew - Applications\">\n";

  // Initialize random number generator
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dist(1000, 9999);

  for (const auto &directory : directories)
  {
    DIR *dir = opendir(directory.c_str());
    // Open the directory
    if (!dir)
    {
      #if SHELL_DEBUG==1 
      shellui_log("Failed to open directory: %s", directory.c_str());
      #endif
      continue;
    }
    
    // Iterate over each entry in the games directory
    while ((entry = readdir(dir)) != nullptr)
    {
      // Skip . and .. directories
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        continue;
        
      std::string game_dir = directory + "/" + entry->d_name;
      
      // Check if this is a directory by trying to open it
      struct stat st;
      if (stat(game_dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        #if SHELL_DEBUG==1 
        shellui_log("Skipping non-directory: %s", game_dir.c_str());
        #endif
        continue;
      }
        
      std::string elf_path = game_dir + "/eboot.elf";
      std::string icon_path = game_dir + "/sce_sys/icon0.png";
      
      // Check if param.json exists
      if (access(elf_path.c_str(), F_OK) != 0) {
        #if SHELL_DEBUG==1 
        shellui_log("No param.json found in: %s", game_dir.c_str());
        #endif
        continue;
      }
      #if SHELL_DEBUG==1 
      shellui_log("Found Game: %s", game_dir.c_str());
      #endif
      
      // Parse the JSON to get title_id, content_id, title, and version
      std::string title_id, title, ver;
            #if 0
      if (!getContentInfofromJson(param_path, title_id, title, ver)) {
        #if SHELL_DEBUG==1 
        shellui_log("Failed to parse param.json in: %s", game_dir.c_str());
        #endif
        continue;
      }
      #endif
      
      std::string shown_path = game_dir; // Initialize with the original path
      
      const std::string prefix = "/user";
      if (shown_path.find(prefix) == 0) { // Check if the path starts with "/user"
         shown_path = shown_path.substr(prefix.length()); // Remove "/user"
      }
      
      shown_path = (game_dir.substr(0, 4) == "/usb") ? "/mnt" + game_dir : shown_path;
      // Generate a random number for the ID
      int random_num = dist(gen);
      
      // Escape the icon path for XML
      escapeXML(icon_path);
      
      // Create and populate a GameEntry
      GameEntry game;
      game.tid = title_id;
      game.title = title;
      escapeXML(game.title);
      game.version = ver;
      game.path = shown_path;
      game.dir_name = entry->d_name;
      escapeXML(game.dir_name);
      game.icon_path = icon_path;
      game.id = "id_game_" + title_id + "_" + std::to_string(random_num);
      
      // Add to the games list
      games_list.push_back(game);
      
      // Format the button XML
      std::string button = "<button id=\"" + game.id + "\" title=\"(" + title_id + ") " + title + 
      "\" icon=\"" + icon_path + "\" second_title=\"" + shown_path + " | Version: " + ver + "\"/>\n";
      
      new_xml += button;
    }
    //shellui_log("cloaing dir %s", directory.c_str());
    closedir(dir);
  }

    new_xml += "</setting_list>\n</system_settings>";
}