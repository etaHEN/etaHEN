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

#pragma once
#include "external_symbols.hpp"
#include <string>
#include <vector>
#include <iostream>
#include "defs.h"

extern "C" uint8_t toolbox_start[];
extern "C" int32_t toolbox_end;

extern "C" uint8_t toolbox_lite_start[];
extern "C" int32_t toolbox_lite_end;

#define MAX_LINE 256
#define MAX_PAIRS 100


#define SCE_LNC_UTIL_ERROR_ALREADY_RUNNING 0x8094000c
#define SCE_LNC_UTIL_ERROR_ALREADY_RUNNING_KILL_NEEDED 0x80940010
#define SCE_LNC_UTIL_ERROR_ALREADY_RUNNING_SUSPEND_NEEDED 0x80940011

#define SCE_REGMGR_ENT_KEY_DEVENV_TOOL_SHELLUI_disp_titleid 2013448470
#define SCE_REGMGR_INT_SIZE 4
#define SCE_REGMGR_ERROR_PRM_REGID 0x800D0203

typedef struct {
    char key[MAX_LINE];
    char value[MAX_LINE];
} KeyValue;

// Base64 decoding table
static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

typedef struct IniParser_t {
    KeyValue pairs[MAX_PAIRS];
    int count = 0;
} IniParser;

enum PupStatus {
    PUP_EXPIRATION_STATUS_OK = 0,
    PUP_EXPIRATION_STATUS_EXPIRED = 1,
    PUP_EXPIRATION_STATUS_EXPIRING = 2,

    PUP_EXPIRATION_MAX_EXPIRING_TIME = 259199, // 3 days
    PUP_EXPIRATION_1_DAY = 159199
};

enum TrailExpireOpt {
    TRIAL_EXPIREING_OFF = 0,
    TRIAL_EXPIREING_1_DAY = 1,
    TRIAL_EXPIREING_2_DAYS = 2,
    TRIAL_EXPIRED,
};

enum RemoveWidget {
    REMOVE_GPU_OVERLAY,
    REMOVE_CPU_OVERLAY,
    REMOVE_RAM_OVERLAY,
    REMOVE_FPS_OVERLAY,
    REMOVE_IP_OVERLAY,
    REMOVE_ALL_OVERLAYS,
	REMOVE_KSTUFF_DISABLED
};

enum CreateWidget {
    CREATE_GPU_OVERLAY,
    CREATE_CPU_OVERLAY,
    CREATE_RAM_OVERLAY,
    CREATE_FPS_OVERLAY,
    CREATE_IP_OVERLAY,
    CREATE_ALL_OVERLAYS,
    CREATE_KSTUFF_DISABLED
};

struct WidgetConfig {
    const char* id;
    float x, y;
    const char* text;
    int bold;
    float r, g, b, a;
};

void RemoveGameWidget(RemoveWidget widget);
void CreateGameWidget(CreateWidget widget);

struct LaunchAppParam
{
  // Token: 0x04000024 RID: 36
  unsigned int size;

  // Token: 0x04000025 RID: 37
  int userId;

  // Token: 0x04000026 RID: 38
  int appAttr;

  // Token: 0x04000027 RID: 39
  int enableCrashReport;

  // Token: 0x04000028 RID: 40
  int checkFlag;

  // Token: 0x04000029 RID: 41
  unsigned long contextId;

  bool isSpeculativeLaunch;
};

typedef struct {
    std::string path;
    std::string shellui_path;
    std::string tid;
    std::string id;
    std::string name; // filename
    std::string version;
} Plugins;

typedef struct {
    std::string path;
    std::string shellui_path;
    std::string id;
    std::string name; 
    std::string version;
} Payloads_Apps;


// Game Entry structure definition
struct GameEntry {
    std::string tid;         // Title ID
    std::string title;       // Game title
    std::string version;     // Game version
    std::string path;        // Displayed path
    std::string dir_name;    // Directory name
    std::string icon_path;   // Path to icon
    std::string id;          // Button ID
  };

extern std::vector<GameEntry> games_list;
enum Cheats_Shortcut{
    CHEATS_SC_OFF = 0,
    R3_L3,
    L2_TRIANGLE,
    LONG_OPTIONS,
    CHEATS_LONG_SHARE,
    CHEATS_SINGLE_SHARE,
 };
 
 enum Toolbox_Shortcut{
    TOOLBOX_SC_OFF = 0,
    L2_R3,
    TOOLBOX_LONG_SHARE,
    TOOLBOX_SINGLE_SHARE,
 };
 
 enum Games_Shortcut{
    GAMES_SC_OFF = 0,
    R1_L1,
    L2_O,
    GAMES_LONG_SHARE,
    GAMES_SINGLE_SHARE,
 };
 
 enum Kstuff_Shortcut{
    KSTUFF_SC_OFF = 0,
    R2_L2,
    L2_SQUARE,
    KSTUFF_LONG_SHARE,
    KSTUFF_SINGLE_SHARE,
 };

 enum overlay_positions{
    OVERLAY_POS_TOP_LEFT = 0,
    OVERLAY_POS_TOP_RIGHT,
    OVERLAY_POS_BOTTOM_LEFT,
    OVERLAY_POS_BOTTOM_RIGHT
 };

 enum cheats_repo_source{
    CHEATS_REPO_ETAHEN = 0,
    CHEATS_REPO_GOLDHEN
 };

typedef struct etaHENSettings_t
{
    bool FTP = true;
    bool Klog = true;
    bool DPI = true;
    bool DPI_v2 = false;
    bool libhijacker_cheats = false;
    bool PS5Debug = false;
    bool launch_itemzflow = false;
    bool discord_rpc = false;
    bool testkit = false;
    bool allow_data_sandbox = false;
    bool ftp_dev_access = false;
    bool util_rest_kill = false;
    bool game_rest_kill = false;
    bool lite_mode = false;
    bool toolbox_auto_start = false;
    bool disable_toolbox_auto_start_for_rest_mode = false;
    bool display_tids = false;
    bool debug_app_jb_msg = false;
    bool debug_legacy_cmd_server = false;
    bool etaHEN_game_opts = true;
    bool auto_eject_disc = false;
    bool overlay_gpu = true;
    bool overlay_cpu = true;
	bool overlay_ram = true;
    bool overlay_fps = false;
    bool overlay_ip = false;
    bool overlay_kstuff = false;
    bool overlay_kstuff_active = false;
    bool enable_kstuff_on_close = false;
    bool pause_kstuff_on_open = false;
    bool all_cpu_usage = false;
    int start_option = 0;
    int trial_soft_expire_time = 0;
    int kit_panel_info = 0;
    int kstuff_pause_opt = NOT_PAUSED;
    uint64_t rest_delay_seconds = 0;
    bool enable_fan_speed = false;
    int fan_threshold = 77;
    int pause_kstuff_on_open_secs = 0;
    
    // Shortcuts
    Cheats_Shortcut cheats_shortcut_opt = CHEATS_SC_OFF;
    Toolbox_Shortcut toolbox_shortcut_opt = TOOLBOX_SC_OFF;
    Games_Shortcut games_shortcut_opt = GAMES_SC_OFF;
    Kstuff_Shortcut kstuff_shortcut_opt = KSTUFF_SC_OFF;

	//floats for overlays
    float overlay_gpu_x = 10.0f;
    float overlay_gpu_y = 10.0f;

    float overlay_cpu_x = 10.0f;
    float overlay_cpu_y = 35.0f;

    float overlay_ram_x = 10.0f;
    float overlay_ram_y = 60.0f;

    float overlay_fps_x = 10.0f;
    float overlay_fps_y = 85.0f;

	float overlay_ip_x = 10.0f;
	float overlay_ip_y = 110.0f;

    overlay_positions overlay_pos = OVERLAY_POS_TOP_LEFT; //0=top left, 1=top right, 2=bottom left, 3=bottom right
    cheats_repo_source selected_cheats_repo = CHEATS_REPO_ETAHEN;

} etaHENSettings;


extern etaHENSettings global_conf;
typedef struct
{
    char prefix[14];  // "etaHEN_PLUGIN" + null terminator
    char titleID[10]; // 4 uppercase letters, 5 numbers, and a null terminator
    char plugin_version[5];
} CustomPluginHeader;

typedef struct _dirdesc {
    int	dd_fd;		/* file descriptor associated with directory */
    long	dd_loc;		/* offset in current buffer */
    long	dd_size;	/* amount of data returned by getdirentries */
    char* dd_buf;	/* data buffer */
    int	dd_len;		/* size of data buffer */
    long	dd_seek;	/* magic cookie returned by getdirentries */
    long	dd_rewind;	/* magic cookie for rewinding */
    int	dd_flags;	/* flags for readdir */
    struct pthread_mutex* dd_lock;	/* lock */
    struct _telldir* dd_td;
} DIR;

enum Plugin_Options {
    KILL_OR_START,
    ENABLE_OR_DISABLE_AUTO
};

enum GamePadButtons
	{
        None = 0,
		// Token: 0x040000D0 RID: 208
		Left = 1U,
		// Token: 0x040000D1 RID: 209
		Up = 2U,
		// Token: 0x040000D2 RID: 210
		Right = 4U,
		// Token: 0x040000D3 RID: 211
		Down = 8U,
		// Token: 0x040000D4 RID: 212
		Square = 16U,
		// Token: 0x040000D5 RID: 213
		Triangle = 32U,
		// Token: 0x040000D6 RID: 214
		Circle = 64U,
		// Token: 0x040000D7 RID: 215
		Cross = 128U,
		// Token: 0x040000D8 RID: 216
		Start = 256U,
		// Token: 0x040000D9 RID: 217
		Select = 512U,
		// Token: 0x040000DA RID: 218
		Option = 256U,
		// Token: 0x040000DB RID: 219
		L1 = 1024U,
		// Token: 0x040000DC RID: 220
		R1 = 2048U,
		// Token: 0x040000DD RID: 221
		L2 = 4096U,
		// Token: 0x040000DE RID: 222
		R2 = 8192U,
		// Token: 0x040000DF RID: 223
		L3 = 16384U,
		// Token: 0x040000E0 RID: 224
		R3 = 32768U,
		// Token: 0x040000E1 RID: 225
		Enter = 65536U,
		// Token: 0x040000E2 RID: 226
		Back = 131072U,
		// Token: 0x040000E3 RID: 227
		TouchPad = 262144U,
		// Token: 0x040000E4 RID: 228
		Move = 524288U,
		// Token: 0x040000E5 RID: 229
		Intercepted = 2147483648U
    };

struct GamePadData
{
  // Token: 0x040000E6 RID: 230
   bool Skip = false;

  // Token: 0x040000E7 RID: 231
   GamePadButtons Buttons = GamePadButtons(0);

  // Token: 0x040000E8 RID: 232
   GamePadButtons ButtonsPrev = GamePadButtons(0);

  // Token: 0x040000E9 RID: 233
   GamePadButtons ButtonsDown = GamePadButtons(0);

  // Token: 0x040000EA RID: 234
   GamePadButtons ButtonsUp = GamePadButtons(0);

  // Token: 0x040000EB RID: 235
   float AnalogLeftX = 0.0f;

  // Token: 0x040000EC RID: 236
   float AnalogLeftY = 0.0f;

  // Token: 0x040000ED RID: 237
   float AnalogRightX = 0.0f;
  // Token: 0x040000EE RID: 238
   float AnalogRightY = 0.0f;
};

struct ioctl_C0105203_args
{
  void* buffer;
  int size;
  int error;
};

void __syscall();
extern bool is_patches_plugin_running;
// Original function pointer type
typedef int (*DecryptRnpsBundle_t)(uint8_t* data, int offset, int size);

extern "C" DIR * opendir(const char*);
extern "C" struct dirent* readdir(DIR*);
extern "C" int closedir(DIR*);

void notify(const char* text, ...);

extern uint64_t(*GetManifestResourceStream_Original)(uint64_t inst, MonoString* FileName);
extern uint64_t(*GetManifestResourceInternal_Orig)(MonoObject* instance, MonoString* name, int* size, MonoObject& module);
extern  void (*OnShareButton_orig)(MonoObject* data);
extern void (*CaptureScreen_orig_old)(MonoObject * inst, int userId, long deviceId, int capType, MonoObject* capacityInfo);
extern void (*CaptureScreen_orig_new)(MonoObject* inst, int userId, long deviceId, int capType,  MonoString* format, MonoObject* capInfo);
extern int (*LaunchApp_orig)(MonoString* titleId, uint64_t* args, int argsSize, LaunchAppParam *param);
extern MonoImage * react_common_img;

/* =============================== mono utils =============================================================================*/
std::string Mono_to_String(MonoString* str);
std::string GetPropertyValue(MonoObject* element, const char* propertyName);
std::string base64_decode(const std::string &encoded_string);
std::vector<unsigned char> encrypt_decrypt(const unsigned char *data, size_t size, const std::string &key);
void ReloadRNPSApp(const char* title_id);

bool is_valid_plugin(CustomPluginHeader& header);
void generate_plugin_xml(std::string& xml_buffer, bool plugins_xml);
void generate_remote_play_xml(std::string& xml_buffer);
void Patch_Main_thread_Check(MonoImage * image_core);
uint64_t Get_Address_of_Method(MonoImage* Assembly_Image, const char* Name_Space, const char* Class_Name, const char* Method_Name, int Param_Count);
uint64_t Get_Address_of_Method(MonoImage* Assembly_Image, MonoClass* klass, const char* Method_Name, int Param_Count);
uint64_t GetManifestResourceStream_Hook(uint64_t inst, MonoString* FileName);
uint64_t GetManifestResourceInternal_Hook(MonoObject* instance, MonoString* name, int* size, MonoObject& module);
MonoObject* New_Mono_XML_From_String(std::string xml_doc);
bool write_asset(const char* path, const void* start, uint32_t size);
int ini_parser_load(IniParser* parser, const char* filename);
const char* ini_parser_get(IniParser* parser, const char* key, const char* default_value);
bool LoadSettings();
bool SaveSettings();
bool SetVersionString(const char* str);
int SendShelluiNotify();
void Terminate();
bool Start_Kit_Hooks();
extern int (*Orig_AppInstUtilInstallByPackage)(MonoString* uri, MonoString* ex_uri, MonoString* playgo_scenario_id, MonoString* content_id, MonoString* content_name, MonoString* icon_url, uint32_t slot, bool is_playgo_enabled, MonoObject* pkg_info, MonoArray* languages, MonoArray* playgo_scenario_ids, MonoArray* content_ids);

template <typename result>
result Get_Property(MonoClass* Klass, MonoObject* Instance, const char* Property_Name)
{
    if (Klass == 0)
    {
        return (result)0;
    }

    MonoProperty* Prop = mono_class_get_property_from_name(Klass, Property_Name);

    if (Prop == 0)
    {
        return (result)0;
    }

    MonoMethod* Get_Method = mono_property_get_get_method(Prop);

    if (Get_Method == 0)
    {
        return (result)0;
    }

    uint64_t Get_Method_Thunk = (uint64_t)mono_compile_method(Get_Method);

    if (Get_Method_Thunk == 0)
    {
        return (result)0;
    }

    if (Instance != 0)
    {
        result(*Method)(MonoObject* Instance) = decltype(Method)(Get_Method_Thunk);
        return Method(Instance);
    }
    else
    {
        result(*Method)() = decltype(Method)(Get_Method_Thunk);
        return Method();
    }
}

template <typename result>
result Get_Property(MonoImage* Assembly_Image, const char* Namespace, const char* Class_Name, MonoObject* Instance, const char* Property_Name)
{
    return Get_Property<result>(mono_class_from_name(Assembly_Image, Namespace, Class_Name), Instance, Property_Name);
}

template <typename Param>
void Set_Property(MonoClass* Klass, MonoObject* Instance, const char* Property_Name, Param Value)
{
    if (Klass == nullptr)
    {
        return;
    }

    if (Instance == nullptr)
    {
        return;
    }

    MonoProperty* Prop = mono_class_get_property_from_name(Klass, Property_Name);

    if (Prop == nullptr)
    {
        return;
    }

    MonoMethod* Set_Method = mono_property_get_set_method(Prop);

    if (Set_Method == nullptr)
    {
        return;
    }

    uint64_t Set_Method_Thunk = (uint64_t)mono_compile_method(Set_Method);

    if (Set_Method_Thunk == 0)
    {
        return;
    }

    void(*Method)(MonoObject* Instance, Param Value) = decltype(Method)(Set_Method_Thunk);
    Method(Instance, Value);
}

template <typename Param>
void Set_Property_Invoke(MonoClass* Klass, MonoObject* Instance, const char* Property_Name, Param Value)
{
    if (Klass == nullptr)
    {
        return;
    }

    if (Instance == nullptr)
    {
        return;
    }

    MonoProperty* Prop = mono_class_get_property_from_name(Klass, Property_Name);

    if (Prop == nullptr)
    {
        return;
    }

    MonoMethod* Set_Method = mono_property_get_set_method(Prop);

    if (Set_Method == nullptr)
    {
        return;
    }

    mono_runtime_invoke(Set_Method, Instance, (void**)&Value, 0);
}

#define ARRAY_COUNT(arry) sizeof(arry) / sizeof(arry[0])

template <typename result, typename... Args>
result Invoke(MonoImage* Assembly_Image, MonoClass* klass, MonoObject* Instance, const char* Method_Name, Args... args)
{
    void* Argsv[] = { &args... };
    uint64_t ThunkAddress = Get_Address_of_Method(Assembly_Image, klass, Method_Name, ARRAY_COUNT(Argsv));

    if (!ThunkAddress)
    {
        return (result)0;
    }

    if (Instance)
    {
        result(*Method)(MonoObject* Instance, Args... args) = decltype(Method)(ThunkAddress);
        return Method(Instance, args...);
    }
    else //Static Call.
    {
        result(*Method)(Args... args) = decltype(Method)(ThunkAddress);
        return Method(args...);
    }
}


/* ================================= ORIG HOOKED MONO FUNCS ============================================= */
extern int (*oOnPress)(MonoObject* Instance, MonoObject* element, MonoObject* e);
extern int (*oOnPreCreate)(MonoObject* Instance, MonoObject* element);
extern MonoString* (*CxmlUri)(MonoObject* obj,MonoString* uri);
extern bool (*CheckRemotePlayRestriction_Orig)(MonoObject* instance);
extern void (*oTerminate)(void);
extern void (*UpdateImposeStatusFlag_Orig)(MonoObject* scene, MonoObject* frontActiveScene);

extern int (*GetHwSerialNumber)(MonoArray* serial);
extern int (*GetHwModelName)(MonoArray* serial);
extern int (*PupExpirationGetStatus)(PupStatus& status, uint32_t& time);
extern bool (*boot_orig)(MonoString* uri, int opt, MonoString* titleIdForBootAction);
extern bool (*boot_orig_2)(MonoString* uri, int opt);
extern GamePadData (*GetData)(int deviceIndex);
extern void(*CallDecrypt_orig)(unsigned char* bundleData, int bundleOffset, int bundleSize, int* payloadOffset, int* realPayloadSize);
extern MonoString *(*oGetString)(MonoObject *Instance, MonoString *str);
extern void (*createJson)(MonoObject*, MonoObject* array, MonoString* id, MonoString* label, MonoString* actionUrl, MonoString* actionId, MonoString* messageId, MonoObject* subMenu, bool enable);
extern DecryptRnpsBundle_t DecryptRnpsBundle;

extern int (*__sys_regmgr_call)(long, long, int*, int*, long);

/* ================================= HOOKED MONO FUNCS ============================================= */
extern  std::vector<Plugins> plugins_list;
extern  std::vector<Plugins> auto_list;
extern  std::vector<Payloads_Apps> payloads_apps_list, custom_pkg_list;
extern  std::string dec_xml_str;
extern  std::string dec_list_xml_str;
extern  std::string cheats_xml;
extern  std::string UI3_dec;
extern  std::string legacy_dec;
extern  std::string appsystem_dll;
extern  std::string uilib;
extern  std::string Sysinfo;
extern  std::string display_info;
extern  std::string uilib_dll;
extern Payloads_Apps custom_pkg_path;

extern  std::string plugin_xml;
extern  std::string debug_settings_xml;
extern  std::string remote_play_xml;
extern  bool is_game_open;
extern  bool is_current_game_open;
extern MonoImage* pui_img;
extern MonoImage* AppSystem_img;
extern MonoObject* Game;



MonoObject* CreateUIColor(float r, float g, float b, float a);
MonoObject* CreateUIFont(int size, int style, int weight);
MonoObject* CreateLabel(const char* name, float x, float y, const char* text, MonoObject* font, int horzAlign, int vertAlign, float r, float g, float b, float a);
void Widget_Append_Child(MonoObject* widget, MonoObject* child);
MonoObject* New_Object(MonoClass* Klass);
MonoString *GetString_Hook(MonoObject *Instance, MonoString *str);
void UpdateImposeStatusFlag_hook(MonoObject* scene, MonoObject* frontActiveScene);
int OnPress_Hook(MonoObject* Instance, MonoObject* element, MonoObject* e);
int OnPreCreate_Hook(MonoObject* Instance, MonoObject* element);
MonoImage * getDLLimage(const char* dll_file);
MonoString* CxmlUri_Hook(MonoObject* obj, MonoString* uri);
MonoObject* InvokeByDesc(MonoClass* p_Class, const char* p_MethodDesc, void* p_Instance, void* p_Args);
void generate_plapps_xml(std::string& new_xml);
bool RemotePlayRestriction_Hook(MonoObject* instance);
MonoString* GetString(MonoString* str);
int ItemzLaunchByUri(const char* uri);
void GoToHome();
void GoToURI(const char* uri);
bool Get_Running_App_TID(std::string& title_id, int& BigAppid);
void generate_cheats_xml(std::string &new_xml, std::string& not_open_tid, bool running_as_debug_settings, bool show_while_not_open);
bool if_exists(const char* path);
extern "C" int sceUserServiceGetInitialUser(int* uid);
bool touch_file(const char *destfile);
void ParseCheatID(const char* tid, int* cheat_id);
void generate_games_xml(std::string &xml_buffer, bool game_shortcut_activated);
int Launch_FG_Game(const char *path, const char* title_id, const char* title);
void CallDecrypt(unsigned char* bundleData, int bundleOffset, int bundleSize,  int* payloadOffset, int* realPayloadSize);
bool uri_boot_hook(MonoString* uri, int opt, MonoString* titleIdForBootAction);
bool uri_boot_hook_2(MonoString* uri, int opt);
GamePadData GetData_hook(int deviceIndex);
void OnShareButton(MonoObject * data);
void CaptureScreen_old(MonoObject*  inst, int userId, long deviceId, int capType, MonoObject* capInfo);
void CaptureScreen_new(MonoObject*  inst, int userId, long deviceId, int capType,  MonoString* format, MonoObject* capInfo);
int DecryptRnpsBundle_Hook(uint8_t* data, int offset, int size);
int rnps_decrypt_block(void* buffer, int size);
int ioctl_hook (int fd, unsigned long request, void *argp);
int LaunchApp(MonoString* titleId, uint64_t* args, int argsSize, LaunchAppParam *param);
int sceRegMgrGetInt_hook(long regid, int* out_val);
void generate_custom_pkg_xml(std::string& xml_buffer);
void createJson_hook(MonoObject* inst, MonoObject* array, MonoString* id, MonoString* label = nullptr, MonoString* actionUrl = nullptr, MonoString* actionId = nullptr, MonoString* messageId = nullptr, MonoObject* subMenu = nullptr, bool enable = true);
/* ================================= HOOKED MONO FUNCS ============================================= */
