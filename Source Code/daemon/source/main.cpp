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

// Include files
#include <cstdint>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>

// System includes
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysctl.h>
#include <sys/_pthreadtypes.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <ps5/klog.h>

// Project includes
#include "../../include/backtrace.hpp"
#include "globalconf.hpp"
#include "launcher.hpp"
#include "ipc.hpp"

#define MSG_NOSIGNAL 0x20000 /* do not generate SIGPIPE on EOF. */
pthread_t cheat_thr = nullptr;

#define PAD_BUTTON_OPTIONS	0x00000008

// Structure definitions
typedef struct {
  unsigned int size;
  uint32_t userId;
} SceShellUIUtilLaunchByUriParam;

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

// External C declarations
extern "C" {
    int sceKernelSendNotificationRequest(int32_t device,
        OrbisNotificationRequest *req,
        size_t size, int32_t blocking);
    int sceSystemServiceNavigateToGoHome(void);
    int sceUserServiceGetUserName(const int userId, char *userName, const size_t size);
    uint64_t sceKernelGetProcessTime();
    int sceSystemServiceGetAppId(const char *title_id);
    int scePadSetProcessPrivilege(int priv);
    pid_t elfldr_spawn(const char* cwd, int stdio, uint8_t* elf, const char* name);
    int sceUserServiceGetForegroundUser(int *userId);
    int sceLncUtilLaunchApp(const char *tid, const char *argv[], LncAppParam *param);
    uint32_t _sceApplicationGetAppId(int pid, uint32_t *appId);
    uint32_t sceLncUtilKillApp(uint32_t appId);
    int sceSysmoduleLoadModuleInternal(int id);
    int sceNetCtlInit();
    int sceUserServiceInitialize(const int *);
    int sceKernelLoadStartModule(const char *name, size_t argc, const void *argv, 
                                uint32_t flags, void *unknown, int *result);
    int sceKernelDlsym(uint32_t lib, const char *name, void **fun);
    //int sceShellUIUtilInitialize(void);
    int scePadClose(int handle);
    //int sceShellUIUtilLaunchByUri(const char *uri, SceShellUIUtilLaunchByUriParam *Param);
    int sceSystemStateMgrEnterStandby(void);
    int sceKernelMprotect(void *addr, size_t len, int prot);
    ssize_t _read(int, void *, size_t);
    int sceKernelGetProcessName(int pid, char *name);
    void free(void *);
    int sceShellCoreUtilRequestEjectDevice(const char *path);

    // PayloadAPI definitions
    #include <ps5/payload.h>
    
    // External data
    extern uint8_t ps5debug_start[];
    extern const unsigned int ps5debug_size;
    int sceNotificationSend(int userId, bool isLogged, const char* payload);

}

// Global variables
uint64_t p_syscall = 0;
char _end[1] = {};
struct daemon_settings global_conf;
int fd = -1;
pthread_t klog_srv = nullptr;
static constexpr auto DEFAULT_PRIORITY = 256;
uintptr_t kernel_base = 0;

// Function declarations
void etaHEN_log(const char *fmt, ...);
void notify(bool show_watermark, const char *text, ...);
bool touch_file(const char *destfile);
int launchApp(const char *titleId);
int get_ip_address(char *ip_address);
bool sceKernelIsTestKit();
int ItemzLaunchByUri(const char *uri);
bool enable_toolbox();
void sig_handler(int signo);

bool if_exists(const char *path);
void *fifo_and_dumper_thread(void *args);
void *Play_time_thread(void *args) noexcept;
void patch_checker();
int elfldr_raise_privileges(pid_t pid);
extern void makenewapp();

// External function declarations
extern void *start_ftp(void *);
extern void *IPC_loop(void *);
extern bool is_handler_enabled;

// Whitelist for PSIDs
const char *whitelisted_psids[] = {
    "b345df7d4c77618d40f19a90e438ad87", 
    "ab535275b7196e7e7d43f4f9e7806724",
    "d376c7780b960e5182d326ba3aa2d7a3", 
    "a8d89ad976b5cb912837ad29b0cc4610",      
    "177e09480b40816a1caca5151565daa5"
};

// Function implementations
void etaHEN_log(const char *fmt, ...) {
    char msg[0x1000];
    va_list args;
    va_start(args, fmt);
    __builtin_vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    // Append newline at the end
    size_t msg_len = strlen(msg);
    if (msg_len < sizeof(msg) - 1) {
        msg[msg_len] = '\n';
        msg[msg_len + 1] = '\0';
    } else {
        msg[sizeof(msg) - 2] = '\n';
        msg[sizeof(msg) - 1] = '\0';
    }

    printf("[etaHEN]: %s", msg); // msg already includes a newline
    klog_printf("%s", msg); // msg already includes a newline

    int fd = open("/data/etaHEN/etaHEN.log", O_WRONLY | O_CREAT | O_APPEND, 0777);
    if (fd < 0) {
        return;
    }
    write(fd, msg, strlen(msg));
    close(fd);
}

bool touch_file(const char *destfile) {
    static constexpr int FLAGS = 0777;
    int fd = open(destfile, O_WRONLY | O_CREAT | O_TRUNC, FLAGS);
    if (fd > 0) {
        close(fd);
        return true;
    }
    return false;
}

int launchApp(const char *titleId) {
    int id = 0;

    uint32_t res = sceUserServiceGetForegroundUser(&id);
    if (res != 0) {
        printf("sceUserServiceGetForegroundUser failed: 0x%x", res);
        return res;
    }
    etaHEN_log("[LA] user id %u", id);

    // the thread will clean this up
    Flag flag = Flag_None;
    LncAppParam param{sizeof(LncAppParam), id, 0, 0, flag};

    puts("calling sceLncUtilLaunchApp");
    int err = sceLncUtilLaunchApp(titleId, nullptr, &param);
    etaHEN_log("sceLncUtilLaunchApp returned 0x%x", (uint32_t)err);
    if (err >= 0) {
        return err;
    }
    
    switch ((uint32_t)err) {
    case SCE_LNC_UTIL_ERROR_ALREADY_RUNNING:
        etaHEN_log("app %s is already running", titleId);
        break;
    case SCE_LNC_ERROR_APP_NOT_FOUND:
        etaHEN_log("app %s not found", titleId);
        notify(true, "app %s not found", titleId);
        break;
    default:
        etaHEN_log("[LA] unknown error 0x%x", (uint32_t)err);
        // notify(true, "unknown error 0x%llx", (uint32_t)err);
        break;
    }
    return err;
}

void sig_handler(int signo) {
    if(!is_handler_enabled){
        etaHEN_log("Signal handler is disabled, ignoring signal %d", signo);
        return;
    }
    notify(true,
          "etaHEN has crashed ...\n\nPlease send /data/etaHEN/etaHEN_crash.log "
          "to the PKG-Zone discord: https://discord.gg/BduZHudWGj");
    etaHEN_log("main etaHEN has crashed ...");
    //printBacktraceForCrash();
    exit(1);
}

bool sceKernelIsTestKit() {
    uint8_t s_PsId[16] = {0};

    size_t v2 = 16;
    if (sysctlbyname("machdep.openpsid_for_sys", &s_PsId, &v2, 0, 0) < 0) {
        printf("sceKernelGetOpenPsIdForSystem failed\n");
        return true;
    }

    char psid_buf[255] = {0};

    for (int i = 0; i < 16; i++) {
        snprintf(psid_buf + strlen(psid_buf), 255 - strlen(psid_buf), "%02x",
                s_PsId[i]);
    }

    for (int i = 0; i < sizeof(whitelisted_psids) / sizeof(whitelisted_psids[0]);
        i++) {
        if (strcmp(psid_buf, whitelisted_psids[i]) == 0) {
            return false; // report not testkit if is whitelisted
        }
    }

    return if_exists("/system/priv/lib/libSceDeci5Ttyp.sprx");
}


int (*sceShellUIUtilInitialize)(void) = nullptr;
int (*sceShellUIUtilLaunchByUri)(const char* uri, SceShellUIUtilLaunchByUriParam* Param) = nullptr;
#define KERNEL_DLSYM(handle, sym) \
    (*(void**)&sym=(void*)kernel_dynlib_dlsym(-1, handle, #sym))
int ItemzLaunchByUri(const char* uri) {
    int libcmi = -1;

    if (!uri)
        return -1;

    if ((libcmi = sceKernelLoadStartModule("/system_ex/common_ex/lib/libSceShellUIUtil.sprx", 0, 0, 0, 0, 0)) < 0 || libcmi < 0)
        return -1;

    KERNEL_DLSYM(libcmi, sceShellUIUtilInitialize);
    KERNEL_DLSYM(libcmi, sceShellUIUtilLaunchByUri);
    if (!sceShellUIUtilInitialize || !sceShellUIUtilLaunchByUri) {
        etaHEN_log("failed to load libSceShellUIUtil.sprx");
        return -1;
    }
    //
    SceShellUIUtilLaunchByUriParam Param;
    Param.size = sizeof(SceShellUIUtilLaunchByUriParam);
    sceShellUIUtilInitialize();
    sceUserServiceGetForegroundUser((int*)&Param.userId); // DONT CARE

    return sceShellUIUtilLaunchByUri(uri, &Param);
}

bool cmd_enable_toolbox();
void LoadSettings();
bool is_800 = false;
int main() {
    char buz[255];
    pthread_t fifo_thr = nullptr;
    pthread_t pt_thr = nullptr;
    pthread_t msg_thr = nullptr;
    
    sceNetCtlInit();
    sceUserServiceInitialize(&DEFAULT_PRIORITY);
    puts("daemon entered");
    
    OrbisKernelSwVersion sys_ver;
    sceKernelGetProsperoSystemSwVersion(&sys_ver);
    int fw_ver = (sys_ver.version >> 16);

    // Set up signal handlers
    struct sigaction new_SIG_action;
    new_SIG_action.sa_handler = sig_handler;
    sigemptyset(&new_SIG_action.sa_mask);
    new_SIG_action.sa_flags = 0;

    for (int i = 0; i < 12; i++)
        sigaction(i, &new_SIG_action, NULL);

    unlink("/data/etaHEN/etaHEN.log");
    unlink("/data/etaHEN/etaHEN_crash.log");

    payload_args_t *args = payload_get_args();
    kernel_base = args->kdata_base_addr;

    etaHEN_log("=========== starting etaHEN (0x%X) ... ===========", fw_ver);
    bool has_hv_bypass = (sceKernelMprotect(&buz[0], 100, 0x7) == 0);
    bool is_lite = if_exists("/system_tmp/lite_mode");
    bool toolbox_only = (fw_ver >= 0x10000);
    bool no_ps5debug = (fw_ver >= 0x800);
    is_800 = (fw_ver >= 0x800);


    LoadSettings();

#if 0
    // Check if running on a test kit
    if (sceKernelIsTestKit()) {
        etaHEN_log("no NO NO");
        return -1;
        raise(SIGSEGV);
    }
#endif

    // Start threads
    get_ip_address(&buz[0]);
    pthread_create(&fifo_thr, nullptr, fifo_and_dumper_thread, nullptr);
    pthread_create(&pt_thr, nullptr, Play_time_thread, nullptr);
    pthread_create(&msg_thr, nullptr, IPC_loop, nullptr);

    etaHEN_log("is toolbox only: %s | ver: %x", toolbox_only ? "Yes" : "No", sys_ver.version);
    // Initialize toolbox if needed
    if (global_conf.toolbox_auto_start) {
        cmd_enable_toolbox();
    }
    else if (!global_conf.toolbox_auto_start) {
        notify(true, "the etaHEN Toolbox auto start is disabled in the config.ini\n\n"
                    "If you want to re-enable the toolbox go to ItemzFlow's settings menu");
    }

    // Load PS5Debug if needed
    if (global_conf.PS5Debug && !no_ps5debug && !has_hv_bypass && !is_lite) {
        if (!elfldr_spawn("/", STDOUT_FILENO, ps5debug_start, "ps5debug"))
            notify(true, "Failed to load PS5Debug");
    }

     const char json_payload[] =
     "{\n"
     "  \"rawData\": {\n"
     "    \"viewTemplateType\": \"InteractiveToastTemplateB\",\n"
     "    \"channelType\": \"Downloads\",\n"
     "    \"useCaseId\": \"IDC\",\n"
     "    \"toastOverwriteType\": \"No\",\n"
     "    \"isImmediate\": true,\n"
     "    \"priority\": 100,\n"
     "    \"viewData\": {\n"
     "      \"icon\": {\n"
     "        \"type\": \"Url\",\n"
     "        \"parameters\": {\n"
     "          \"url\": \"/user/data/etaHEN/etahen.png\"\n"
     "        }\n"
     "      },\n"
     "      \"message\": {\n"
     "        \"body\": \"etaHEN 2.5B AIO HEN By LM\"\n"
     "      },\n"
     "      \"subMessage\": {\n"
     "        \"body\": \"Welcome to etaHEN\"\n"
     "      },\n"
     "      \"actions\": [\n"
     "        {\n"
     "          \"actionName\": \"Go to the etaHEN Toolbox\",\n"
     "          \"actionType\": \"DeepLink\",\n"
     "          \"defaultFocus\": true,\n"
     "          \"parameters\": {\n"
     "            \"actionUrl\": \"pssettings:play?function=debug_settings\"\n"
     "          }\n"
     "        }\n"
     "      ]\n"
     "    },\n"
     "    \"platformViews\": {\n"
     "      \"previewDisabled\": {\n"
     "        \"viewData\": {\n"
     "          \"icon\": {\n"
     "            \"type\": \"Predefined\",\n"
     "            \"parameters\": {\n"
     "              \"icon\": \"download\"\n"
     "            }\n"
     "          },\n"
     "          \"message\": {\n"
     "            \"body\": \"etaHEN Running\"\n"
     "          }\n"
     "        }\n"
     "      }\n"
     "    }\n"
     "  },\n"
     "  \"createdDateTime\": \"2025-12-14T03:14:51.473Z\",\n"
     "  \"localNotificationId\": \"588193127\"\n"
     "}";
	sceNotificationSend(0xFE, true, &json_payload[0]);


    etaHEN_log("StartUp thread created!! - welcome to etaHEN");

    // Launch the appropriate app based on configuration
    const char *URI = nullptr;
    switch (global_conf.start_opt) {
    case HOME_MENU: {
        URI = "pshomeui:navigateToHome?bootCondition=psButton";
        break;
    }
    case TOOLBOX: {
        if (global_conf.toolbox_auto_start)
            URI = "pssettings:play?mode=settings&function=debug_settings";
        else
            URI = "pshomeui:navigateToHome?bootCondition=psButton";
        break;
    }
    case SETTINGS: {
        URI = "pssettings:play?mode=settings";
        break;
    }
    case ITEMZFLOW: {
        launchApp("ITEM00001");
        break;
    }
    default:
        etaHEN_log("unknown opt %d", global_conf.start_opt);
        break;
    }

    if (URI && !is_lite)
        etaHEN_log("ret %d", ItemzLaunchByUri(URI));

    if(global_conf.auto_eject_disc){
        sceShellCoreUtilRequestEjectDevice("/dev/cd0");
    }

    unlink("/system_tmp/lite_mode");

    // Main loop to keep the process running
    while (true) {
        pthread_join(msg_thr, NULL);
        pthread_create(&msg_thr, nullptr, IPC_loop, nullptr);
        sleep(1);
    }

    puts("main thread ended");
    return 0;
}
