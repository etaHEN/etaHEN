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

#include "ipc.hpp"
#include "CheatManager.hpp"
#include <cstdint>
#include <hijacker/hijacker.hpp>
#include <sys/_pthreadtypes.h>
#include <unistd.h>

typedef struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    uint32_t app_type;
    char     title_id[10];
    char     unknown2[0x3c];
} app_info_t;

pthread_t cmd_server = 0;

extern "C" {

  #define DEBUG_AUTHID 0x4800000000000006
  #include "faulthandler.h"
  #include "common_utils.h"
  #include <ps5/payload.h>

  void * start_john_elf_loader(void * arg);
  bool StartFTP(void);
  void ShutdownFTP(void);
  void shutdown_klog(void);
  bool start_klog(void);
  void * start_ftp(void * args);
  void * krw_server(void * args);
  int sceKernelGetAppInfo(pid_t pid, app_info_t * info);
  int sceKernelGetProcessName(int pid, char * out);
  int _sceApplicationGetAppId(int pid, uint32_t * appId);
  void * start_j_ftp(void * args);

  struct proc * get_proc_by_pid(pid_t pid);
  //
  // Search process entr on the allproc linked list
  // acquire the "ucred" structure and set it
  uintptr_t set_proc_authid(pid_t pid, uintptr_t new_authid) {
    struct proc * proc = get_proc_by_pid(pid);

    if (proc) {
      //
      // Read from kernel
      //
      uintptr_t authid = 0;
      kernel_copyout((uintptr_t) proc -> p_ucred + 0x58, & authid, sizeof(uintptr_t));
      kernel_copyin( & new_authid, (uintptr_t) proc -> p_ucred + 0x58, sizeof(uintptr_t));

      free(proc);

      return authid;
    }

    return 0;
  }

}

extern bool is_handler_enabled;

util_settings global_conf;
bool startDirectPKGInstaller(bool is_v2);
void shutdownDirectPKGInstaller(bool is_v2);
void start_ip_thread(void);
void* runCommandNControlServer(void*);
void patch_checker(void);
void* IPC_loop(void* args);
bool shellui_patch(void);
void* runDirectPKGInstaller(void* args);

extern atomic_bool no_network_rest_mode_action;
extern pthread_t discordRpcServerThread;
extern pthread_t kernelrw_thread;

jmp_buf g_catch_buf;
uintptr_t kernel_base = 0;
void* __stack_chk_guard = (void*)0xdeadbeef;

bool if_exists(const char* path) {
    struct stat buffer;
    return stat(path, &buffer) == 0;
}

static void cleanup(void) {
    notify(true, "etaHEN utilities daemon has crashed...\n\nAttemping to recover...");

    if (global_conf.FTP)
        ShutdownFTP();

    if (global_conf.discord_rpc)
        pthread_join(discordRpcServerThread, NULL);

    shutdown_klog();
    pthread_join(kernelrw_thread, NULL);

    if (global_conf.DPI)
        shutdownDirectPKGInstaller(false);

    if (global_conf.DPI_v2)
        shutdownDirectPKGInstaller(true);

    exit(1);
}

void __stack_chk_fail(void) {
    puts("Stack smashing detected.");
}

void LoadSettings(void) {
    if (if_exists("/data/etaHEN/config.ini")) {
        IniParser parser;

        if (ini_parser_load(&parser, "/data/etaHEN/config.ini")) {
            const char* FTP_str = ini_parser_get(&parser, "Settings.FTP", "1");
            const char* DPI_str = ini_parser_get(&parser, "Settings.DPI", "0");
            const char* discord_rpc_str = ini_parser_get(&parser, "Settings.discord_rpc", "0");
            const char* allow_data_n_sandbox = ini_parser_get(&parser, "Settings.Allow_data_in_sandbox", "1");
            const char* ftp_dev_access = ini_parser_get(&parser, "Settings.ALLOW_FTP_DEV_ACCESS", "0");
            const char* lite_mode = ini_parser_get(&parser, "Settings.LiteMode", "0");
            const char* DPI_v2 = ini_parser_get(&parser, "Settings.DPI_v2", "0");
            const char* Klog_str = ini_parser_get(&parser, "Settings.Klog", "0");
            const char* toolbox_for_rest = ini_parser_get(&parser, "Settings.disable_toolbox_auto_start_for_rest_mode", "0");\
				const char* legacy_cmd_server_str = ini_parser_get(&parser, "Settings.legacy_cmd_server", "0");

            global_conf.discord_rpc = discord_rpc_str ? atoi(discord_rpc_str) : 0;
            global_conf.allow_data = allow_data_n_sandbox ? atoi(allow_data_n_sandbox) : 0;
            global_conf.has_ftp_dev = ftp_dev_access ? atoi(ftp_dev_access) : 0;
            global_conf.FTP = FTP_str ? atoi(FTP_str) : 0;
            global_conf.DPI = DPI_str ? atoi(DPI_str) : 0;
            global_conf.lite = lite_mode ? atoi(lite_mode) : 0;
            global_conf.DPI_v2 = DPI_v2 ? atoi(DPI_v2) : 0;
            global_conf.toolbox_auto_start = atoi(ini_parser_get(&parser, "Settings.toolbox_auto_start", "1"));
            global_conf.klog = Klog_str ? atoi(Klog_str) : 0;
            global_conf.disable_toolbox_for_rest = toolbox_for_rest ? atoi(toolbox_for_rest) : 0;
			global_conf.legacy_cmd_server = legacy_cmd_server_str ? atoi(legacy_cmd_server_str) : 0;
            
            if (if_exists("/mnt/usb0/toolbox_auto_start"))
                global_conf.toolbox_auto_start = false;
        } else {
            etaHEN_log("Failed to load config.ini");
            notify(true, "Failed to load config.ini");
        }
    }
}
bool patchShellActi();

bool sceKernelIsTestKit() {
    //printf("PSID (%s) Not whitelisted\n", psid_buf);
    return if_exists("/system/priv/lib/libSceDeci5Ttyp.sprx");
}
bool patchShellCoreTEST();
  
int main(void) {
    pthread_t ipc_server = 0, cheat_cache = 0;//, j_ftp = 0;
    char tmp_buf[200];
    
    sceNetCtlInit();
    sceUserServiceInitialize(NULL);
    etaHEN_log("util daemon entered");

    if (setjmp(g_catch_buf) == 0)
        etaHEN_log("jump has been set");
    else
        notify(true, "The Fatal error has been successfully resolved\n\nyou have nothing to worry about");

    etaHEN_log("Registering signal handler...");
    fault_handler_init(cleanup);
    etaHEN_log("   Success!");

    payload_args_t* args = payload_get_args();
    kernel_base = args->kdata_base_addr;
    set_proc_authid(getpid(), DEBUG_AUTHID);


    global_conf.allow_data = true;
    global_conf.DPI = true;
    global_conf.seconds = 0;
    global_conf.FTP = true;
    global_conf.discord_rpc = false;
    global_conf.has_ftp_dev = false;
    global_conf.toolbox_auto_start = true;
    global_conf.DPI_v2 = false;
    global_conf.klog = true;
	global_conf.legacy_cmd_server_exit = false;

    unlink("/data/etaHEN/etaHEN_util_daemon.log");
    unlink("/data/etaHEN/etaHEN_util_crash.log");

    etaHEN_log("=========== starting etaHEN Utilities... ===========");
   // if(!sceKernelIsTestKit())
   //     patchShellCoreTEST();

    LoadSettings();

    if(sceKernelIsTestKit()){
       etaHEN_log("Kit detected, patching acti time...");
       patchShellActi();
    }
    if (global_conf.allow_data) {
        etaHEN_log("Allowing data in sandbox");
        patchShellCore();
        etaHEN_log("Patched shellcore");
    }


    start_ip_thread();
    pthread_create(&ipc_server, NULL, IPC_loop, NULL);

    if (!IniliatizeHTTP()) {
        etaHEN_log("Failed to initialize HTTP lib");
        notify(true, "Failed to initialize the HTTP lib, downloading cheats will not work");
    }

    if (global_conf.toolbox_auto_start && if_exists("/system_tmp/util_first_boot") && !global_conf.lite) {
        etaHEN_log("not First boot detected, activating toolbox");
        patch_checker();
    }

    for (;;) {
        // for rest mode we wait til we can restart everything
        if (global_conf.toolbox_auto_start && get_ip_address(&tmp_buf[0]) < 0) {
            sleep(1);

            bool fail1 = get_ip_address(&tmp_buf[0]) < 0;
            if (!fail1)
                continue;

            sleep(2);

            bool fail2 = get_ip_address(&tmp_buf[0]) < 0;
            if (!fail2)
                continue;

            if (no_network_rest_mode_action) {
                patch_checker();
            }
            continue;
        }
        no_network_rest_mode_action = false;

       // pthread_create(&j_ftp, NULL, start_j_ftp, NULL);   

        if (global_conf.FTP) {
            if (StartFTP())
                etaHEN_log("[Setting enabled] Starting FTP Server...");
        }
        
        if (global_conf.discord_rpc) {
            pthread_create(&discordRpcServerThread, NULL, startDiscordRpcServer, NULL);
        }
        
        if (global_conf.DPI) {
            startDirectPKGInstaller(false);
        }

        if (global_conf.DPI_v2) {
            startDirectPKGInstaller(true);
        }

        if(global_conf.klog){
           etaHEN_log("Starting klog thread...");
           start_klog();
        }
        etaHEN_log("started klog thread...");
        
        pthread_create(&cmd_server, NULL, runCommandNControlServer, NULL);
        etaHEN_log("loading settings...");
        LoadSettings();
        etaHEN_log("done loading settings...");

        etaHEN_log("Caching cheat list...");
        pthread_create(&cheat_cache, NULL, MakeInitialCheatCache, NULL);

        if (global_conf.discord_rpc)
            pthread_join(discordRpcServerThread, NULL);

        pthread_join(cmd_server, NULL);

        if(global_conf.klog)
           shutdown_klog();

        if (global_conf.FTP)
            ShutdownFTP();

        if (global_conf.DPI)
            shutdownDirectPKGInstaller(false);
        
        if (global_conf.DPI_v2)
            shutdownDirectPKGInstaller(true);

        usleep(SLEEP_PERIOD);
    }
    
    return 0;
}
