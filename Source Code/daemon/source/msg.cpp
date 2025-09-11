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
#include "../../extern/cJSON/cJSON.hpp"
#include "../../extern/tiny-json/tiny-json.hpp"
#include "globalconf.hpp"
#include <atomic>
#include <msg.hpp>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <strings.h>
#include <sys/_pthreadtypes.h>
#include <sys/_stdint.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <ps5/kernel.h>
#include <sys/user.h>
#include <vector>
#include "../../include/ini.h"


typedef struct app_info {
  uint32_t app_id;
  uint64_t unknown1;
  uint32_t app_type;
  char     title_id[10];
  char     unknown2[0x3c];
} app_info_t;


bool if_exists(const char *path);

extern "C" {
#include <sys/mount.h>
pid_t elfldr_spawn(const char* cwd, int stdio, uint8_t* elf, const char* name);
int32_t sceKernelPrepareToSuspendProcess(pid_t pid);
int32_t sceKernelSuspendProcess(pid_t pid);
int32_t sceKernelPrepareToResumeProcess(pid_t pid);
int32_t sceKernelResumeProcess(pid_t pid);
int32_t sceUserServiceInitialize(int32_t *priority);
int32_t sceUserServiceGetForegroundUser(int32_t *new_id);
int32_t scePadSetProcessPrivilege(int32_t num);
int sceKernelMprotect(void *addr, size_t len, int prot);
int sceSystemServiceLoadExec(const char *path, const char *argv[]);

extern uint8_t ps5debug_start[];
extern const unsigned int ps5debug_size;


extern uint8_t shellui_elf_start[];
extern const unsigned int shellui_elf_size;

bool Inject_Toolbox(int pid, uint8_t *elf);
int sceKernelGetAppInfo(int pid, app_info_t *title);
int sceKernelGetProcessName(int pid, char *name);

}


bool is_handler_enabled = true;
using namespace std;
extern pthread_t cheat_thr;
extern struct daemon_settings global_conf;
extern atomic_bool shortcut_activated;

int launchApp(const char *titleId);
int ItemzLaunchByUri(const char *uri);

void etaHEN_log(const char *fmt, ...);

extern "C" int unmount(const char *path, int flags);
bool copyRecursive(const char *source, const char *destination);
bool rmtree(const char *path);
void calculateSize(uint64_t size, char *result);
extern std::string dump_path;
extern std::string dump_title;
extern bool is_dumper_enabled;
extern Dump_Option dump_opt;
extern "C" void sceLncUtilGetAppTitleId(uint32_t appId, char *titleId);
bool GetFileContents(const char *path, char **buffer);
uint64_t calculateTotalSize(const char *path);
bool copyFile(const char *source, const char *destination, bool for_dumper);

void notify(bool show_watermark, const char *text, ...);
bool isProcessAlive(int pid) noexcept;

int DaemonSocket = 0;


struct NonStupidIovec {
  const void *iov_base;
  size_t iov_length;

  constexpr NonStupidIovec(const char *str)
      : iov_base(str), iov_length(__builtin_strlen(str) + 1) {}
  constexpr NonStupidIovec(const char *str, size_t length)
      : iov_base(str), iov_length(length) {}
};

constexpr NonStupidIovec operator""_iov(const char *str, unsigned long len) {
  return {str, len + 1};
}
static bool remount(const char *dev, const char *path, int mnt_flag) {
  NonStupidIovec iov[]{
      "fstype"_iov, "nullfs"_iov, "fspath"_iov, {path},
      "target"_iov, {dev},        "rw"_iov,     {nullptr, 0},
  };
  constexpr size_t iovlen = sizeof(iov) / sizeof(iov[0]);
  return nmount(reinterpret_cast<struct iovec *>(iov), iovlen, mnt_flag) == 0;
}


bool pause_kstuff()
{
  intptr_t sysentvec = 0;
  intptr_t sysentvec_ps4 = 0;

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
     return false;
  case 0x3000000:
  case 0x3100000:
  case 0x3200000:
  case 0x3210000:
    sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xca0cd8;
    sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xca0e50;
    break;
 
  case 0x4000000:
  case 0x4020000:
  case 0x4030000:
  case 0x4500000:
  case 0x4510000:
    sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xd11bb8;
    sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xd11d30;
    break;
 
  case 0x5000000:
  case 0x5020000:
  case 0x5100000:
  case 0x5500000:
    sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xe00be8;
    sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe00d60;
    break;
 
  case 0x6000000:
  case 0x6020000:
  case 0x6500000:
    sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xe210a8;
    sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe21220;
    break;

  case 0x7000000:
  case 0x7010000:
     sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xe21ab8;
     sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe21c30;
     break;
  case 0x7200000:
  case 0x7400000:
  case 0x7600000:
  case 0x7610000:
     sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xe21b78;
     sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe21cf0;
     break;
 
  case 0x8000000:
  case 0x8200000:
  case 0x8400000:
  case 0x8600000:
    sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xe21ca8;
    sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xe21e20;
    break;

  case 0x9000000:
  case 0x9200000:
  case 0x9400000:
  case 0x9600000:
    sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xde0e18;
    sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xde0f90;
    break;

  case 0x10000000:
  case 0x10010000:
  case 0x10200000:
  case 0x10400000:
  case 0x10600000:
    sysentvec     = KERNEL_ADDRESS_DATA_BASE + 0xde0ee8;
    sysentvec_ps4 = KERNEL_ADDRESS_DATA_BASE + 0xde1060;
    break;

  default:
    etaHEN_log("Unsupported firmware");
    return false;
    
  }

  if(kernel_getshort(sysentvec_ps4 + 14) == 0xffff) {
     etaHEN_log("already paused, doing nothing");
  } else {
    kernel_setshort(sysentvec + 14, 0xffff);
    kernel_setshort(sysentvec_ps4 + 14, 0xffff);
}

 return true;
}

void LoadSettings() {
  if (if_exists("/data/etaHEN/config.ini")) {
    IniParser parser;
    if (ini_parser_load( & parser, "/data/etaHEN/config.ini")) {
      const char * libhijacker_cheats_str =
        ini_parser_get( & parser, "Settings.libhijacker_cheats", "0");
      const char * PS5Debug_str =
        ini_parser_get( & parser, "Settings.PS5Debug", "0");
      const char * start_option =
        ini_parser_get( & parser, "Settings.StartOption", "0");
      const char * DPI_v2 = ini_parser_get( & parser, "Settings.DPI_v2", "0");
      const char * auto_eject_disc = ini_parser_get( & parser, "Settings.auto_eject_disc", "0");
      // Check if the std::strings are not nullptr before converting
      global_conf.libhijacker_cheats =
        libhijacker_cheats_str ? atoi(libhijacker_cheats_str) : 0;
      global_conf.PS5Debug = PS5Debug_str ? atoi(PS5Debug_str) : 0;
      global_conf.start_opt =
        start_option ? (StartOpts) atoi(start_option) : NONE;
      global_conf.DPIv2 = DPI_v2 ? atoi(DPI_v2) : 0;
      global_conf.toolbox_auto_start = atoi(ini_parser_get( & parser, "Settings.toolbox_auto_start", "1"));

      global_conf.seconds = atol(ini_parser_get( & parser, "Settings.Rest_Mode_Delay_Seconds", "0"));
      global_conf.debug_app_jb_msg = atoi(ini_parser_get( & parser, "Settings.APP_JB_Debug_Msg", "0"));
      global_conf.auto_eject_disc = auto_eject_disc ? atoi(auto_eject_disc) : 0;

      if (if_exists("/mnt/usb0/toolbox_auto_start"))
        global_conf.toolbox_auto_start = false;
    } else {
      notify(true, "Failed to Read the Settings file");
    }
  } else {
    // Create default config if it doesn't exist
    std::string ini_file(
      "[Settings]\nPS5Debug=0\nFTP=1\nlaunch_itemzflow="
      "0\ndiscord_rpc=0\nAllow_data_in_sandbox=1\nDPI=0\ntoolbox_auto_start=1\nDPI_v2=0\nKlog=0\nAPP_JB_Debug_Msg=0\nauto_eject_disc=0\n");
    int fd = open("/data/etaHEN/config.ini", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd >= 0) {
      write(fd, ini_file.c_str(), ini_file.length());
      close(fd);
      notify(true, "etaHEN config created! @ /data/etaHEN/config.ini");
    }
  }
}


static pid_t find_pid(const char *name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if (sysctl(mib, 4, 0, &buf_size, 0, 0)) {
      perror("sysctl");
      return -1;
  }

  if (!(buf = (uint8_t *)malloc(buf_size))) {
      perror("malloc");
      return -1;
  }

  if (sysctl(mib, 4, buf, &buf_size, 0, 0)) {
      perror("sysctl");
      free(buf);
      return -1;
  }

  for (uint8_t *ptr = buf; ptr < (buf + buf_size);) {
      int ki_structsize = *(int *)ptr;
      pid_t ki_pid = *(pid_t *)&ptr[72];
      char *ki_tdname = (char *)&ptr[447];

      ptr += ki_structsize;
      if (strcmp(ki_tdname, name) == 0) {
          printf("[MATCH] ki_pid: %d, ki_tdname: %s\n", ki_pid, ki_tdname);
          pid = ki_pid;
          break;
      }
  }

  free(buf);
  return pid;
}


int networkListen(const char *soc_path) {
  struct sockaddr_un server;
  unlink(soc_path);
  etaHEN_log("[Daemon] Deleted Socket...");
  int s = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s < 0) {
    etaHEN_log("[Daemon] Socket failed! %s", strerror(errno));
    return INVAIL;
  }

  memset(&server, 0, sizeof(server));
  server.sun_family = AF_UNIX;
  strcpy(server.sun_path, soc_path);

  int r = bind(s, (struct sockaddr *)&server, SUN_LEN(&server));
  if (r < 0) {
    etaHEN_log("[Daemon] Bind failed! %s", strerror(errno));
    return INVAIL;
  }

  //etaHEN_log("Socket has name %s", server.sun_path);

  r = listen(s, 100);
  if (r < 0) {
    etaHEN_log("[Daemon] listen failed! %s", strerror(errno));
    return INVAIL;
  }

  return s;
}

int networkAccept(int socket) {
  //touch_file("/system_tmp/IPC_init");
  return accept(socket, 0, 0);
}

int networkReceiveData(int socket, void *buffer, int32_t size) {
  int nu = recv(socket, buffer, size, 0);
  etaHEN_log("got %i bytes", nu);
  return nu;
}

int networkSendData(int socket, void *buffer, int32_t size) {
  return send(socket, buffer, size, MSG_NOSIGNAL);
}

int networkSendDebugData(void *buffer, int32_t size) {
  return networkSendData(DaemonSocket, buffer, size);
}

int networkCloseConnection(int socket) { return close(socket); }

int networkCloseDebugConnection() {
  return networkCloseConnection(DaemonSocket);
}

#include <fcntl.h>
// pop -Winfinite-recursion error for this func for clang
#define MB(x) ((size_t)(x) << 20)

#define READ_SIZE 0x1024

bool test_sb_file(const char *filename) {
  if (!filename) {
    etaHEN_log("test_sb_file: filename is null");
    return false;
  }

  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    etaHEN_log("test_sb_file: Failed to open %s", filename);
    return false;
  }

  // Determine the size of the file
  struct stat fileInfo;
  if (fstat(fd, &fileInfo) < 0) {
    etaHEN_log("test_sb_file: Failed to get file size for %s", filename);
    close(fd);
    return false;
  }

  off_t fileSize = fileInfo.st_size;
  char buffer[READ_SIZE];

  // Read start
  if (read(fd, buffer, READ_SIZE) < 0) {
    etaHEN_log("test_sb_file: Failed to read start of %s", filename);
    close(fd);
    return false;
  }

  // Calculate middle, ensuring we don't try to seek beyond the file size
  off_t middlePosition =
      fileSize / 2 > READ_SIZE ? fileSize / 2 - READ_SIZE / 2 : 0;
  if (lseek(fd, middlePosition, SEEK_SET) < 0 ||
      read(fd, buffer, READ_SIZE) < 0) {
    etaHEN_log("test_sb_file: Failed to read middle of %s", filename);
    close(fd);
    return false;
  }

  // Read end
  off_t endPosition = fileSize > READ_SIZE ? fileSize - READ_SIZE : 0;
  if (lseek(fd, endPosition, SEEK_SET) < 0 || read(fd, buffer, READ_SIZE) < 0) {
    etaHEN_log("test_sb_file: Failed to read end of %s", filename);
    close(fd);
    return false;
  }

  close(fd);
  etaHEN_log("test_sb_file: Successfully sampled %s", filename);
  return true;
}
extern "C" int sceSystemServiceKillApp(uint32_t appid, int opt, int method,
                                       int reason);
extern "C" int sceSystemServiceGetAppId(const char *tid);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winfinite-recursion"
bool if_exists(const char *path);

extern std::string dumping_tid;


void reply(int sender_socket, bool error, std::string out_var = "Nothing") {

  std::string inputStr = "{\"res\":" + std::to_string(error ? -1 : 0) +
                         ", \"var\":\"" + out_var + "\"}";

  IPCMessage outputMessage;
  outputMessage.cmd = BREW_RETURN_VALUE;
  outputMessage.error = error ? -1 : 0;
  etaHEN_log("error: %d", outputMessage.error);
  bzero(outputMessage.msg, sizeof(outputMessage.msg));
  if (!inputStr.empty()) {
    strncpy(outputMessage.msg, inputStr.c_str(), sizeof(outputMessage.msg) - 1);
    // Null-terminate the destination array
    outputMessage.msg[sizeof(outputMessage.msg) - 1] = '\0';
  }

  networkSendData(sender_socket, reinterpret_cast<void *>(&outputMessage),
                  sizeof(outputMessage));
}

int get_shellui_pid() {
  int pid = -1;
  size_t NumbOfProcs = 9999;

  for (int j = 0; j <= NumbOfProcs; j++) {
      char tmp_buf[500];
      memset(tmp_buf, 0, sizeof(tmp_buf));
      sceKernelGetProcessName(j, tmp_buf);
      if (strcmp("SceShellUI", tmp_buf) == 0) {
          pid = j;
          break;
      }
  }

  return pid == -1 ? find_pid( "SceShellUI") : pid;
}

extern "C" {
  struct proc* get_proc_by_pid(pid_t pid);
  uintptr_t set_proc_authid(pid_t pid, uintptr_t new_authid)
{
    struct proc* proc = get_proc_by_pid(getpid());

    if (proc)
    {
        //
        // Read from kernel
        //
        uintptr_t authid = 0;
        kernel_copyout((uintptr_t) proc->p_ucred + 0x58, &authid, sizeof(uintptr_t));
        kernel_copyin(&new_authid, (uintptr_t) proc->p_ucred + 0x58, sizeof(uintptr_t));

        free(proc);

        return authid;
    }

    return 0;
}
  int sceKernelTerminateProcess(int pid, int *ret);
}

void ForceKillProc(int pid) {
  if (pid < 0) {
    etaHEN_log("Invalid PID: %d", pid);
    return;
  }
  
  #define DECID_AUTH_ID 0x4800000000000022 // required for killing with sceKernelTerminateProcess / sys_proc_term  syscall
  uintptr_t authid = set_proc_authid(getpid(), DECID_AUTH_ID );

  int ret = 0;
  if (sceKernelTerminateProcess(pid, &ret) != 0) {
    etaHEN_log("Failed to terminate process with PID: %d, error: %d", pid, ret);
  } else {
    etaHEN_log("Successfully terminated process with PID: %d", pid);
  }

  set_proc_authid(getpid(), authid); // Restore original authid
}

bool cmd_enable_toolbox(){
    int wait = 0;
    char buz[100] = {0};
    if(sceKernelMprotect(&buz[0], 100, 0x7) == 0){
        if(pause_kstuff()){
            etaHEN_log("Paused kstuff...");
            touch_file("/system_tmp/kstuff_paused");
        }
    }

    etaHEN_log("Activating toolbox...");
    if (if_exists("/system_tmp/util_first_boot")) {
      LoadSettings();
      etaHEN_log("sleeping for %llu", global_conf.seconds);
      sleep(global_conf.seconds);
    }

    notify(true, "Loading the etaHEN ToolBox...");

    int pid = get_shellui_pid();
    if (pid < 0) {
      notify(true, "Failed to get shellui pid");
      return false;
    }

    if (!Inject_Toolbox(pid, shellui_elf_start)) {
      ForceKillProc(pid);
      notify(true, "Failed to inject toolbox");
      return false;
    }

    while (!if_exists("/system_tmp/toolbox_online")) {
      etaHEN_log("waiting for toolbox to start");
      sleep(1);
      if(++wait >= 15){
        ForceKillProc(pid);
        notify(true, "Failed to load the etaHEN toolbox");
        return false;
      }
    }
    unlink("/system_tmp/toolbox_online");

    return true;
}
void handleIPC(struct clientArgs *client, std::string &inputStr,
               DaemonCommands command) {

  constexpr uint32_t MAX_TOKENS = 256;
  json_t pool[MAX_TOKENS]{};
  int sender_app = client->socket;

  struct stat buffer;
  std::string path_buf, path_buf2, json_path;
  const char *path = nullptr, *dest = nullptr;
  char size_buf[0x255];
  bool last_ipc_error = false;

  std::string out_var = "Nothing"; // default send var

  etaHEN_log("Received IPC command 0x%X", command);

  json_t const *my_json =
      inputStr.empty()
          ? NULL
          : json_create((char *)inputStr.c_str(), pool, MAX_TOKENS);
  if (!my_json) {
    etaHEN_log("Error parsing JSON");
    notify(true, "Error parsing JSON");
    reply(sender_app, true);
    return;
  }

  switch (command) {
  case BREW_TEST_CONNECTION: {
    reply(sender_app, false, out_var);
    break;
  }
  case BREW_ENABLE_TOOLBOX: {
    if(cmd_enable_toolbox()){
        reply(sender_app, false);
    } else {
        reply(sender_app, true);
    }
    break;
  }
  case BREW_LAST_RET: {
    reply(sender_app, last_ipc_error, last_ipc_error ? "1" : "0");
    break;
  }
  case BREW_DECRYPT_DIR: {

    reply(sender_app, false);

    launchApp(dumping_tid.c_str());

    std::string dump_path =
        std::string(json_getPropertyValue(my_json, "dest_path"));
    std::string sandbox_dir =
        std::string(json_getPropertyValue(my_json, "src_path"));
    etaHEN_log("Decrypt to %s", dump_path.c_str());
    mkdir(dump_path.c_str(), 0777);
    notify(false, "Attempting to decrypt %s -> %s", sandbox_dir.c_str(),
           dump_path.c_str());
    sleep(6);
    last_ipc_error = !decrypt_dir(sandbox_dir, dump_path);
    mkdir("/data/decryption_done.log", 0777);

    launchApp("DUMP00000");

    break;
  }
  case BREW_INSTALL_THE_STORE: {

    int rv = sceAppInstUtilInitialize();
    if (rv != 0) {
      etaHEN_log("Store 3: Failed to initialize libSceAppInstUtil.sprx");
      notify(true, "Store 3: Failed to initialize libSceAppInstUtil.sprx");
      reply(sender_app, true);
      break;
    }

    PlayGoInfo arg3;
    SceAppInstallPkgInfo pkg_info;
    (void)memset(&arg3, 0, sizeof(arg3));

    for (size_t i = 0; i < NUM_LANGUAGES; i++) {
      strncpy(arg3.languages[i], "", sizeof(language_t) - 1);
    }

    for (size_t i = 0; i < NUM_IDS; i++) {
      strncpy(arg3.playgo_scenario_ids[i], "",
              sizeof(playgo_scenario_id_t) - 1);
      strncpy(*arg3.content_ids, "", sizeof(content_id_t) - 1);
    }

    MetaInfo arg1 = {.uri = "https://pkg-zone.com/update/Store-R2-PS5.pkg",
                      .ex_uri = "",
                      .playgo_scenario_id = "",
                      .content_id = "",
                      .content_name = "The Homebrew Store",
                      .icon_url = ""};

    int num = sceAppInstUtilInstallByPackage(&arg1, &pkg_info, &arg3);
    if (num == 0) {
      notify(true, "the Store is now downloading");
    } else {
      notify(true,
             "An error has occurred while trying to download the Store PKG "
             "(error: 0x%X), Check your internet connection and try again",
             num);
      reply(sender_app, true);
      break;
    }
    reply(sender_app, false);
    break;
  }
  case BREW_ACTIVATE_DUMPER: {

    dump_path = std::string(json_getPropertyValue(my_json, "dump_path"));
    dump_opt =
        (Dump_Option)json_getInteger(json_getProperty(my_json, "dump_opt"));
    dump_title = std::string(json_getPropertyValue(my_json, "dump_title"));
    reply(sender_app, false);
    is_dumper_enabled = true;
    break;
  }
  case BREW_TESTKIT_CHECK: {
    reply(sender_app, !if_exists("/system/priv/lib/libSceDeci5Ttyp.sprx"));
    break;
  }
  case BREW_REMOUNT_FOLDER:
    path_buf = std::string(json_getPropertyValue(my_json, "mount_dest"));
    path_buf2 = std::string(json_getPropertyValue(my_json, "mount_src"));
    json_path = path_buf + "/sce_sys/param.json";
    etaHEN_log("change dir selected, %s", path_buf2.c_str());

    if(path_buf.rfind("/user") == std::string::npos && path_buf.length() <= strlen("/system_ex/app/")) {
      notify(true, "Invalid path of size %d", path_buf.length());
      reply(sender_app, true);
      break;
    }

    mkdir(path_buf.c_str(), 0777);

    if (if_exists(json_path.c_str())) {
      etaHEN_log("param.json exists, trying to unmount");
      int retries = 0;
      do {
        if (retries == 0)
          etaHEN_log("unmounting .....");
        else
          etaHEN_log("retrying attempt unmounting %d | prev. error %s", retries, strerror(errno));

        if (retries >= 20) {
          notify(true, "Failed to unmount | error %s",
                 strerror(errno));
          reply(sender_app, true);
          break;
        }
        retries++;

      } while (unmount(path_buf.c_str(), MNT_FORCE) < 0);
    }

    if (!remount(path_buf2.c_str(), path_buf.c_str(), MNT_FORCE)) {
      if (errno == EBADF || errno == EPERM ||
          errno == EIO) { // if anyone repots a game not mounting til the 2nd
                          // time look at this
        etaHEN_log("trying to unmount");
        unmount(path_buf.c_str(), MNT_FORCE);
      }
      if (!remount(path_buf2.c_str(), path_buf.c_str(), MNT_UPDATE)) {
        notify(true, "remount error: %s\nPath: %s", strerror(errno),
               path_buf2.c_str());
        etaHEN_log("remount error: %s Path: %s", strerror(errno),
                   path_buf2.c_str());
        reply(sender_app, true);
        break;
      } 
    }

    reply(sender_app, false);
    break;
  case BREW_STAT_CMD: {
    path = json_getPropertyValue(my_json, "path");
    if (stat(path, &buffer) == 0) {
      snprintf(size_buf, sizeof(size_buf), "%ld", buffer.st_size);
      etaHEN_log("%s exists | size %s", path, size_buf);
      reply(sender_app, false, size_buf);
    } else {
      etaHEN_log("error for %s | %s", path, strerror(errno));
      reply(sender_app, true);
    }
    break;
  }
  case BREW_CALC_DIR_SIZE: {
    uint64_t size = calculateTotalSize(json_getPropertyValue(my_json, "path"));
    snprintf(size_buf, sizeof(size_buf), "%lu", size);
    etaHEN_log("size %lu", size_buf);
    reply(sender_app, false, size_buf);
    break;
  }
  case BREW_COPY_FILE: {
    path = json_getPropertyValue(my_json, "path");
    dest = json_getPropertyValue(my_json, "dest");
    if (copyFile(path, dest, false)) {
      reply(sender_app, false);
    } else {
      etaHEN_log("error for %s | %s", path, strerror(errno));
      reply(sender_app, true);
    }
    break;
  }
  case BREW_COPY_DIR: {
    path = json_getPropertyValue(my_json, "path");
    dest = json_getPropertyValue(my_json, "dest");
    snprintf(size_buf, sizeof(size_buf), "%lu", calculateTotalSize(path));
    if (copyRecursive(path, dest)) {
      reply(sender_app, false, size_buf);
    } else {
      etaHEN_log("error for %s | %s", path, strerror(errno));
      reply(sender_app, true);
    }
    break;
  }
  case BREW_DELETE_DIR: {
    path = json_getPropertyValue(my_json, "path");
    if (rmtree(path)) {
      reply(sender_app, false);
    } else {
      reply(sender_app, true);
    }
    break;
  }
  case BREW_TEST_SB_FILE: {
    reply(sender_app, !test_sb_file(json_getPropertyValue(my_json, "path")));
    break;
  }
  case BREW_DAEMON_PID: {
    snprintf(size_buf, sizeof(size_buf), "%d", getpid());
    reply(sender_app, false, size_buf);
    break;
  }
  case BREW_TOGGLE_PS5DEBUG:{
    OrbisKernelSwVersion sys_ver;
    sceKernelGetProsperoSystemSwVersion(&sys_ver);
    bool not_supported = ((sys_ver.version >> 16) < 0x300 || (sys_ver.version >> 16) >= 0x800);
    if(not_supported){
      notify(true, "PS5Debug is not supported on this firmware");
      reply(sender_app, true);
      break;
    }

    if(global_conf.PS5Debug){
      notify(true, "PS5Debug is Running\nPS5Debug requires a restart to disable");
      reply(sender_app, false);
      break;
    }

    notify(true, "Loading PS5Debug...");
    if (elfldr_spawn("/", STDOUT_FILENO, ps5debug_start, "PS5Debug") < 0) {
        notify(true, "PS5Debug is starting\nWait for the PS5Debug welcome message");
        global_conf.PS5Debug = true;
    }

    reply(sender_app, false);

    break;
  }
  case BREW_UNUSED_1: {
    // This command is not used anymore but kept for backwards compatibility
    notify(true, "This command is not used anymore, Update itemzflow");
    reply(sender_app, true);
    break;
  }
  case BREW_KILL_DAEMON:{
    is_handler_enabled = false;
    exit(1337);
    kill(getpid(), SIGKILL);
    reply(sender_app, false);
    break;
  }
  case BREW_FORCE_KILL_PID: {
    int pid = json_getInteger(json_getProperty(my_json, "pid"));
    if (pid < 0) {
      etaHEN_log("Invalid PID: %d", pid);
      reply(sender_app, true);
      break;
    }

    ForceKillProc(pid);
    reply(sender_app, false);
    break;
  }
  case BREW_RELOAD_SETTINGS: {
    LoadSettings();
 //   notify(true, "Reloaded Settings");
    reply(sender_app, false);
    break;
  }
  default:
    notify(true, "Unknown command 0x%X", command);
    reply(sender_app, true);
    break;
  }
}

void *ipc_client(void *args) {
  struct clientArgs *client = (struct clientArgs *)args;
  etaHEN_log("[Daemon IPC] Thread created for Socket %i", client->socket);

  uint32_t readSize = 0;
  IPCMessage ipcMessage; // Create an IPCMessage struct to store received data

  while ((readSize = networkReceiveData(client->socket,
                                        reinterpret_cast<void *>(&ipcMessage),
                                        sizeof(ipcMessage))) > 0) {
    if (ipcMessage.magic == 0xDEADBABE) {
      // Handle IPCMessage
      std::string message = ipcMessage.msg; // Retrieve the string message
      handleIPC(client, message, ipcMessage.cmd);
    } else {
      etaHEN_log("[Daemon IPC][client %i] Invalid magic number",
                 client->cl_nmb);
      ipcMessage.error = -1;
      networkSendData(client->socket, reinterpret_cast<void *>(&ipcMessage),
                      sizeof(ipcMessage));
    }
  }

  etaHEN_log(
      "[Daemon IPC][client %i] IPC Connection disconnected, Shutting down ...",
      client->cl_nmb);

  networkCloseConnection(client->socket);
  delete client;
  pthread_exit(NULL);

  return NULL;
}

void *IPC_loop(void *args) {
  // Listen on port
  int serverSocket = networkListen(CRIT_IPC_SOC);
  if (serverSocket < 0) {
    etaHEN_log("[Daemon IPC] networkListen error %s", strerror(errno));
    return nullptr;
  }

  // Keep accepting client connections
  int cli_new = 0;
  while (true) {
    // Accept a client connection
    int clientSocket = networkAccept(serverSocket);
    if (clientSocket < 0) {
      etaHEN_log("[Daemon IPC] networkAccept error %s", strerror(errno));
      break; // Breaking out of the loop on error to cleanup
    }

    etaHEN_log("[Daemon IPC] Connection Accepted");
    etaHEN_log("[Daemon IPC] cl_nmb %i", cli_new);

    // Build data to send to thread
    auto clientParams = new clientArgs();
    clientParams->ip = "localhost";
    clientParams->socket = clientSocket;
    clientParams->cl_nmb = cli_new;

    etaHEN_log("[Daemon IPC] clientParams->cl_nmb %i", clientParams->cl_nmb);
    pthread_t ipc_thread;
    pthread_create(&ipc_thread, NULL, ipc_client, clientParams);
    cli_new++;
  }

  // Cleanup
  networkCloseConnection(serverSocket);
  return nullptr;
}
