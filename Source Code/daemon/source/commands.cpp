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

#include <hijacker/hijacker.hpp>
#include <notify.hpp>
#include <util.hpp>
#include <freebsd-helper.h>
#include "hijacker.hpp"
#include "launcher.hpp"
#include "globalconf.hpp"
#include "ipc.hpp"
#include "../../extern/tiny-json/tiny-json.hpp"

#include <atomic>
#include <string>
#include <sstream>
#include <iomanip>
#include <unordered_set>

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/dirent.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <netinet/in.h>

extern "C" {
#include <ps5/kernel.h>
pid_t elfldr_spawn(const char* cwd, int stdio, uint8_t* elf, const char* name);
}

using namespace std;
extern struct daemon_settings global_conf;
// Global variables
std::string dump_path;
std::string dump_title;
std::string dumping_tid;
bool is_dumper_enabled = false;
Dump_Option dump_opt = DUMP_ALL;
atomic_bool cmd_srv_Running = false;
atomic_bool rest_mode_action = false;
extern atomic_bool sce_cmd_srv_Running;
extern atomic_bool ipc_server_2_running;
extern atomic_int ipc_2_ret;
extern pthread_t klog_srv;
extern pthread_t discordRpcServerThread;
extern int shellui_pid_for_comp;
extern int DISCORD_RPC_SERVER_PORT;

// Locks and synchronization objects
pthread_mutex_t jb_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock;

// Command enum
enum Commands : int {
  INVALID_CMD = -1,
  ACTIVE_CMD = 0,
  LAUNCH_CMD,
  PROCLIST_CMD,
  KILL_CMD,
  KILL_APP_CMD,
  JAILBREAK_CMD,
  REMOUNT_FOLDER_CMD,
  ETAHEN_VER_CMD,
  PATCH_LNC_DEBUG_CMD,
  ACTIVATE_DUMPER_CMD,
  TEST_CMD,
  SYMLINK_CMD,
};

// Constants
#define MAX_TID_SIZE 10

// Network structures
typedef struct SceNetEtherAddr {
  uint8_t data[6];
} SceNetEtherAddr;

typedef union SceNetCtlInfo {
  uint32_t device;
  SceNetEtherAddr ether_addr;
  uint32_t mtu;
  uint32_t link;
  SceNetEtherAddr bssid;
  char ssid[33];
  uint32_t wifi_security;
  int32_t rssi_dbm;
  uint8_t rssi_percentage;
  uint8_t channel;
  uint32_t ip_config;
  char dhcp_hostname[256];
  char pppoe_auth_name[128];
  char ip_address[16];
  char netmask[16];
  char default_route[16];
  char primary_dns[16];
  char secondary_dns[16];
  uint32_t http_proxy_config;
  char http_proxy_server[256];
  uint16_t http_proxy_port;
} SceNetCtlInfo;

// App information structure
typedef struct app_info {
  uint32_t app_id;
  uint64_t unknown1;
  uint32_t app_type;
  char title_id[10];
  char unknown2[0x3c];
} app_info_t;

// Function declarations
void etaHEN_log(const char *fmt, ...);
void crash_log(const char *fmt, ...);
bool if_exists(const char *path);
void jailbreak_proc(int pid);
bool isProcessAlive(int pid) noexcept;
bool GetFileContents(const char *path, char **buffer);
void notify(bool show_watermark, const char *text, ...);
bool rmtree(const char *path);
int get_ip_address(char *ip_address);
bool Get_Running_App_TID(std::string& title_id, int& BigAppid);
bool is_whitelisted_app(const std::string &tid);
void *Play_time_thread(void *args) noexcept;
bool enable_toolbox();
bool isUserLoggedIn();
pid_t find_pid(const char *name);
bool Open_Utility_Elf(const char *path, uint8_t **buffer);
void *fifo_and_dumper_thread(void *args) noexcept;
void *runDirectPKGInstaller(void *args);
void *startDiscordRpcServerThread(void *arg);
void Start_Dumper(const char *source, const char *destination, const char *title_id, Dump_Option opt);
void activate_shellui_patch(void);

// External function declarations
extern "C" {
  int sceNetCtlGetInfo(int32_t s, SceNetCtlInfo *b);
  void sceNetCtlTerm(void);
  int sceKernelLoadStartModule(const char *name, size_t argc, const void *argv, uint32_t flags, void *unknown, int *result);
  int sceKernelDlsym(uint32_t lib, const char *name, void **fun);
  int PS5Debug_connect();
  int unmount(const char *dir, int flags);
  int sceLncUtilLaunchApp(const char *tid, const char *argv[], LncAppParam *param);
  int sceSysUtilSendSystemNotificationWithText(int messageType, const char *message);
  int sceNotificationSendById(int userid, bool logged_in, const char *useCaseId, const char *message);
  int sceUserServiceGetForegroundUser(int *userId);
  int sceSystemServiceGetAppIdOfRunningBigApp();
  int sceSystemServiceGetAppTitleId(int app_id, char *title_id);
  int32_t sceKernelPrepareToSuspendProcess(pid_t pid);
  int32_t sceKernelSuspendProcess(pid_t pid);
  int sceSystemServiceGetAppId(const char *title_id);
  int sceUserServiceGetUserName(const int userId, char *userName, const size_t size);
  int sceKernelGetAppInfo(int pid, app_info_t *title);
  int sceKernelGetProcessName(int pid, char *name);
}

// Global variables
char ip_address[20];
int last_BigAppid = -1;
bool shown_dead_noti = false;

// Function implementations
bool if_exists(const char *path) {
  struct stat buffer;
  return stat(path, &buffer) == 0;
}

void jailbreak_proc(int pid) {
  kernel_set_proc_rootdir(pid, kernel_get_root_vnode());
}

bool isProcessAlive(int pid) noexcept {
  int mib[]{CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
  return sysctl(mib, 4, nullptr, nullptr, nullptr, 0) == 0;
}

static bool writeRecord(const char *filename, const char *tid, uint64_t duration) {
  FILE *file = fopen(filename, "a+b"); // Open in append mode to add new records without deleting old ones
  if (file == NULL) {
    etaHEN_log("Failed to open file for writing: %s", strerror(errno));
    return false;
  }

  char tid_padded[MAX_TID_SIZE] = {0};    // Initialize all to zero
  strncpy(tid_padded, tid, MAX_TID_SIZE); // Safely copy the TID

  if (fwrite(tid_padded, sizeof(char), MAX_TID_SIZE, file) < MAX_TID_SIZE) {
    etaHEN_log("Failed to write TID to file: %s", strerror(errno));
    fclose(file);
    return false;
  }
  
  if (fwrite(&duration, sizeof(uint64_t), 1, file) < 1) {
    etaHEN_log("Failed to write duration to file: %s", strerror(errno));
    fclose(file);
    return false;
  }

  fclose(file);
  return true;
}

static bool modifyRecordDuration(const char *filename, const char *target_tid, uint64_t &new_duration) {
  FILE *file = fopen(filename, "r+b"); // Read/Write mode, binary
  if (!file) {
    etaHEN_log("Failed to open file for reading and writing: %s", strerror(errno));
    return false;
  }

  char tid[MAX_TID_SIZE];
  uint64_t duration = 0;
  bool found = false;

  while (fread(tid, sizeof(char), MAX_TID_SIZE, file) == MAX_TID_SIZE) {
    if (fread(&duration, sizeof(uint64_t), 1, file) == 1) {
      if (strncmp(tid, target_tid, MAX_TID_SIZE) == 0) {
        found = true;
        // Move the file pointer back to the beginning of the duration to overwrite it
        fseek(file, -((long)sizeof(uint64_t)), SEEK_CUR);
        fwrite(&new_duration, sizeof(uint64_t), 1, file);
        break;
      }
    }
  }

  fclose(file);
  return found;
}

static bool getDurationForTID(const char *filename, const char *target_tid, uint64_t &duration) {
  if (!if_exists(filename)) {
    return writeRecord(filename, target_tid, duration);
  }

  FILE *file = fopen(filename, "rb");
  if (file == NULL) {
    etaHEN_log("Failed to open file for reading: %s", strerror(errno));
    return false;
  }

  char tid[MAX_TID_SIZE];
  bool found = false;

  while (fread(tid, sizeof(char), MAX_TID_SIZE, file) == MAX_TID_SIZE) {
    if (fread((void *)&duration, sizeof(uint64_t), 1, file) == 1) {
      if (strncmp(tid, target_tid, MAX_TID_SIZE) == 0) {
        found = true;
        break;
      }
    } else {
      // If we fail to read the duration after the TID, break the loop
      duration = 0;
      break;
    }
  }

  fclose(file);
  return (found == true) ? true : writeRecord(filename, target_tid, 0);
}

bool GetFileContents(const char *path, char **buffer) {
  FILE *fp = fopen(path, "rb");
  if (fp == NULL) {
    etaHEN_log("failed to open %s", path);
    return false;
  }

  fseek(fp, 0, SEEK_END);
  long size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  if (size == 0) {
    fclose(fp);
    etaHEN_log("size is 0");
    return false;
  }

  *buffer = (char *)malloc(size + 1); // Allocate memory for the file content plus null terminator
  if (*buffer == NULL) {
    etaHEN_log("failed to allocate memory (OOM)");
    fclose(fp);
    return false;
  }

  if (fread(*buffer, size, 1, fp) != 1) {
    fclose(fp);
    free(*buffer);
    return false;
  }

  fclose(fp);
  (*buffer)[size] = '\0'; // Null-terminate the buffer
  return true;
}

void notify(bool show_watermark, const char *text, ...) {
  OrbisNotificationRequest req;
  (void)memset(&req, 0, sizeof(OrbisNotificationRequest));
  char buff[3075];

  va_list args{};
  va_start(args, text);
  vsnprintf(buff, sizeof(buff), text, args);
  va_end(args);

  if (show_watermark)
    snprintf(req.message, sizeof(req.message), "[etaHEN] %s", buff);
  else
    snprintf(req.message, sizeof(req.message), "[Itemzflow] %s", buff);

  req.type = 0;
  req.unk3 = 0;
  req.use_icon_image_uri = 1;
  req.target_id = -1;
  strcpy(req.uri, "cxml://psnotification/tex_icon_system");

  etaHEN_log("Notify: %s\n", req.message);
  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

int get_ip_address(char *ip_address) {
  int ret;
  SceNetCtlInfo info;

  ret = sceNetCtlGetInfo(14, &info);
  if (ret < 0)
    goto error;

  memcpy(ip_address, info.ip_address, sizeof(info.ip_address));
  return ret;

error:
  memcpy(ip_address, "IP NOT FOUND", sizeof(info.ip_address));
  return -1;
}

bool Get_Running_App_TID(std::string &title_id, int &BigAppid) {
  char tid[255];
  BigAppid = sceSystemServiceGetAppIdOfRunningBigApp();
  if (BigAppid < 0) {
    return false;
  }
  (void)memset(tid, 0, sizeof tid);

  if (sceSystemServiceGetAppTitleId(BigAppid, &tid[0]) != 0) {
    return false;
  }

  title_id = std::string(tid);
  return true;
}

bool is_whitelisted_app(const std::string &tid) {
  // Static set of exactly matched title IDs (only initialized once)
  static const std::unordered_set<std::string> whitelist = {
      "ITEM00001",
      "NPXS39041", 
      "DUMP00000",
      "PKGI13337",
      "TOOL00001",
  };
  
  // Check for exact matches
  if (whitelist.find(tid) != whitelist.end()) {
      return true;
  }
  
  // Check for partial match with "LAPY"
  if (tid.find("LAPY") != std::string::npos) {
      return true;
  }
  
  return false;
}

void *Play_time_thread(void *args) noexcept {
  const char *filename = "/data/etaHEN/playtime.bin";
  std::string tid;
  uint64_t duration = 0;
  int appid;
  
  while (true) {
    if (!Get_Running_App_TID(tid, appid)) {
      continue;
    }
    
    etaHEN_log("getting duration for %s", tid.c_str());
    if (!getDurationForTID(filename, tid.c_str(), duration)) {
      continue;
    }
    
    etaHEN_log("got duration for %s: %llu", tid.c_str(), duration);
    duration++;
    if (!modifyRecordDuration(filename, tid.c_str(), duration)) {
      etaHEN_log("Failed to modify record duration for %s", tid.c_str());
      continue;
    }
    
    etaHEN_log("Record duration for %s changed to %llu", tid.c_str(), duration);
    sleep(59);
  }

  return nullptr;
}

bool isUserLoggedIn() {
  bool isLoggedIn = false;
  UserServiceLoginUserIdList userIdList;
  (void)memset(&userIdList, 0, sizeof(UserServiceLoginUserIdList));
  
  if (sceUserServiceGetLoginUserIdList(&userIdList) < 0) {
    return false;
  }

  for (int i = 0; i < 4; i++) {
    char username[500] = {0};
    int userid = userIdList.user_id[i];
    if (userid != -1) {
      int ret = sceUserServiceGetUserName(userid, &username[0], sizeof(username));
      etaHEN_log("sceUserServiceGetUserName returned %d", ret);
      if (ret == 0) {
        isLoggedIn = true;
        break;
      }
    }
  }
  
  sleep(5);
  return isLoggedIn;
}

pid_t find_pid(const char *name) {
  int mib[4] = {
    CTL_KERN,
    KERN_PROC,
    KERN_PROC_PROC,
    0
  };
  app_info_t appinfo;
  size_t buf_size;
  void *buf;

  int pid = -1;
  // determine size of query response
  if (sysctl(mib, 4, NULL, &buf_size, NULL, 0)) {
    etaHEN_log("sysctl failed: %s", strerror(errno));
    return -1;
  }

  // allocate memory for query response
  if (!(buf = malloc(buf_size))) {
    etaHEN_log("malloc failed %s", strerror(errno));
    return -1;
  }

  // query the kernel for proc info
  if (sysctl(mib, 4, buf, &buf_size, NULL, 0)) {
    etaHEN_log("sysctl failed: %s", strerror(errno));
    free(buf);
    return -1;
  }

  for (char *ptr = static_cast<char *>(buf); 
       ptr < (static_cast<char *>(buf) + buf_size);) {
    struct kinfo_proc *ki = reinterpret_cast<struct kinfo_proc *>(ptr);
    ptr += ki->ki_structsize;

    if (sceKernelGetAppInfo(ki->ki_pid, &appinfo)) {
      memset(&appinfo, 0, sizeof(appinfo));
    }

    if (strlen(ki->ki_comm) < 2)
      continue;

    if (strstr(ki->ki_comm, name) != NULL) {
      pid = ki->ki_pid;
      break;
    }
  }

  free(buf);
  return pid;
}

bool Open_Utility_Elf(const char *path, uint8_t **buffer) {
  if (!path || !buffer) {
    etaHEN_log("Invalid arguments: path or buffer is null.");
    return false;
  }

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    etaHEN_log("Failed to open file: %s (error: %s)", path, strerror(errno));
    return false;
  }

  struct stat st;
  if (fstat(fd, &st) != 0) {
    etaHEN_log("Failed to get file stats for %s (error: %s)", path, strerror(errno));
    close(fd);
    return false;
  }

  if (st.st_size == 0) {
    etaHEN_log("File %s is empty.", path);
    close(fd);
    return false;
  }

  // Allocate buffer and check for allocation failure
  uint8_t *buf = (uint8_t *)malloc(st.st_size);
  if (!buf) {
    etaHEN_log("Failed to allocate memory for file %s (size: %ld bytes).", path, st.st_size);
    close(fd);
    return false;
  }

  ssize_t bytes_read = read(fd, buf, st.st_size);
  if (bytes_read != st.st_size) {
    etaHEN_log("Failed to read the entire file %s (read: %ld bytes, expected: %ld bytes).",
               path, bytes_read, st.st_size);
    free(buf);
    close(fd);
    return false;
  }

  close(fd);
  *buffer = buf; // Pass the buffer back to the caller
  return true;
}
bool cmd_enable_fps(int appid);
void *fifo_and_dumper_thread(void *args) noexcept {
  char *json_str = nullptr;
  constexpr uint32_t MAX_TOKENS = 256;
  json_t pool[MAX_TOKENS]{};
  std::string tid, sandbox_dir_base;
  int retries = 0;
  bool fifo_found = false;

#define MAX_RETIRES 5
  uint8_t* util_elf = nullptr;

  while (true) {
      std::string sandbox_dir;
      // restart the util services daemon if it crashes or exits
      if (find_pid("etaHEN Utility") < 0 && retries < MAX_RETIRES) {
          if (retries == 0 || !util_elf) {
              notify(true, "etaHEN Utility is not running, restarting...");
              if (!Open_Utility_Elf("/data/etaHEN/daemons/util.elf", &util_elf)) {
                  if (++retries >= MAX_RETIRES)
                      notify(true, "Failed to open etaHEN Utility, please resend the payload or restart the console");
                  continue;
              }
          }

          if (++retries >= MAX_RETIRES) {
              notify(true, "etaHEN Utility services failed to restart, please resend the payload or restart the console");
              free(util_elf);
              continue;
          }

          if (elfldr_spawn("/", STDOUT_FILENO, util_elf, "etaHEN Utility Daemon") >= 0) {
              etaHEN_log("  Launched!");
              notify(true, "etaHEN Utility services successfully restarted");
              retries = 0;
          }
          else {
              etaHEN_log("failed to launch utility daemon, retry: %d", retries);
          }

          free(util_elf);
      }

    pthread_mutex_lock(&jb_lock);
    int bappid;
    if (!Get_Running_App_TID(tid, bappid)) {
      pthread_mutex_unlock(&jb_lock);
      continue;
    }
#if 0
    if(tid.rfind("CUSA") != std::string::npos || tid.rfind("SCUS") != std::string::npos)
         cmd_enable_fps(bappid);
#endif
    if (is_dumper_enabled) {
      if (strstr(tid.c_str(), "ITEM00001") != 0) {
        pthread_mutex_unlock(&jb_lock);
        continue;
      }
      
      sandbox_dir = "/mnt/sandbox/pfsmnt/" + tid + "-app0/";
      while (!if_exists(sandbox_dir.c_str())) {
        puts("waiting for Game filesystem ...");
        sleep(1);
      }

      etaHEN_log("Game filesystem mounted @ %s", sandbox_dir.c_str());

      int id = 0;
      uint32_t res = sceUserServiceGetForegroundUser(&id);
      if (res != 0) {
        printf("sceUserServiceGetForegroundUser failed: 0x%x\n", res);
        pthread_mutex_unlock(&jb_lock);
        continue;
      }
      etaHEN_log("[LA] user id %u", id);

      // the thread will clean this up
      Flag flag = Flag_None;
      LncAppParam param{sizeof(LncAppParam), id, 0, 0, flag};
      char buffer[255];
      snprintf(buffer, sizeof(buffer), "%d", dump_opt);
      const char *argv[5] = {dump_title.c_str(), dump_path.c_str(), tid.c_str(), &buffer[0], nullptr};

      dumping_tid = tid;
      // LAUNCH THE DUMP UTIL WITH ARGS FROM ITEMZFLOW
      int err = sceLncUtilLaunchApp("DUMP00000", argv, &param);
      if (0 < err) {
        etaHEN_log("sceLncUtilLaunchApp returned 0x%x", (uint32_t)err);
      }
      is_dumper_enabled = false;
    }
    
    if (!is_whitelisted_app(tid)) {
      pthread_mutex_unlock(&jb_lock);
      continue;
    }
    
    sandbox_dir_base = "/mnt/sandbox/" + tid + "_";
    fifo_found = false;
    
    // Try different suffixes (e.g., 000 to 50)
    for (int i = 0; i <= 50; ++i) {
      std::ostringstream oss;
      oss << std::setw(3) << std::setfill('0') << i; // Generate suffix with leading zeros
      sandbox_dir = sandbox_dir_base + oss.str() + "/download0/etahen_jailbreak";

      if (if_exists(sandbox_dir.c_str())) {
        // Found the directory
        fifo_found = true;
        break;
      }
    }

    if (!fifo_found) {
      // Log and unlock if no directory was found
      pthread_mutex_unlock(&jb_lock);
      continue;
    }
    
    if (!GetFileContents(sandbox_dir.c_str(), &json_str)) {
      etaHEN_log("Failed to get command from %s", sandbox_dir.c_str());
      pthread_mutex_unlock(&jb_lock);
      continue;
    }
    
    etaHEN_log("\nfound. %s for %s", json_str, tid.c_str());
    json_t const *my_json = json_create(json_str, pool, MAX_TOKENS);
    if (my_json == NULL) {
      puts("Error parsing JSON");
      etaHEN_log("Error parsing JSON");
      pthread_mutex_unlock(&jb_lock);
      continue;
    }

    const char *PID = json_getPropertyValue(my_json, "PID");
    if (!PID) {
      etaHEN_log("PID is null");
      notify(true, "Jailbreak failed, PID is null");
      pthread_mutex_unlock(&jb_lock);
      continue;
    }

    int reserved_value = atoi(PID);
    etaHEN_log("reserved_value: %d", reserved_value);

    int retries = 0;
    // limit the hijackers scope
    UniquePtr<Hijacker> spawned = nullptr;
    do {
      spawned = Hijacker::getHijacker(reserved_value);
      if (!spawned) {
        if (++retries > 30 || isProcessAlive(reserved_value)) {
          notify(true, "Jailbreak failed, PID is invaild");
          etaHEN_log("Jailbreak failed, PID is invaild");
          break;
        }
      }
      etaHEN_log("is null for PID %d", reserved_value);
    } while (spawned == nullptr);

    if (spawned) {
      etaHEN_log("RIGHT Jailbreak command received: jailbreaking...");

      if(global_conf.debug_app_jb_msg)
          notify(true, "App (PID %i) has been granted a jailbreak", reserved_value);

      spawned->jailbreak(true);
	  spawned.release();
    //  jailbreak_proc(reserved_value);
      unlink(sandbox_dir.c_str());
    }

    free(json_str);
    json_str = nullptr;
    pthread_mutex_unlock(&jb_lock);
  }

  return nullptr;
}
