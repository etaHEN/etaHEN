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


/******************************************************************************
 * Standard and System Header Includes
 ******************************************************************************/
 #include <csignal>
 #include <dirent.h>
 #include <errno.h>
 #include <fcntl.h>
 #include <netinet/in.h>
 #include <pthread.h>
 #include <setjmp.h>
 #include <stdarg.h>
 #include <stdbool.h>
 #include <stdint.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/_iovec.h>
 #include <sys/mount.h>
 #include <sys/signal.h>
 #include <sys/socket.h>
 #include <sys/stat.h>
 #include <sys/sysctl.h>
 #include <sys/types.h>
 #include <sys/un.h>
 #include <sys/wait.h>
 #include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
 
 /******************************************************************************
  * Custom Header Includes
  ******************************************************************************/
 #include <util.hpp>
 #include <freebsd-helper.h>
 
 extern "C" {
 #include "elfldr.h"
 #include "faulthandler.h"
 #include "hbldr.h"
 #include "pt.h"
 #include <ps5/klog.h>
 #include <ps5/kernel.h>

 pid_t elfldr_spawn(const char* cwd, int stdio, uint8_t* elf, const char* name);
 int sceKernelMprotect(void* addr, size_t len, int prot);

 extern uint8_t kstuff_start[];
 extern const unsigned int kstuff_size;

 extern uint8_t fps_prx_start[];
 extern const unsigned int fps_prx_size;
 }
 
 /******************************************************************************
  * Macros and Constants
  ******************************************************************************/
 #define QAFLAGS_SIZE 16
 #define USER_SERVICE_ID 0x80000011
 #define SYSTEM_SERVICE_ID 0x80000010
 #define LNC_UTIL_ERROR_ALREADY_RUNNING 0x8094000c
 #define LNC_ERROR_APP_NOT_FOUND 0x80940031
 #define ENTRYPOINT_OFFSET 0x70
 
 #define PROCESS_LAUNCHED 1
 
 #define LOOB_BUILDER_SIZE 21
 #define LOOP_BUILDER_TARGET_OFFSET 3
 
 #define USLEEP_NID "QcteRwbsnV0"
 
 #define LOOKUP_SYMBOL(resolver, sym) \
   resolver_lookup_symbol(resolver, sym, strlen(sym))
   
 #define SET_FUNCTION_ADDRESS(resolver, function) \
   *(void **)&(function) = \
       (void *)LOOKUP_SYMBOL(resolver, #function) /* NOLINT */
 
 #define BUILD_IOVEC(str) \
   { .iov_base = (str), .iov_length = __builtin_strlen(str) + 1 }
 
 /******************************************************************************
  * Type Definitions and Structures
  ******************************************************************************/
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
 
 typedef enum {
   Flag_None = 0,
   SkipLaunchCheck = 1,
   SkipResumeCheck = 1,
   SkipSystemUpdateCheck = 2,
   RebootPatchInstall = 4,
   VRMode = 8,
   NonVRMode = 16,
   Pft = 32UL,
   RaIsConfirmed = 64UL,
   ShellUICheck = 128UL
 } Flag;
 
 typedef struct {
   uint32_t sz;
   int user_id;
   uint32_t app_opt;
   uint64_t crash_report;
   Flag check_flag;
 } LncAppParam;
 
 typedef struct {
   const void *iov_base;
   size_t iov_length;
 } iovec_t;
 
 typedef struct FileDescriptors {
   int fd = 1;
 } FileDescriptor;
 
 typedef struct {
   uint64_t pad0;
   char version_str[0x1C];
   uint32_t version;
   uint64_t pad1;
 } OrbisKernelSwVersion;
 
 typedef struct {
   char prefix[14];  // "etaHEN_PLUGIN" + null terminator
   char titleID[10]; // 4 uppercase letters, 5 numbers, and a null terminator
   char plugin_version[5];
 } CustomPluginHeader;
 
 typedef struct app_info {
   uint32_t app_id;
   uint64_t unknown1;
   uint32_t app_type;
   char     title_id[10];
   char     unknown2[0x3c];
 } app_info_t;
 
 /******************************************************************************
  * External Declarations
  ******************************************************************************/
 extern "C" {
     int sceKernelSendNotificationRequest(int32_t device,
                                          OrbisNotificationRequest *req,
                                          size_t size, int32_t blocking);
     int sceUserServiceGetForegroundUser(uint32_t *userId);
     int sceLncUtilLaunchApp(const char *tid, const char *argv[],
                             LncAppParam *param);
     uint32_t sceLncUtilKillApp(uint32_t appId);
     int sceSystemServiceGetAppId(const char *titleId);
     int sceUserServiceInitialize(void *param);
     int sceKernelGetProsperoSystemSwVersion(OrbisKernelSwVersion *sw);
     int unmount(const char *path, int flags);
     int sceKernelGetAppInfo(int pid, app_info_t *title);
     int sceKernelGetProcessName(int pid, char *name);
     int sceKernelGetOpenPsIdForSystem(void *psid);
     int sceKernelIsGenuineDevKit();

     bool devkit_byepervisor(void);
     void notify(const char *text, ...) {
      OrbisNotificationRequest req;
      va_list args;
    
      memset(&req, 0, sizeof(OrbisNotificationRequest));
    
      // Process args
      va_start(args, text);
      vsnprintf(req.message, sizeof(req.message), text, args);
      va_end(args);
    
      req.type = 0;
      req.unk3 = 0;
      req.use_icon_image_uri = 1;
      req.target_id = -1;
      snprintf(req.uri, sizeof(req.uri), "cxml://psnotification/tex_icon_system");
    
      printf("Notify: %s\n", req.message);
      sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
    }
    
 }
 
 extern int _write(int fd, const void *, size_t); // NOLINT
 extern ssize_t _read(int, void *, size_t);       // NOLINT
 
 extern const unsigned int daemon_size;
 extern uint8_t daemon_start[];
 extern uint8_t util_start[];
 extern const unsigned int util_size;
 extern uint8_t store_png_start;
 extern const unsigned int store_png_size;
 extern uint8_t sicon_start[];
 extern const unsigned int sicon_size;
 extern uint8_t webman_icon_start[];
 extern const unsigned int webman_icon_size;
 
 /******************************************************************************
  * Global Variables
  ******************************************************************************/
 int plugin_count = 0;
 char buff[255];
 char **loaded_filenames = NULL;
 jmp_buf g_catch_buf;
 FileDescriptor sock;
 
 // Constants
 static const int LOGGER_PORT = 9021;
 static const int STDOUT = 1;
 static const int STDERR = 2;
 
 /******************************************************************************
  * Function Prototypes
  ******************************************************************************/
 void write_embedded_assets();
 bool if_exists(const char *path);
 void notify(const char *text, ...);
static void cleanup(void);
 FileDescriptor FileDescriptor_init(int fd);
 int initStdout();
 void release(FileDescriptor *fd);
 void patch_app_db(void);
 bool is_valid_plugin(const unsigned char *file_buffer);
 uint8_t *get_elf_header_address(unsigned char *file_buffer);
 static bool remount(const char *dev, const char *path);
 
 /******************************************************************************
  * Function Implementations
  ******************************************************************************/
 extern uint8_t shellui_prx_start[];
 extern const unsigned int shellui_prx_size;

  void write_embedded_assets() {
    mkdir("/data/etaHEN/", 0777);
    mkdir("/data/etaHEN/assets/", 0777);
#if 0
    int fd = open("/system_ex/common_ex/lib/shell.prx", O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd == -1) {
        perror("open failed");
        return;
    }
    if (write(fd, &shellui_prx_start, shellui_prx_size) == -1) {
        perror("write failed");
        return;
    }
    close(fd);
#endif    
if (!if_exists("/data/etaHEN/assets/store.png")) {
      int fd = open("/data/etaHEN/assets/store.png", O_WRONLY | O_CREAT | O_TRUNC, 0666);
      if (fd == -1) {
        perror("open failed");
        return;
      }
      if (write(fd, & store_png_start, store_png_size) == -1) {
        perror("write failed");
      }
      close(fd);
    }

    if (!if_exists("/data/etaHEN/assets/webMAN.png")) {
      int fd = open("/data/etaHEN/assets/webMAN.png", O_WRONLY | O_CREAT | O_TRUNC, 0666);
      if (fd == -1) {
        perror("open failed");
        return;
      }
      if (write(fd, & webman_icon_start, webman_icon_size) == -1) {
        perror("write failed");
      }
      close(fd);
    }
 
    if (!if_exists("/system_ex/rnps/apps/NPXS40008/assets/src/modules/categoriesList/assets/texture/etahen_sicon.png")) {
      int fd = open("/system_ex/rnps/apps/NPXS40008/assets/src/modules/categoriesList/assets/texture/etahen_sicon.png", O_WRONLY | O_CREAT | O_TRUNC, 0666);
      if (fd == -1) {
        perror("open failed");
        return;
      }
      if (write(fd, & sicon_start, sicon_size) == -1) {
        perror("write failed");
      }
      close(fd);
    }
 
    if (!if_exists("/mnt/rnps/apps/NPXS40008/assets/src/modules/categoriesList/assets/texture/etahen_sicon.png")) {
      int fd = open("/mnt/rnps/apps/NPXS40008/assets/src/modules/categoriesList/assets/texture/etahen_sicon.png", O_WRONLY | O_CREAT | O_TRUNC, 0666);
      if (fd == -1) {
        perror("open failed");
        return;
      }
      if (write(fd, & sicon_start, sicon_size) == -1) {
        perror("write failed");
      }
      close(fd);
    }
}

  bool is_elf_header(uint8_t* data)
  {
      uint8_t header[] = { 0x7f, 'E', 'L', 'F' };

      return !memcmp(data, header, 4);
  }


  uint8_t* get_kstuff_address(bool& require_cleanup) {
      const char* path = "/data/etaHEN/kstuff.elf";
      long offset = 0;
      off_t size;
      uint8_t* address;
      int fd;

      if (!if_exists(path)) {
          goto embedded_kstuff;
      }

      fd = open(path, O_RDONLY);
      if (fd <= 0) {
          goto embedded_kstuff;
      }

      size = lseek(fd, 0, SEEK_END);
      address = (uint8_t*)malloc(size);

      if (!address) {
          goto close_fd;
      }

      lseek(fd, 0, SEEK_SET);

      while (offset != size) {
          int n = read(fd, address + offset, size - offset);

          if (n <= 0)
          {
              goto free_mem;
          }

          offset += n;
      }

      if (!is_elf_header(address)) {
          notify( "Kstuff '%s' doesn't have ELF header.", path);
          goto free_mem;
      }

      require_cleanup = true;
      notify("Loading kstuff from: %s", path);
      return address;

  free_mem:
      free(address);
  close_fd:
      close(fd);
  embedded_kstuff:
      require_cleanup = false;
      return kstuff_start;
  }
 
 bool if_exists(const char *path) {
   struct stat buffer;
   return (stat(path, &buffer) == 0);
 }
 
 static bool remount(const char *dev, const char *path) {
   iovec_t iov[] = {BUILD_IOVEC("fstype"),    BUILD_IOVEC("exfatfs"),
                    BUILD_IOVEC("fspath"),    BUILD_IOVEC(path),
                    BUILD_IOVEC("from"),      BUILD_IOVEC(dev),
                    BUILD_IOVEC("large"),     BUILD_IOVEC("yes"),
                    BUILD_IOVEC("timezone"),  BUILD_IOVEC("static"),
                    BUILD_IOVEC("async"),     {NULL, 0},
                    BUILD_IOVEC("ignoreacl"), {NULL, 0}};
   return nmount((struct iovec *)iov, sizeof(iov) / sizeof(iov[0]),
                 MNT_UPDATE) == 0;
 }
 static void cleanup(void) { 
    if (sock.fd != -1) {
      close(sock.fd);
      sock.fd = -1;
    }
  
    // Notify user about cleanup
    notify("etaHEN has been cleaned up.");
  
    // Exit the program
    exit(0);
 }
 
 // FileDescriptor methods implementations
 FileDescriptor FileDescriptor_init(int fd) {
   FileDescriptor newFd;
   newFd.fd = fd;
   return newFd;
 }
 
 void release(FileDescriptor *fd) { 
   fd->fd = -1; 
 }
 
 // Stdout initialization logic
 int initStdout() {
   // Check for logging file existence logic here
   // For simplicity, I'm assuming it always exists
   char error_msg[500] = {0};
 
   sock.fd = -1;
   sock = FileDescriptor_init(socket(AF_INET, SOCK_STREAM, 0));
   if (sock.fd == -1) {
     snprintf(error_msg, sizeof(error_msg), "Failed to create socket: %s",
              strerror(errno));
     notify(error_msg);
     return -1;
   }
 
   int value = 1;
   if (setsockopt(sock.fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0) {
     snprintf(error_msg, sizeof(error_msg), "Failed to set socket options: %s",
              strerror(errno));
     notify(error_msg);
     return -1;
   }
 
   struct sockaddr_in server_addr;
   (void)memset(&server_addr, 0, sizeof(server_addr));
   server_addr.sin_family = AF_INET;
   server_addr.sin_port = htons(LOGGER_PORT);
   server_addr.sin_addr.s_addr = 0;
 
   if (bind(sock.fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
     snprintf(error_msg, sizeof(error_msg), "Failed to bind socket: %s",
              strerror(errno));
     notify(error_msg);
     return -1;
   }
 
   if (listen(sock.fd, 1) != 0) {
     snprintf(error_msg, sizeof(error_msg), "Failed to listen on socket: %s",
              strerror(errno));
     notify(error_msg);
     return -1;
   }
 
   struct sockaddr client_addr;
   socklen_t addr_len = sizeof(client_addr);
   int conn = accept(sock.fd, &client_addr, &addr_len);
   if (conn != -1) {
     dup2(conn, STDOUT);
     dup2(conn, STDERR);
     close(conn);
     return conn;
   }
 
   snprintf(error_msg, sizeof(error_msg), "Failed to accept connection: %s",
            strerror(errno));
   notify(error_msg);
   return -1;
 }
 
 // Function to check if the file buffer contains a valid custom plugin header
 bool is_valid_plugin(const unsigned char *file_buffer) {
   // Check if the prefix matches
   if (strncmp((const char *)file_buffer, "etaHEN_PLUGIN", 13) != 0) {
     puts("Plugin header prefix does not match");
     return false;
   }
 
   // Validate the title ID format (4 uppercase letters followed by 4 numbers)
   const CustomPluginHeader *header = (const CustomPluginHeader *)file_buffer;
   for (int i = 0; i < 4; ++i) {
     if (header->titleID[i] < 'A' || header->titleID[i] > 'Z') {
       puts("Invalid plugin file: titleID must contain 4 uppercase letters as "
            "the start");
       return false;
     }
   }
   for (int i = 4; i < 9; ++i) {
     if (header->titleID[i] < '0' || header->titleID[i] > '9') {
       puts("Invalid plugin file: titleID must contain 5 numbers as the end");
       return false;
     }
   }
 
   // Ensure the title ID is null-terminated
   if (header->titleID[9] != '\0') {
     puts("Invalid plugin file: titleID must be null-terminated");
     return false;
   }
 
   for (int i = 0; i < 3; ++i) {
     if (header->plugin_version[i] == '.') {
       continue;
     } else if (header->plugin_version[i] < '0' ||
                header->plugin_version[i] > '9') {
       puts(
           "Invalid plugin file: version must be in the following format xx.xx");
       return false;
     }
   }
 
   return true;
 }
 
 // Function to return the address of the ELF header, skipping the custom plugin header
 uint8_t *get_elf_header_address(unsigned char *file_buffer) {
   // The ELF header should start right after the custom plugin header
   return file_buffer + sizeof(CustomPluginHeader);
 }
 

pid_t find_pid(const char * name) {
  int mib[4] = {
    CTL_KERN,
    KERN_PROC,
    KERN_PROC_PROC,
    0
  };
  size_t buf_size;
  void * buf;

  int pid = -1;
  // determine size of query response
  if (sysctl(mib, 4, NULL,&buf_size, NULL, 0)) {
    printf("sysctl failed: %s\n", strerror(errno));
    return -1;
  }

  // allocate memory for query response
  if (!(buf = malloc(buf_size))) {
    printf("malloc failed %s\n", strerror(errno));
    return -1;
  }

  // query the kernel for proc info
  if (sysctl(mib, 4, buf,&buf_size, NULL, 0)) {
    printf("sysctl failed: %s\n", strerror(errno));
    free(buf);
    return -1;
  }

  for (char * ptr = static_cast < char * > (buf); ptr < (static_cast < char * > (buf) + buf_size);) {
    struct kinfo_proc * ki = reinterpret_cast < struct kinfo_proc * > (ptr);
    ptr += ki->ki_structsize;

    if(strlen(ki->ki_comm) < 2)
      continue;

    if (strstr(ki->ki_comm, name) != NULL) {
      pid = ki->ki_pid;
      break;
    }
  }

  free(buf);

  return pid;
}

bool is_elf_file(const void* buffer, size_t size) {
    if (size < 4) return false;
    
    const unsigned char elf_magic[] = {0x7F, 'E', 'L', 'F'};
    return memcmp(buffer, elf_magic, 4) == 0;
}


bool load_plugin(const char *path, const char *filename)
{
  int fd = open(path, O_RDONLY);
  if (fd < 0)
  {
    perror("Failed to open file");
    return false;
  }

  struct stat st;
  if (fstat(fd, &st) != 0)
  {
    perror("Failed to get file stats");
    close(fd);
    return false;
  }
  // Allocate buffer and read the entire file.
  uint8_t *buf = (uint8_t *)malloc(st.st_size);
  if (!buf)
  {
    perror("Failed to allocate memory for Plugin file");
    close(fd);
    return false;
  }

  if (read(fd, buf, st.st_size) != st.st_size)
  {
    perror("Failed to read Plugin file");
    free(buf), buf = NULL;
    close(fd);
    return false;
  }
  close(fd);

  const CustomPluginHeader *header = (const CustomPluginHeader *)buf;

  char pbuf[256];
  snprintf(pbuf, sizeof(pbuf), "/system_tmp/%s.PID", header->titleID);

  if (strstr(filename, ".elf") != NULL)
  {
    // Handle ELF plugin loading
    if (!is_elf_file(buf, st.st_size))
    {
      free(buf), buf = NULL;
      return false;
    }

    pid_t pid = -1;
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
        printf("Stale plugin PID file detected for %s, removing\n", header->titleID);
        unlink(pbuf);
        pid = -1;
      }
    }

    printf("seeing if elf is running\n");
    if (pid > 0)
    {
      printf("killing pid %d\n", pid);
      if (kill(pid, SIGKILL))
        perror("kill");
      unlink(pbuf);
    }

    printf("loading elf %s\n", filename);
    pid = elfldr_spawn("/", sock.fd, buf, header->titleID);
    if (pid >= 0)
      printf("  Launched!\n");
    else
      printf("  Already Running!\n");

    free(buf), buf = NULL;

    f = open(pbuf, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (f >= 0)
    {
      if (pid >= 0)
      {
        char t[32];
        int l = snprintf(t, sizeof(t), "%d", pid);
        write(f, t, l);
      }
      else
      {
        unlink(pbuf);
      }
      close(f);
    }

    return true;
  }

  if (!is_valid_plugin(buf))
  {
    puts("Invalid plugin file.");
    free(buf), buf = NULL;
    return false;
  }

  puts("============== Plugin info ===============");
  printf("Plugin Prefix: %s\n", header->prefix);
  printf("Plugin TitleID: %s\n", header->titleID);
  printf("Plugin Version: %s\n", header->plugin_version);
  puts("=========================================");

  snprintf(pbuf, sizeof(pbuf), "/system_tmp/%s.PID", header->titleID);

  uint8_t *elf = get_elf_header_address(buf);

  pid_t pid = -1;
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
      printf("Stale plugin PID file detected for %s, removing\n", header->titleID);
      unlink(pbuf);
      pid = -1;
    }
  }

  printf("seeing if plugin is running\n");
  if (pid > 0)
  {
    printf("killing pid %d\n", pid);
    if (kill(pid, SIGKILL))
      perror("kill");
    unlink(pbuf);
  }

  if (strcmp(header->titleID, "EORR37000") == 0)
  {
    notify("The Error disabler plugin is no longer required and has been auto deleted.");
    unlink(path);
    free(buf), buf = NULL;
    return true;
  }

  printf("loading plugin %s\n", path);
  pid = elfldr_spawn("/", sock.fd, elf, header->titleID);
  if (pid >= 0)
    printf("  Launched!\n");
  else
    printf("  Already Running!\n");

  f = open(pbuf, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (f >= 0)
  {
    if (pid >= 0)
    {
      char t[32];
      int l = snprintf(t, sizeof(t), "%d", pid);
      write(f, t, l);
    }
    else
    {
      unlink(pbuf);
    }
    close(f);
  }

  free(buf), buf = NULL;

  return true;
}

/*=================== LOAD PLUGINS =========================*/
char **find_plugin_files() {
  const char *base_dirs[] = {
    // Plugin directories
    "/mnt/usb0/etahen/plugins", "/mnt/usb0/etaHEN/plugins",
    "/mnt/usb1/etahen/plugins", "/mnt/usb2/etahen/plugins",
    "/mnt/usb3/etahen/plugins", "/user/data/etaHEN/plugins",
    "/user/data/etahen/plugins",
    
    // Payload directories
    "/mnt/usb0/etahen/payloads", "/mnt/usb0/etaHEN/payloads",
    "/mnt/usb1/etahen/payloads", "/mnt/usb2/etahen/payloads",
    "/mnt/usb3/etahen/payloads", "/user/data/etaHEN/payloads",
    "/user/data/etahen/payloads"
};

  int base_dirs_count = sizeof(base_dirs) / sizeof(base_dirs[0]);

  char **plugin_paths = NULL;
  char full_path[255];
  char auto_start_path[255];
  plugin_count = 0;
  loaded_filenames = (char **)malloc(255 * sizeof(char *));

  for (int i = 0; i < base_dirs_count; i++) {
    DIR *dir = opendir(base_dirs[i]);
    if (dir) {
      struct dirent *entry;
      while ((entry = readdir(dir)) != NULL) {
        (void)memset(full_path, 0, sizeof(full_path));
        if (entry->d_type == DT_REG) { // Regular file
          const char *ext = strrchr(entry->d_name, '.');
          if (ext && (strcmp(ext, ".plugin") == 0 || strcmp(ext, ".elf") == 0)) {
            bool skip = false;
            // Construct full path
            snprintf(full_path, sizeof(full_path), "%s/%s", base_dirs[i],
                     entry->d_name);
            snprintf(auto_start_path, sizeof(auto_start_path),
                     "%s/%s.auto_start", base_dirs[i], entry->d_name);

            if (!if_exists(auto_start_path)) {
              printf("skipping auto start for plugin: %s\n", full_path);
              continue;
            }

            for (int j = 0; j < plugin_count; j++) {
              if (strcmp(loaded_filenames[j], entry->d_name) == 0) {
                skip = true;
                // Only print the message for /data/etaHEN/plugins/elfldr.plugin
                // as per specific requirement
                if ((strcmp(base_dirs[i], "/data/etaHEN/plugins") == 0) || (strcmp(entry->d_name, "/data/etaHEN/payloads") == 0)) {
                  printf("skipping duplicate plugin: %s | already loaded: %s\n",
                         full_path, loaded_filenames[j]);
                }
                break;
              }
            }
            if (skip)
              continue;

            // Add to array
            plugin_paths = (char **)realloc(plugin_paths, (plugin_count + 1) *
                                                              sizeof(char *));
            plugin_paths[plugin_count] = strdup(full_path);

            // Copy filename to loaded_filenames
            loaded_filenames[plugin_count] =
                strdup(entry->d_name); // Use strdup for simplicity
            plugin_count++;
          }
        }
      }
      closedir(dir);
    }
  }

  return plugin_paths;
}
void free_plugin_files(char **plugin_files) {
  // Free memory for loaded_filenames
  for (int i = 0; i < plugin_count; i++) {
    free(loaded_filenames[i]);
  }
  free(loaded_filenames);

  for (int i = 0; i < plugin_count; i++) {
    free((void *)plugin_files[i]);
  }
  free((void *)plugin_files);
}

bool Byepervisor();
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

  const char *whitelisted_psids[] = {
      "b345df7d4c77618d40f19a90e438ad87",
      "ab535275b7196e7e7d43f4f9e7806724",
      "d376c7780b960e5182d326ba3aa2d7a3",
      "a8d89ad976b5cb912837ad29b0cc4610",
      "177e09480b40816a1caca5151565daa5",
           

  };

#if 0
  printf("PSID: %s\n", psid_buf);
  char buff[300];
  snprintf(buff, sizeof buff, "PSID: %s", psid_buf);
  notify(buff);
#endif

  for (int i = 0; i < sizeof(whitelisted_psids) / sizeof(whitelisted_psids[0]);
       i++) {
    if (strcmp(psid_buf, whitelisted_psids[i]) == 0) {
      // printf("PSID (%s) whitelisted\n", psid_buf);
      return false; // report not testkit if is whitelisted
    }
  }

  // printf("PSID (%s) Not whitelisted\n", psid_buf);
  return if_exists("/system/priv/lib/libSceDeci5Ttyp.sprx");
}
#define PUBLIC_TEST 0
#define EXPIRE_YEAR 2025
#define EXPIRE_MONTH 12
#define EXPIRE_DAY 25


bool isPastBetaDate(int year, int month, int day);

int main(void) {
  // ptrace(PT_ATTACH, pid, 0, 0);
  /// clearFramePointer();
  int pid = -1;

#if BETA == 1
  char out[1024];
#endif

  signal(SIGCHLD, SIG_IGN);

  klog_puts("Jailbreaking the boostrapper ...");
  // launch socksrv.elf in a new processes
  if (elfldr_raise_privileges(getpid())) {
    notify("Unable to raise privileges");
    return -1;
  }

#if BETA == 1
  printf("Get_code %d", GetDecryptedConsoleCode(
                            &out[0])); // ignore return value because we need to
                                       // call is_console_whitelisted anyway
  bool is_whitelisted = is_console_whitelisted(
      &buffer[0], &out[0]); // gets PSID if its not whitelisted too
#endif

#if BETA == 1 || PUBLIC_TEST == 1
  if (isPastBetaDate(EXPIRE_YEAR, EXPIRE_MONTH, EXPIRE_DAY)) {
    notify("This etaHEN Beta version expired on %d-%d-%d", EXPIRE_YEAR,
           EXPIRE_MONTH, EXPIRE_DAY);
    return -1;
    raise(SIGSEGV);
  }
#endif

#if 0
  if (sceKernelIsTestKit()) {
    notify("support dropped for testkits if you donated to my ko-fi and are NOT andrew send me a message");
    return 0;
  }
#endif


  klog_printf("   Success!\n");
  if(if_exists("/data/I_want_logging_for_etahen")){
      klog_printf("Redirecting stdout and stderr to logger ...");
     if(initStdout() >= 0)
         klog_puts("   Success!");
     else
         klog_puts("   Failed!");
      
  }


  
  #if BETA == 1 
  if (!is_whitelisted) {
    notify("This console is NOT approved to use this etaHEN beta version\n\nIf "
           "you are not yet approved send LM the pending_approval.bin file "
           "from your USB for the etaHEN_approval.bin");
    int fd = open("/mnt/usb0/pending_approval.bin", O_CREAT | O_TRUNC | O_RDWR,
                  0777);
    if (fd < 0) {
      fd = open("/mnt/usb1/pending_approval.bin", O_CREAT | O_TRUNC | O_RDWR,
                0777);
      if (fd < 0) {
        fd = open("/mnt/usb2/pending_approval.bin", O_CREAT | O_TRUNC | O_RDWR,
                  0777);
      }

    if (fd >= 0) {
      write(fd, buffer, strlen(buffer));
      close(fd);
    } else {
      notify("No USB Found to save pending_approval.bin\n\nInsert a EXFAT USB "
             "then re-run this payload");
    }

    return -1;
    raise(SIGSEGV);
  }
  #endif


  OrbisKernelSwVersion sys_ver;
  sceKernelGetProsperoSystemSwVersion(&sys_ver);

  if (sys_ver.version < 0x3000000 && !sceKernelIsGenuineDevKit()) {
    klog_printf("FW %s version has Byepervisor available, sstarting....\n", sys_ver.version_str);
    if (!Byepervisor()) {
      printf("Byepervisor failed or is resume_nedded");
      return 0;
    }
  }


  notify("[Bootstrapper] etaHEN is starting...\n    DO NOT EXIT    \nwait for "
         "the etaHEN welcome message");

  klog_puts("============== Spawner (Bootstrapper) Started =================");

  mkdir("/data/etaHEN", 0777);
  mkdir("/data/etaHEN/plugins", 0777);
  mkdir("/data/etaHEN/payloads", 0777);
  mkdir("/data/etaHEN/daemons", 0777);

  klog_printf("Registering signal handler ...");
  fault_handler_init(cleanup);
  klog_printf("   Success!\n");

  klog_printf("Remounting system partitions ...");
  if (!remount("/dev/ssd0.system_ex", "/system_ex")) {
    perror("failed to mount /system_ex\nif you see this reboot");
    notify("failed to mount /system_ex\nif you see this reboot");
    return -1;
  }
  if (!remount("/dev/ssd0.system", "/system")) {
    perror("failed to mount /system_\nif you see this reboot");
    notify("failed to mount /system\nif you see this reboot");
    return -1;
  }
  klog_printf("   Success!\n");

  klog_printf("Writing embedded assets ...");
  write_embedded_assets();
  klog_printf("   Written!\n");

  klog_printf("Unmounting /update forcefully ...");
  // block updates
  unlink("/update/PS5UPDATE.PUP");
  unlink("/update/PS5UPDATE.PUP.net.temp");
  // unlink("/update/PS4UPDATE.PUP.md5");
  if ((int)unmount("/update", 0x80000LL) < 0) {
    unmount("/update", 0);
  }

  klog_puts("   Success!");

#if 1
  char buz[100] = { 0 };
  // Load kstuff if needed
  bool dont_load_kstuff = (if_exists("/mnt/usb0/no_kstuff") || if_exists("/data/etaHEN/no_kstuff"));
  if (dont_load_kstuff) {
      notify("kstuff loading disabled via file, non-payload homebrew and PS4 FPKGs will be disabled");
      klog_puts("kstuff loading disabled in config.ini or no_kstuff file found");
  }
  if (!dont_load_kstuff && sys_ver.version >= 0x3000000) {
      notify("Loading kstuff ...");

      bool cleanup_kstuff = false;
      uint8_t* kstuff_address = get_kstuff_address(cleanup_kstuff);

      if (elfldr_spawn("/", STDOUT_FILENO, kstuff_address, "kstuff")) {
          int wait = 0;
          bool kstuff_not_loaded = false;
          sleep(1);
          while ((kstuff_not_loaded = sceKernelMprotect(&buz[0], 100, 0x7) < 0)) {
              if (wait++ > 10) {
                  notify("Failed to load kstuff, kstuff will be unavailable");
                  break;
              }
              sleep(1);
          }

          if (!kstuff_not_loaded)
              klog_puts("kstuff loaded");

          if (cleanup_kstuff) {
              free(kstuff_address);
          }
      }
      else {
          notify("Failed to load kstuff, kstuff will be unavailable");
      }
  }
  sleep(1);
#endif

  klog_printf("Starting Utility etaHEN services ...");

  while ((pid = find_pid("etaHEN")) > 0) {
   // printf("killing pid %d\n", pid);
    if (kill(pid, SIGKILL)) {
      perror("kill");
    }
  }

  if (elfldr_spawn("/", sock.fd, util_start, "etaHEN Utility Daemon") >= 0) {
      klog_printf("  Launched!\n");
    // Open the file with write permission, create if not exist, truncate to zero if exists
    int fd = open("/data/etaHEN/daemons/util.elf", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd == -1) {
      perror("open failed");
      return -1337;
    }
    // Write the buffer to the file
    if (write(fd, util_start, util_size) == -1) {
       perror("write failed");
    }

    // Close the file descriptor
    close(fd);
  } else {
    klog_printf("failed to launch utility daemon\n");
    notify("failed to launch the etaHEN utility daemon");
    return -2;
  }

  klog_printf("Starting the main etaHEN daemon ...");

  if (elfldr_spawn("/", sock.fd, daemon_start, "etaHEN Critical services") >= 0) {
      klog_printf("  Launched!\n");
  } else {
      klog_printf("failed to launch main daemon\n");
      notify("failed to launch the main etaHEN daemon");
      return -2;
  }

  // return 0;

  char **plugin_paths = find_plugin_files();
  if (plugin_paths && plugin_count > 0) {
    int loaded_plugins = 0;
    // First, load all plugins except elfldr.plugin
    for (int i = 0; i < plugin_count; i++) {
      // Skip loading elfldr.plugin in this loop
      if (strstr(plugin_paths[i], "elfldr") == 0) {
          klog_printf("Loading plugin: %s\n", plugin_paths[i]);
        if (!load_plugin(plugin_paths[i], loaded_filenames[i])) {
          snprintf(buff, sizeof(buff),
                   "[etaHEN] Failed to load plugin!\nPath: %s",
                   plugin_paths[i]);
          notify(buff);
          klog_puts("FAILED!");
          continue;
        }

        klog_puts("Loaded!");
        loaded_plugins++;
      }
    }
    //(void)memset(buff, 0, sizeof(buff));
    // snprintf(buff, sizeof(buff), "Successfully loaded %d plugins",
    // loaded_plugins); notify(buff);
    klog_printf("Successfully loaded %d plugins\n", loaded_plugins);
    free_plugin_files(plugin_paths);
  }
  // raise(SIGKILL, getpid());
  // sceSystemServiceLoadExec("exit", NULL);
  klog_puts("============== Spawner (Bootstrapper) Finished =================");

  return 0;
}
