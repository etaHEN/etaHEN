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

#include "common_utils.h"
#include <signal.h>
#include <unistd.h>
#include <sys/signal.h>
#include <freebsd-helper.h>
#include <libgen.h>
#include <ps5/klog.h>
#include "pt.h"

typedef struct app_info {
  uint32_t app_id;
  uint64_t unknown1;
  uint32_t app_type;
  char     title_id[10];
  char     unknown2[0x3c];
} app_info_t;

int launchApp(const char *titleId);
int sceSystemServiceGetAppId(const char *title_id);
void free(void *ptr);
void *malloc(size_t size);
int elfldr_set_procname(pid_t pid, const char* name);

int sceKernelGetProcessName(int pid, char *name);
int sceKernelGetAppInfo(int pid, app_info_t *title);
pid_t elfldr_spawn(const char* cwd, int stdio, uint8_t* elf, const char* name);

atomic_bool not_connected = false;

#define SCE_NET_CTL_ERROR_NOT_CONNECTED 0x80412108
#define SCE_NET_CTL_ERROR_NOT_AVAIL 0x80412109
 
 __asm__(

  
	".global elfldr_start\n"
	".type   elfldr_start, @object\n"
	".align  16\n"
	"elfldr_start:\n"
    	".incbin \"assets/elfldr.elf\"\n"
	"elfldr_end:\n"
	    ".global elfldr_size\n"
	    ".type   elfldr_size, @object\n"
	    ".align  4\n"
	"elfldr_size:\n"
    	".int    elfldr_end - elfldr_start\n"
);



 static int
     sys_ptrace(int request, pid_t pid, caddr_t addr, int data) {
     pid_t mypid = getpid();
     uint64_t authid;
     int ret;

     if (!(authid = kernel_get_ucred_authid(mypid))) {
         return -1;
     }
     if (kernel_set_ucred_authid(mypid, 0x4800000000010003l)) {
         return -1;
     }

     ret = (int)syscall(SYS_ptrace, request, pid, addr, data);

     if (kernel_set_ucred_authid(mypid, authid)) {
         return -1;
     }

     return ret;
 }


 int pt_detach_proc(pid_t pid, int sig) {
     if (sys_ptrace(PT_DETACH, pid, 0, sig) == -1) {
         return -1;
     }

     return 0;
 }

 int pt_attach_proc(pid_t pid) {
     if (sys_ptrace(PT_ATTACH, pid, 0, 0) == -1) {
         return -1;
     }

     if (waitpid(pid, 0, 0) == -1) {
         return -1;
     }

     return 0;
 }

int get_ip_address(char *ip_address)
{
	unsigned int ret = 0;
	SceNetCtlInfo info;

	ret = sceNetCtlGetInfo(14, &info);
	if (ret < 0){
		if(ret == SCE_NET_CTL_ERROR_NOT_CONNECTED || ret == SCE_NET_CTL_ERROR_NOT_AVAIL){
			not_connected = true;
		}
		goto error;
	}

	memcpy(ip_address, info.ip_address, sizeof(info.ip_address));

	return ret;

error:
	memcpy(ip_address, "IP NOT FOUND", sizeof(info.ip_address));
	return -1;
}

void etaHEN_log(const char * fmt, ...) {
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

  printf("[etaHEN utils]: %s", msg); // msg already includes a newline
  klog_printf("%s", msg); // msg already includes a newline

  int fd = open("/data/etaHEN/etaHEN_util_daemon.log", O_WRONLY | O_CREAT | O_APPEND, 0777);
  if (fd < 0) {
    return;
  }
  write(fd, msg, strlen(msg));
  close(fd);
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

void notify(bool show_watermark, const char *text, ...)
{
	OrbisNotificationRequest req;
	(void)memset(&req, 0, sizeof(OrbisNotificationRequest));
	char buff[3075];

	// printf("******************** text: %s\n", text);

	va_list args;
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

	etaHEN_log("Notify: %s", req.message);
	sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}


bool copyFile(const char *source, const char *destination)
{

    FILE *src = fopen(source, "rb");
    if (src == NULL)
    {
        notify(false, "copyFile failed for %s", source);
        etaHEN_log("copyFile failed for %s", source);
        return false;
    }

    FILE *dest = fopen(destination, "wb");
    if (dest == NULL)
    {
        notify(false, "copyFile failed for %s", destination);
        etaHEN_log("copyFile failed for %s", destination);
        fclose(src);
        return false;
    }

    char buffer[1024];
    size_t bytes = 0;

    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0)
    {
        fwrite(buffer, 1, bytes, dest);
    }

    fclose(src);
    fclose(dest);

    return true;
}



void make_hb_elf(const char *tid, const void *start, const unsigned int size) {
  char path[1024];
  snprintf(path, sizeof(path), "/system_ex/app/%s/homebrew.elf", tid);
  FILE *fp = fopen(path, "wb+");
  if (fp == NULL) {
    perror("open failed");
    return;
  }
  fwrite(start, 1, size, fp);
  fclose(fp);
}


uint8_t *get_elf_header_address(unsigned char *file_buffer)
{
	// The ELF header should start right after the custom plugin header
	return file_buffer + sizeof(CustomPluginHeader);
}


static bool mkdir_if_necessary(const char *path) {
  if (mkdir(path, 0777) == -1) {
    const int err = errno;
    if (err != EEXIST) {
      perror("mkdir failed");
      return false;
    }
  }
  return true;
}

bool make_plugin_app(const char *tid, const void *start,
                     const unsigned int size)
{
  // REDIS->NPXS40028
  char sys_app[255];
  static const char *json = "{\n"
                            "    \"applicationCategoryType\": 33554432,\n"
                            "    \"localizedParameters\": {\n"
                            "        \"defaultLanguage\": \"en-US\",\n"
                            "        \"en-US\": {\n"
                            "            \"titleName\": \"etaHEN Plugin\"\n"
                            "        }\n"
                            "    },\n"
                            "    \"titleId\": \"%s"
                            "\"\n"
                            "}\n";
  snprintf(sys_app, sizeof(sys_app), "/system_ex/app/%s", tid);
  if (mkdir(sys_app, 0777) == -1)
  {
    const int err = errno;
    if (err != EEXIST)
    {
      perror("make_plugin_app mkdir /system_ex/app/");
      return false;
    }
    make_hb_elf(tid, start, size);
    return true;
  }
  make_hb_elf(tid, start, size);
  (void)memset(sys_app, 0, sizeof(sys_app));
  snprintf(sys_app, sizeof(sys_app), "/system_ex/app/%s/eboot.bin", tid);
  if (!copyFile("/system_ex/app/NPXS40028/eboot.bin", sys_app))
  {
    puts("failed to copy redis eboot.bin");
    return false;
  }
  (void)memset(sys_app, 0, sizeof(sys_app));
  snprintf(sys_app, sizeof(sys_app), "/system_ex/app/%s/sce_sys", tid);
  if (!mkdir_if_necessary(sys_app))
  {
    return false;
  }
  (void)memset(sys_app, 0, sizeof(sys_app));
  snprintf(sys_app, sizeof(sys_app), "/system_ex/app/%s/sce_sys/param.json",
           tid);
  FILE *fp = fopen(sys_app, "w+");
  if (fp == NULL)
  {
    perror("open failed");
    return false;
  }
  (void)memset(sys_app, 0, sizeof(sys_app));
  snprintf(sys_app, sizeof(sys_app), json, tid);
  fwrite(sys_app, 1, __builtin_strlen(sys_app), fp);
  fclose(fp);

  return true;
}

bool is_valid_plugin(const unsigned char *file_buffer)
{
  // Check if the prefix matches
  if (strncmp((const char *)file_buffer, "etaHEN_PLUGIN", 13) != 0)
  {
    puts("Plugin header prefix does not match");
    return false;
  }

  // Validate the title ID format (4 uppercase letters followed by 4 numbers)
  const CustomPluginHeader *header = (const CustomPluginHeader *)file_buffer;
  for (int i = 0; i < 4; ++i)
  {
    if (header->titleID[i] < 'A' || header->titleID[i] > 'Z')
    {
      puts("Invalid plugin file: titleID must contain 4 uppercase letters as the start");
      return false;
    }
  }
  for (int i = 4; i < 9; ++i)
  {
    if (header->titleID[i] < '0' || header->titleID[i] > '9')
    {
      puts("Invalid plugin file: titleID must contain 5 numbers as the end");
      return false;
    }
  }

  // Ensure the title ID is null-terminated
  if (header->titleID[9] != '\0')
  {
    puts("Invalid plugin file: titleID must be null-terminated");
    return false;
  }

  for (int i = 0; i < 3; ++i)
  {
    if (header->plugin_version[i] == '.')
    {
      continue;
    }
    else if (header->plugin_version[i] < '0' || header->plugin_version[i] > '9')
    {
      puts("Invalid plugin file: version must be in the following format xx.xx");
      return false;
    }
  }

  return true;
}

pid_t find_pid(const char *name)
{
  int mib[4] = {
      CTL_KERN,
      KERN_PROC,
      KERN_PROC_PROC,
      0};
  app_info_t appinfo;
  size_t buf_size;
  void *buf;

  int pid = -1;
  //  size of query response
  if (sysctl(mib, 4, NULL, &buf_size, NULL, 0))
  {
    etaHEN_log("sysctl failed: %s", strerror(errno));
    return -1;
  }

  // allocate memory for query response
  if (!(buf = malloc(buf_size)))
  {
    etaHEN_log("malloc failed %s", strerror(errno));
    return -1;
  }

  // query the kernel for proc info
  if (sysctl(mib, 4, buf, &buf_size, NULL, 0))
  {
    etaHEN_log("sysctl failed: %s", strerror(errno));
    free(buf);
    return -1;
  }

  for (void *ptr = buf; ptr < (buf + buf_size);)
  {
    struct kinfo_proc *ki = (struct kinfo_proc *)ptr;
    ptr += ki->ki_structsize;

    if (sceKernelGetAppInfo(ki->ki_pid, &appinfo))
    {
      memset(&appinfo, 0, sizeof(appinfo));
    }

    if (strcmp(ki->ki_comm, name) == 0)
    {
      pid = ki->ki_pid;
      break;
    }
  }

  free(buf);

  return pid;
}


bool is_elf_file(const void *buffer, size_t size)
{
  if (size < 4)
    return false;

  const unsigned char elf_magic[] = {0x7F, 'E', 'L', 'F'};
  return memcmp(buffer, elf_magic, 4) == 0;
}

bool load_plugin(const char *path)
{
  int fd = open(path, O_RDONLY);
  if (fd < 0)
  {
    etaHEN_log("Failed to open file, %s (error %s)", path, strerror(errno));
    return false;
  }

  struct stat st;
  if (fstat(fd, &st) != 0)
  {
    etaHEN_log("Failed to get file stats");
    close(fd);
    return false;
  }
 
  // Allocate buffer and read the entire file.
  uint8_t *buf = (uint8_t *)malloc(st.st_size);
  if (!buf)
  {
    etaHEN_log("Failed to allocate memory for Plugin file");
    close(fd);
    return false;
  }

  if (read(fd, buf, st.st_size) != st.st_size)
  {
    etaHEN_log("Failed to read Plugin file");
    free(buf);
    close(fd);
    return false;
  }
  close(fd);

  const CustomPluginHeader *header = (const CustomPluginHeader *)buf;
  const char *filename = basename(path);

  if (strstr(filename, ".elf") != NULL)
  {
    etaHEN_log("ELF detected: %s", filename);

    if (!is_elf_file(buf, st.st_size))
    {
      etaHEN_log("Invalid ELF file.");
      notify(true, "Invalid ELF file: %s", filename);
      free(buf);
      return false;
    }

    char pbuf[256];
    snprintf(pbuf, sizeof(pbuf), "/system_tmp/%s.PID", header->titleID);

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
        etaHEN_log("Stale plugin PID file detected for %s, removing", header->titleID);
        unlink(pbuf);
        pid = -1;
      }
    }

    if (pid > 0)
    {
      etaHEN_log("killing pid %d (plugin: %s)", pid, header->titleID);
      kill(pid, SIGKILL);
      unlink(pbuf);
    }

    etaHEN_log("loading elf %s", filename);
    pid = elfldr_spawn("/", STDOUT_FILENO, buf, header->titleID);

    if (pid >= 0)
      etaHEN_log("  Launched!");
    else
      etaHEN_log("  Already Running!");

    free(buf);

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

    return (pid >= 0);
  }

  if (!is_valid_plugin(buf))
  {
    etaHEN_log("Invalid plugin file.");
    free(buf);
    return false;
  }

  etaHEN_log("============== Plugin info ===============");
  etaHEN_log("Plugin Prefix: %s", header->prefix);
  etaHEN_log("Plugin TitleID: %s", header->titleID);
  etaHEN_log("Plugin Version: %s", header->plugin_version);
  etaHEN_log("=========================================");

  char pbuf[256];
  snprintf(pbuf, sizeof(pbuf), "/system_tmp/%s.PID", header->titleID);

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
      etaHEN_log("Stale plugin PID file detected for %s, removing", header->titleID);
      unlink(pbuf);
      pid = -1;
    }
  }

  etaHEN_log("seeing if plugin is running");
  if (pid > 0)
  {
    etaHEN_log("killing pid %d (plugin: %s)", pid, header->titleID);
    kill(pid, SIGKILL);
    unlink(pbuf);
  }

  uint8_t *elf = get_elf_header_address(buf);
  make_plugin_app(header->titleID, elf, st.st_size - sizeof(CustomPluginHeader));

  etaHEN_log("loading plugin %s", path);
  pid = elfldr_spawn("/", STDOUT_FILENO, elf, header->titleID);
  bool success = (pid >= 0);
  if (success)
    etaHEN_log("  Launched!");
  else
    etaHEN_log("  Failed to launch plugin");

  f = open(pbuf, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (f >= 0)
  {
    if (success)
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

  free(buf);
  return success;
}

int launchApp(const char *titleId)
{
	int id = 0;

	uint32_t res = sceUserServiceGetForegroundUser(&id);
	if (res != 0)
	{
		printf("sceUserServiceGetForegroundUser failed: 0x%x\n", res);
		return res;
	}
	etaHEN_log("[LA] user id %u", id);

    LncAppParam param;
	param.sz = sizeof(LncAppParam);
	param.user_id = id;
	param.app_opt = 0;
	param.crash_report = 0;
	param.check_flag = Flag_None;


	puts("calling sceLncUtilLaunchApp");
	int err = sceLncUtilLaunchApp(titleId, NULL, &param);
	etaHEN_log("sceLncUtilLaunchApp returned 0x%x", (uint32_t)err);
	if (err >= 0)
	{
		return err;
	}
	switch ((uint32_t)err)
	{
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
