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
#include "tcp.h"
#include <stdio.h>
#include <ps5/payload.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <ini.h>
#include <poll.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include "faulthandler.h"
#include "../extern/tiny-json/tiny-json.hpp"
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <cmd.h>

/*==================== DPI =========================*/
#define PLAYGOSCENARIOID_SIZE 3
#define CONTENTID_SIZE 0x30
#define LANGUAGE_SIZE 8

typedef char playgo_scenario_id_t[PLAYGOSCENARIOID_SIZE];
typedef char language_t[LANGUAGE_SIZE];
typedef char content_id_t[CONTENTID_SIZE];

typedef struct
{
	content_id_t content_id;
	int content_type;
	int content_platform;
} SceAppInstallPkgInfo;

typedef struct {
    const char* uri;
    const char* ex_uri;
    const char* playgo_scenario_id;
    const char* content_id;
    const char* content_name;
    const char* icon_url;
} MetaInfo;

#define NUM_LANGUAGES 30
#define NUM_IDS 64

typedef struct
{
	language_t languages[NUM_LANGUAGES];
	playgo_scenario_id_t playgo_scenario_ids[NUM_IDS];
	content_id_t content_ids[NUM_IDS];
    long unknown[810];
} PlayGoInfo;
/*==================== DPI =========================*/

/*================== Networking =================*/
typedef struct SceNetEtherAddr
{
	uint8_t data[6];
} SceNetEtherAddr;

typedef union SceNetCtlInfo
{
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

int32_t sceNetCtlGetInfo(int32_t s, SceNetCtlInfo *b);
void sceNetCtlTerm(void);
/*================== Networking =================*/

typedef struct notify_request
{
	char useless1[45];
	char message[3075];
} notify_request_t;

/*================ SETTINGS ==============*/
typedef struct
{
	bool FTP;
	bool discord_rpc;
	bool has_ftp_dev;
	bool allow_data;
	bool DPI;
	bool lite;
	bool toolbox_auto_start;
	bool DPI_v2;
	bool klog;
	bool disable_toolbox_for_rest;
	uint64_t seconds;
} util_settings;

extern util_settings global_conf;
/*================ SETTINGS ==============*/
// Define your custom header structure for clarity
typedef struct
{
	char prefix[14];  // "etaHEN_PLUGIN" + null terminator
	char titleID[10]; // 4 uppercase letters, 5 numbers, and a null terminator
	char plugin_version[5];
} CustomPluginHeader;

bool load_plugin(const char *path);

/*================== Threads =================*/
extern pthread_t dpi_thread;
extern pthread_t discordRpcServerThread;
extern pthread_t ftp;
extern pthread_t klog_thread;
extern pthread_t kernelrw_thread;
/*================== Threads =================*/
extern atomic_bool g_running;
/*============ Back up JB server ==============*/
enum Commands
{
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

typedef struct
{
	int32_t type;			 // 0x00
	int32_t req_id;			 // 0x04
	int32_t priority;		 // 0x08
	int32_t msg_id;			 // 0x0C
	int32_t target_id;		 // 0x10
	int32_t user_id;		 // 0x14
	int32_t unk1;			 // 0x18
	int32_t unk2;			 // 0x1C
	int32_t app_id;			 // 0x20
	int32_t error_num;		 // 0x24
	int32_t unk3;			 // 0x28
	char use_icon_image_uri; // 0x2C
	char message[1024];		 // 0x2D
	char uri[1024];			 // 0x42D
	char unkstr[1024];		 // 0x82D
} OrbisNotificationRequest;	 // Size = 0xC30


#define SCE_LNC_UTIL_ERROR_ALREADY_RUNNING 0x8094000c
#define SCE_LNC_ERROR_APP_NOT_FOUND 0x80940031

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

int sceUserServiceGetForegroundUser(int *userId);
int sceLncUtilLaunchApp(const char* tid, const char* argv[], LncAppParam* param);
uint32_t sceLncUtilKillApp(uint32_t appId);
bool copyFile(const char *source, const char *destination);

bool start_klog(void);
void stop_klog(void);
bool StartFTP(void);
void shutdownDirectPKGInstaller(bool is_v2);
void ShutdownFTP(void);
int32_t sceKernelSendNotificationRequest(int32_t device, OrbisNotificationRequest *req, size_t size, int32_t blocking);

bool IniliatizeHTTP(void);
bool download_file(const char *url, const char *dst);
bool check_for_new_commit();
bool extract_zip(const char *zip_path, const char *extract_dir);


/*============ Back up JB server ==============*/
void *startDiscordRpcServer(void *unused);
int get_ip_address(char *ip_address);
void etaHEN_log(const char *fmt, ...);
bool touch_file(const char *destfile);
void notify(bool show_watermark, const char *text, ...);
int sceNetCtlInit(void);
int sceUserServiceInitialize(void *ptr);
bool patchShellCore(void);