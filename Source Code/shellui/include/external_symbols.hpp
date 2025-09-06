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
#include <cstdint>
#include <sys/types.h>
#include "monodef.h"

#define SCE_OK 0
struct AppMessage {
    static constexpr size_t PAYLOAD_SIZE = 8192;
    uint32_t sender;
    uint32_t msgType;
    char payload[PAYLOAD_SIZE];
    uint32_t payloadSize;
    uint64_t timestamp;
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
#define SCE_NET_CTL_STATE_DISCONNECTED		0
#define SCE_NET_CTL_STATE_CONNECTING		1
#define SCE_NET_CTL_STATE_IPOBTAINING		2
#define SCE_NET_CTL_STATE_IPOBTAINED		3

/* event type */
#define SCE_NET_CTL_EVENT_TYPE_DISCONNECTED				1
#define SCE_NET_CTL_EVENT_TYPE_DISCONNECT_REQ_FINISHED	2
#define SCE_NET_CTL_EVENT_TYPE_IPOBTAINED				3

/* info code */
#define SCE_NET_CTL_INFO_DEVICE				1
#define SCE_NET_CTL_INFO_ETHER_ADDR			2
#define SCE_NET_CTL_INFO_MTU				3
#define SCE_NET_CTL_INFO_LINK				4
#define SCE_NET_CTL_INFO_BSSID				5
#define SCE_NET_CTL_INFO_SSID				6
#define SCE_NET_CTL_INFO_WIFI_SECURITY		7
#define SCE_NET_CTL_INFO_RSSI_DBM			8
#define SCE_NET_CTL_INFO_RSSI_PERCENTAGE	9
#define SCE_NET_CTL_INFO_CHANNEL			10
#define SCE_NET_CTL_INFO_IP_CONFIG			11
#define SCE_NET_CTL_INFO_DHCP_HOSTNAME		12
#define SCE_NET_CTL_INFO_PPPOE_AUTH_NAME	13
#define SCE_NET_CTL_INFO_IP_ADDRESS			14
#define SCE_NET_CTL_INFO_NETMASK			15
#define SCE_NET_CTL_INFO_DEFAULT_ROUTE		16
#define SCE_NET_CTL_INFO_PRIMARY_DNS		17
#define SCE_NET_CTL_INFO_SECONDARY_DNS		18
#define SCE_NET_CTL_INFO_HTTP_PROXY_CONFIG	19
#define SCE_NET_CTL_INFO_HTTP_PROXY_SERVER	20
#define SCE_NET_CTL_INFO_HTTP_PROXY_PORT	21
#define SCE_NET_CTL_INFO_RESERVED1			22
#define SCE_NET_CTL_INFO_RESERVED2			23

/* device */
#define SCE_NET_CTL_DEVICE_WIRED		0
#define SCE_NET_CTL_DEVICE_WIRELESS	 	1

/* link */
#define SCE_NET_CTL_LINK_DISCONNECTED	0
#define SCE_NET_CTL_LINK_CONNECTED		1

/* wifi_security */
#define SCE_NET_CTL_WIFI_SECURITY_NOAUTH			0
#define SCE_NET_CTL_WIFI_SECURITY_WEP				1
#define SCE_NET_CTL_WIFI_SECURITY_WPAPSK_WPA2PSK	2
#define SCE_NET_CTL_WIFI_SECURITY_WPAPSK_TKIP		3
#define SCE_NET_CTL_WIFI_SECURITY_WPAPSK_AES		4
#define SCE_NET_CTL_WIFI_SECURITY_WPA2PSK_TKIP		5
#define SCE_NET_CTL_WIFI_SECURITY_WPA2PSK_AES		6
#define SCE_NET_CTL_WIFI_SECURITY_UNSUPPORTED		7

/* ip_config */
#define SCE_NET_CTL_IP_DHCP	 	0
#define SCE_NET_CTL_IP_STATIC	1
#define SCE_NET_CTL_IP_PPPOE	2

/* http_proxy_config */
#define SCE_NET_CTL_HTTP_PROXY_OFF	0
#define SCE_NET_CTL_HTTP_PROXY_ON	1

#define SCE_NET_CTL_SSID_LEN				(32 + 1)
#define SCE_NET_CTL_WIFI_SECURITY_KEY_LEN	(64 + 1)
#define SCE_NET_CTL_AUTH_NAME_LEN			(127 + 1)
#define SCE_NET_CTL_AUTH_KEY_LEN			(127 + 1)
#define SCE_NET_CTL_HOSTNAME_LEN			(255 + 1)
#define SCE_NET_CTL_IPV4_ADDR_STR_LEN		(16)

#define SCE_NET_ETHER_ADDR_LEN	6
#define SCE_NET_ETHER_ADDRSTRLEN	18

typedef struct SceNetEtherAddr {
	uint8_t data[SCE_NET_ETHER_ADDR_LEN];
} SceNetEtherAddr;

typedef void (*SceNetCtlCallback)(
	int eventType,		/* SCE_NET_CTL_EVENT_TYPE_XXX */
	void *arg
	);

typedef union SceNetCtlInfo {
	uint32_t device;
	SceNetEtherAddr ether_addr;
	uint32_t mtu;
	uint32_t link;
	SceNetEtherAddr bssid;
	char ssid[SCE_NET_CTL_SSID_LEN];
	uint32_t wifi_security;
	int32_t rssi_dbm;
	uint8_t rssi_percentage;
	uint8_t channel;
	uint32_t ip_config;
	char dhcp_hostname[SCE_NET_CTL_HOSTNAME_LEN];
	char pppoe_auth_name[SCE_NET_CTL_AUTH_NAME_LEN];
	char ip_address[SCE_NET_CTL_IPV4_ADDR_STR_LEN];
	char netmask[SCE_NET_CTL_IPV4_ADDR_STR_LEN];
	char default_route[SCE_NET_CTL_IPV4_ADDR_STR_LEN];
	char primary_dns[SCE_NET_CTL_IPV4_ADDR_STR_LEN];
	char secondary_dns[SCE_NET_CTL_IPV4_ADDR_STR_LEN];
	uint32_t http_proxy_config;
	char http_proxy_server[SCE_NET_CTL_HOSTNAME_LEN];
	uint16_t http_proxy_port;
} SceNetCtlInfo;

// Token: 0x040002CA RID: 714
#define SCE_NET_SHOW_BUFFER_SIZE 8192

// Token: 0x040002CB RID: 715
#define SCE_NET_SHOW_NETSTAT_BUFFER_SIZE 65536

// Token: 0x040002CC RID: 716
#define SCE_NET_ADDR_STR_SIZE 18

// Token: 0x02000060 RID: 96
typedef enum SceNetIfName
{
    // Token: 0x040002CE RID: 718
    SCE_NET_IF_NAME_UNKNOWN = -2,
    // Token: 0x040002CF RID: 719
    SCE_NET_IF_NAME_NONE,
    // Token: 0x040002D0 RID: 720
    SCE_NET_IF_NAME_LO0,
    // Token: 0x040002D1 RID: 721
    SCE_NET_IF_NAME_PHYSICAL,
    // Token: 0x040002D2 RID: 722
    SCE_NET_IF_NAME_ETH0 = 1,
    // Token: 0x040002D3 RID: 723
    SCE_NET_IF_NAME_ETH1,
    // Token: 0x040002D4 RID: 724
    SCE_NET_IF_NAME_DBG0,
    // Token: 0x040002D5 RID: 725
    SCE_NET_IF_NAME_WLAN0,
    // Token: 0x040002D6 RID: 726
    SCE_NET_IF_NAME_WLAN1,
    // Token: 0x040002D7 RID: 727
    SCE_NET_IF_NAME_GBE0,
    // Token: 0x040002D8 RID: 728
    SCE_NET_IF_NAME_BT0,
    // Token: 0x040002D9 RID: 729
    SCE_NET_IF_NAME_PHONE0,
    // Token: 0x040002DA RID: 730
    SCE_NET_IF_NAME_VIRTUAL,
    // Token: 0x040002DB RID: 731
    SCE_NET_IF_NAME_PPPOE0 = 9,
    // Token: 0x040002DC RID: 732
    SCE_NET_IF_NAME_MAX
} SceNetIfName;

// Token: 0x02000061 RID: 97
typedef enum SceNetSockInfo
{
    // Token: 0x040002DE RID: 734
    SCE_NET_SOCKINFO_ALL = 1,
    // Token: 0x040002DF RID: 735
    SCE_NET_SOCKINFO_NAME = 2,
    // Token: 0x040002E0 RID: 736
    SCE_NET_SOCKINFO_EPOLL = 32,
    // Token: 0x040002E1 RID: 737
    SCE_NET_SOCKINFO_TIME_WAIT = 64,
    // Token: 0x040002E2 RID: 738
    SCE_NET_SOCKINFO_IP46 = 4096,
    // Token: 0x040002E3 RID: 739
    SCE_NET_SOCKINFO_SYSTEM = 65536,
    // Token: 0x040002E4 RID: 740
    SCE_NET_SOCKINFO_IPV6 = 131072,
    // Token: 0x040002E5 RID: 741
    SCE_NET_SOCKINFO_DEBUGGABLE_ONLY = 262144
} SceNetSockInfo;

// Token: 0x02000062 RID: 98
typedef enum SceNetIfListFlag
{
    // Token: 0x040002E7 RID: 743
    SCE_NET_IF_LIST_F_UP = 1U,
    // Token: 0x040002E8 RID: 744
    SCE_NET_IF_LIST_F_BROADCAST = 2U,
    // Token: 0x040002E9 RID: 745
    SCE_NET_IF_LIST_F_LOOPBACK = 8U,
    // Token: 0x040002EA RID: 746
    SCE_NET_IF_LIST_F_POINTOPOINT = 16U,
    // Token: 0x040002EB RID: 747
    SCE_NET_IF_LIST_F_RUNNING = 64U,
    // Token: 0x040002EC RID: 748
    SCE_NET_IF_LIST_F_MULTICAST = 32768U,
    // Token: 0x040002ED RID: 749
    SCE_NET_IF_LIST_F_STATIC = 8388608U,
    // Token: 0x040002EE RID: 750
    SCE_NET_IF_LIST_F_INTERNET = 16777216U
} SceNetIfListFlag;

// Token: 0x02000063 RID: 99
typedef enum SceNetIfListIn6Flag
{
    // Token: 0x040002F0 RID: 752
    SCE_NET_IF_LIST_IN6_IFF_TENTATIVE = 2U,
    // Token: 0x040002F1 RID: 753
    SCE_NET_IF_LIST_IN6_IFF_DUPLICATED = 4U,
    // Token: 0x040002F2 RID: 754
    SCE_NET_IF_LIST_IN6_IFF_ASSIGNED_BY_AUTOCONF = 268435456U,
    // Token: 0x040002F3 RID: 755
    SCE_NET_IF_LIST_IN6_IFF_RA_ENABLED = 536870912U,
    // Token: 0x040002F4 RID: 756
    SCE_NET_IF_LIST_IN6_IFF_RA_M_FLAG = 1073741824U,
    // Token: 0x040002F5 RID: 757
    SCE_NET_IF_LIST_IN6_IFF_RA_O_FLAG = 2147483648U
} SceNetIfListIn6Flag;

// Token: 0x02000064 RID: 100
typedef enum SceNetIfListType
{
    // Token: 0x040002F7 RID: 759
    SCE_NET_IF_LIST_TYPE_UNKNOWN,
    // Token: 0x040002F8 RID: 760
    SCE_NET_IF_LIST_TYPE_ETHERNET,
    // Token: 0x040002F9 RID: 761
    SCE_NET_IF_LIST_TYPE_WLAN,
    // Token: 0x040002FA RID: 762
    SCE_NET_IF_LIST_TYPE_BT,
    // Token: 0x040002FB RID: 763
    SCE_NET_IF_LIST_TYPE_PHONE
} SceNetIfListType;

// Token: 0x02000065 RID: 101
typedef enum SceNetConfigEtherLinkMode
{
    // Token: 0x040002FD RID: 765
    SCE_NET_CONFIG_ETHER_LINK_MODE_OFF = 0,
    // Token: 0x040002FE RID: 766
    SCE_NET_CONFIG_ETHER_LINK_MODE_ON = 1,
    // Token: 0x040002FF RID: 767
    SCE_NET_CONFIG_ETHER_LINK_MODE_FD = 2,
    // Token: 0x04000300 RID: 768
    SCE_NET_CONFIG_ETHER_LINK_MODE_AUTO = 4,
    // Token: 0x04000301 RID: 769
    SCE_NET_CONFIG_ETHER_LINK_MODE_10M = 16,
    // Token: 0x04000302 RID: 770
    SCE_NET_CONFIG_ETHER_LINK_MODE_100M = 32,
    // Token: 0x04000303 RID: 771
    SCE_NET_CONFIG_ETHER_LINK_MODE_1G = 64,
    // Token: 0x04000304 RID: 772
    SCE_NET_CONFIG_ETHER_LINK_MODE_2G5 = 128,
    // Token: 0x04000305 RID: 773
    SCE_NET_CONFIG_ETHER_LINK_MODE_5G = 256,
    // Token: 0x04000306 RID: 774
    SCE_NET_CONFIG_ETHER_LINK_MODE_10G = 512,
    // Token: 0x04000307 RID: 775
    SCE_NET_CONFIG_ETHER_LINK_MODE_10M_HD = 17,
    // Token: 0x04000308 RID: 776
    SCE_NET_CONFIG_ETHER_LINK_MODE_10M_FD = 19,
    // Token: 0x04000309 RID: 777
    SCE_NET_CONFIG_ETHER_LINK_MODE_100M_HD = 33,
    // Token: 0x0400030A RID: 778
    SCE_NET_CONFIG_ETHER_LINK_MODE_100M_FD = 35,
    // Token: 0x0400030B RID: 779
    SCE_NET_CONFIG_ETHER_LINK_MODE_1G_FD = 67,
    // Token: 0x0400030C RID: 780
    SCE_NET_CONFIG_ETHER_LINK_MODE_2G5_FD = 131,
    // Token: 0x0400030D RID: 781
    SCE_NET_CONFIG_ETHER_LINK_MODE_5G_FD = 259,
    // Token: 0x0400030E RID: 782
    SCE_NET_CONFIG_ETHER_LINK_MODE_10G_FD = 515,
    // Token: 0x0400030F RID: 783
    SCE_NET_CONFIG_ETHER_LINK_MODE_AUTO_10M_HD = 21,
    // Token: 0x04000310 RID: 784
    SCE_NET_CONFIG_ETHER_LINK_MODE_AUTO_10M_FD = 23,
    // Token: 0x04000311 RID: 785
    SCE_NET_CONFIG_ETHER_LINK_MODE_AUTO_100M_HD = 37,
    // Token: 0x04000312 RID: 786
    SCE_NET_CONFIG_ETHER_LINK_MODE_AUTO_100M_FD = 39,
    // Token: 0x04000313 RID: 787
    SCE_NET_CONFIG_ETHER_LINK_MODE_AUTO_1G_FD = 71,
    // Token: 0x04000314 RID: 788
    SCE_NET_CONFIG_ETHER_LINK_MODE_AUTO_ALL = 119
} SceNetConfigEtherLinkMode;

// Token: 0x02000067 RID: 103
typedef struct SceNetInAddr
{
    // Token: 0x04000316 RID: 790
    uint32_t s_addr;
} SceNetInAddr;

// Token: 0x02000068 RID: 104
typedef struct SceNetIfListAddr
{
    // Token: 0x04000317 RID: 791
    SceNetInAddr addr;
    // Token: 0x04000318 RID: 792
    SceNetInAddr dstaddr;
    // Token: 0x04000319 RID: 793
    SceNetInAddr broadaddr;
    // Token: 0x0400031A RID: 794
    SceNetInAddr netmask;
} SceNetIfListAddr;

// Token: 0x02000069 RID: 105
typedef struct SceNetIn6Addr
{
    // Token: 0x0400031B RID: 795
    uint8_t __u6_addr8[16];
} SceNetIn6Addr;

// Token: 0x0200006A RID: 106
typedef struct SceNetIfListAddr6
{
    // Token: 0x0400031C RID: 796
    SceNetIn6Addr addr;
} SceNetIfListAddr6;

// Token: 0x0200006B RID: 107
typedef struct SceNetIfListPacketStatistics
{
    // Token: 0x0400031D RID: 797
    uint64_t allBytes;
    // Token: 0x0400031E RID: 798
    uint64_t allPackets;
    // Token: 0x0400031F RID: 799
    uint64_t broadcastBytes;
    // Token: 0x04000320 RID: 800
    uint64_t broadcastPackets;
    // Token: 0x04000321 RID: 801
    uint64_t multicastBytes;
    // Token: 0x04000322 RID: 802
    uint64_t multicastPackets;
    // Token: 0x04000323 RID: 803
    uint64_t droppedPackets;
    // Token: 0x04000324 RID: 804
    uint64_t errorPackets;
} SceNetIfListPacketStatistics;

// Token: 0x0200006C RID: 108
typedef struct SceNetIfListStatistics
{
    // Token: 0x04000325 RID: 805
    SceNetIfListPacketStatistics tx;
    // Token: 0x04000326 RID: 806
    SceNetIfListPacketStatistics rx;
} SceNetIfListStatistics;

// Token: 0x0200006D RID: 109
typedef struct SceNetIfList
{
    // Token: 0x04000327 RID: 807
    uint8_t ifname[16];
    // Token: 0x04000328 RID: 808
    uint8_t dstifname[16];
    // Token: 0x04000329 RID: 809
    int ifindex;
    // Token: 0x0400032A RID: 810
    int dstifindex;
    // Token: 0x0400032B RID: 811
    SceNetIfListAddr addrs[2];
    // Token: 0x0400032C RID: 812
    SceNetIfListFlag ifflags;
    // Token: 0x0400032D RID: 813
    SceNetIfListType type;
    // Token: 0x0400032E RID: 814
    SceNetEtherAddr addr;
    // Token: 0x0400032F RID: 815
    int mtu;
    // Token: 0x04000330 RID: 816
    int maxmtu;
    // Token: 0x04000331 RID: 817
    SceNetIfListStatistics drv_statistics;
    // Token: 0x04000332 RID: 818
    SceNetIfListStatistics emu_statistics;
    // Token: 0x04000333 RID: 819
    SceNetConfigEtherLinkMode link_status;
    // Token: 0x04000334 RID: 820
    int reserved1;
    // Token: 0x04000335 RID: 821
    int total_use_timer;
    // Token: 0x04000336 RID: 822
    int tx_bps;
    // Token: 0x04000337 RID: 823
    int rx_bps;
    // Token: 0x04000338 RID: 824
    int max_tx_bps;
    // Token: 0x04000339 RID: 825
    int max_rx_bps;
    // Token: 0x0400033A RID: 826
    SceNetIfListAddr6 addrs6[2];
    // Token: 0x0400033B RID: 827
    uint32_t addrs6_plen[2];
    // Token: 0x0400033C RID: 828
    SceNetIfListIn6Flag addrs6_flags[2];
    // Token: 0x0400033D RID: 829
    uint8_t reserved[52];
} SceNetIfList;

typedef struct
{
    uint64_t pad0;
    char version_str[0x1C];
    uint32_t version;
    uint64_t pad1;
} OrbisKernelSwVersion;

enum Flag
{
    Flag_None = 0,
    SkipLaunchCheck = 1,
    SkipResumeCheck = 1,
    SkipSystemUpdateCheck = 2,
    RebootPatchInstall = 4,
    VRMode = 8,
    NonVRMode = 16
};

typedef struct _LncAppParam
{
    uint32_t sz;
    uint32_t user_id;
    uint32_t app_opt;
    uint64_t crash_report;
    enum Flag check_flag;
}
LncAppParam;


typedef struct app_info {
  uint32_t app_id;
  uint64_t unknown1;
  uint32_t app_type;
  char     title_id[10];
  char     unknown2[0x3c];
} app_info_t;



typedef uint32_t(*SceLncUtilLaunchAppType)(const char* tid, const char* argv[], LncAppParam* param);
extern SceLncUtilLaunchAppType sceLncUtilLaunchApp_dyn;
uint32_t sceLncUtilLaunchApp(const char* tid, const char* argv[], LncAppParam* param);
/* ====================================== Global vars ======================================================*/
extern MonoDomain* Root_Domain;
extern MonoClass* MemoryStream_IO;

/* ====================================== Dynamic SystemService Symbols ===================================*/
extern  int (*sceSystemServiceGetAppIdOfRunningBigApp)(void);
/* ====================================== Remote Play Symbols ======================================*/
extern int (*sceRemoteplayInitialize)(void*, size_t);
extern int (*sceRemoteplayGeneratePinCode)(uint32_t*);
extern  int (*sceSystemServiceGetAppTitleId)(int appid, char* titleid);

extern int (*sceRemoteplayConfirmDeviceRegist)(int*, int*);
extern int (*sceRemoteplayNotifyPinCodeError)(int);

/* ====================================== Dynamic Appmsg Symbols ===================================*/
extern uint32_t(*sceAppMessagingSendMsg)(uint32_t appId, uint32_t msgType, const void* msg, size_t msgLength, uint32_t flags);
extern int (*sceAppMessagingReceiveMsg)(const AppMessage* msg);

/* ====================================== Dynamic libkernel_sys Symbols ===================================*/

extern int (*sceKernelMprotect)(void* addr, size_t len, int prot);
extern int (*sceKernelDebugOutText)(int DBG_CHANNEL, const char* text);


extern int (*sceKernelSendNotificationRequest)(int unk1, OrbisNotificationRequest* req, int size, int unk2);
extern int (*sceKernelMkdir)(const char* path, int mode);


extern  int (*sceKernelGetProsperoSystemSwVersion)(OrbisKernelSwVersion* sw);
extern  int (*scePthreadCreate)(void* thread, const void* attr, void* (*entry) (void*), void* arg, const char* name);

extern int (*sceKernelGetAppInfo)(pid_t pid, app_info_t *info);
extern int (*sceKernelGetProcessName)(int pid, char* name);
extern  int (*sceKernelJitCreateSharedMemory)(int flags, size_t size, int protection, int *destinationHandle);
extern  int (*sceKernelJitCreateAliasOfSharedMemory)(int handle, int protection, int *destinationHandle);
extern  int (*sceKernelJitMapSharedMemory)(int handle, int protection, void **destination);
extern int(*ioctl)(int, int, void*);
extern int (*sceRegMgrGetInt)(long, int*);


/* ====================================== Dynamic Mono Symbols ===================================*/
extern MonoArray* (*mono_array_new)(MonoDomain* domain, MonoClass* eclass, uint32_t size);
extern void (*mono_gchandle_new)(MonoObject* obj, int pinned);
extern MonoClass* (*mono_get_byte_class)();
extern  MonoObject* (*mono_vtable_get_static_field_data)(MonoVTable* vt);
extern char* (*mono_array_addr_with_size)(MonoArray* array, int size, uintptr_t idx);
extern uint64_t(*mono_aot_get_method)(MonoDomain* domain, MonoMethod* method);
extern  void* (*mono_object_unbox)(MonoObject* obj);
extern uint64_t(*mono_compile_method)(MonoMethod* method);
extern const char* (*mono_string_to_utf8)(MonoString* str);
extern void (*mono_free)(void* ptr);
extern MonoDomain* (*mono_get_root_domain)();
extern MonoDomain* (*mono_jit_init_version)(const char* file, const char* runtime_version);
extern MonoClass* (*mono_class_from_name)(MonoImage* image, const char* name_space, const char* name);
extern MonoAssembly* (*mono_domain_assembly_open)(MonoDomain* domain, const char* name);
extern MonoImage* (*mono_assembly_get_image)(MonoAssembly* assembly);
extern MonoMethod* (*mono_property_get_get_method)(MonoProperty* prop);
extern MonoMethod* (*mono_property_get_set_method)(MonoProperty* prop);
extern MonoProperty* (*mono_class_get_property_from_name)(MonoClass* klass, const char* name); //
extern MonoObject* (*mono_runtime_invoke)(MonoMethod* method, void* obj, void** params, MonoObject** exc); //
extern MonoString* (*mono_string_new)(MonoDomain* domain, const char* str); //
extern MonoThread* (*mono_thread_attach)(MonoDomain* domain);
extern MonoMethod* (*mono_class_get_method_from_name)(MonoClass* klass, const char* name, int param_count);//
extern void (*mono_runtime_object_init)(MonoObject* obj);
extern MonoClassField* (*mono_class_get_field_from_name)(MonoClass* klass, const char* name);
extern void (*mono_field_static_set_value)(MonoVTable* vt, MonoClassField* field, void* value);
extern MonoVTable* (*mono_class_vtable)(MonoDomain* domain, MonoClass* klass);
extern MonoImage* (*mono_image_open_from_data)(char* data, uint32_t data_len, int need_copy, MonoImageOpenStatus* status);
extern MonoAssembly* (*mono_assembly_load_from)(MonoImage* image, const char* fname, MonoImageOpenStatus* status);
// extern void (*setenv)(const char*, const char*, int);
extern MonoDomain* (*mono_domain_get)();
extern void (*mono_set_dirs)(const char*, const char*);
extern void (*mono_assembly_setrootdir)(const char*);
extern void (*mono_thread_detach)(MonoThread* thread);
extern MonoThread* (*mono_thread_current)();
extern void (*mono_jit_set_aot_only)(int aot_only);
extern void (*mono_domain_unload)(MonoDomain* domain);
extern MonoMethodDesc* (*mono_method_desc_new)(const char* name, int include_namespace);
extern MonoMethod* (*mono_method_desc_search_in_class)(MonoMethodDesc* desc, MonoClass* klass);
extern void (*mono_method_desc_free)(MonoMethodDesc* desc);
extern MonoObject* (*mono_object_new)(MonoDomain* domain, MonoClass* klass);
extern MonoObject* (*mono_object_new_specific)(MonoVTable* vtable);//mono_object_get_class
extern MonoClass* (*mono_object_get_class)(MonoObject* obj);
extern MonoString *(*mono_object_to_string)(MonoObject *obj, MonoObject **exc);
extern void (*mono_raise_exception)(MonoObject *exception);
extern MonoString* (*getIpMacHost)(uint64_t inst, SceNetIfName name);

/* WRAPPERS */
int sceSystemServiceGetAppId(const char * tid);
void KillAllWithName(const char * name, int signal);
extern "C" void pause_resume_kstuff(KstuffPauseStatus opt, bool notify_user);
