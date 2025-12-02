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

#include <string>
#include <vector>
#include <unistd.h>
#include <atomic>
#include <pthread.h>
#include <sys/sysctl.h>

#include "dbg/dbg.hpp"
#include "elf/elf.hpp"
#include "hijacker/hijacker.hpp"
#include "ipc.hpp"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ps5/kernel.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>


// External C declarations
extern "C" {
    #include "common_utils.h"
    #include "global.h"
    #include "pt.h"

    int sceUserServiceGetUserName(const int userId, char *userName, const size_t size);
    int _sceApplicationGetAppId(int pid, int32_t *appId);
    int sceSystemServiceGetAppTitleId(uint32_t appId, char *titleId);
    int sceLncUtilGetAppStatusList(AppStatus *outStatusList, uint32_t numEntries, uint32_t *outEntries);
    int sceKernelGetProcessName(int pid, char *out);
    int sceKernelIsGenuineDevKit();

    extern uint8_t shellui_elf_start[];
    extern const unsigned int shellui_elf_size;

    // Atomic state variables
    atomic_bool rest_mode_action = false;
    atomic_bool no_network_rest_mode_action = false;
    atomic_bool no_network_patched = false;
    atomic_bool real_rest_mode_detected = false;
}

// Types and Constants
enum write_flag : uint32_t {
    no_flag = 0,
    isOffsetConfigureOutput = 1 << 1,
    isOffsetVideoModeSupported = 1 << 2,
};

struct Command {
    unsigned int magic = 0;
    Commands cmd = INVALID_CMD;
    int PID = -1;
    int ret = 0;
    char msg1[0x500];
    char msg2[0x500];
};

// Firmware version constants
static constexpr uint32_t VERSION_MASK = 0xffff0000;
static constexpr uint32_t V100 = 0x1000000;
static constexpr uint32_t V101 = 0x1010000;
static constexpr uint32_t V102 = 0x1020000;
static constexpr uint32_t V105 = 0x1050000;
static constexpr uint32_t V110 = 0x1100000;
static constexpr uint32_t V111 = 0x1110000;
static constexpr uint32_t V112 = 0x1120000;
static constexpr uint32_t V113 = 0x1130000;
static constexpr uint32_t V114 = 0x1140000;
static constexpr uint32_t V200 = 0x2000000;
static constexpr uint32_t V220 = 0x2200000;
static constexpr uint32_t V225 = 0x2250000;
static constexpr uint32_t V226 = 0x2260000;
static constexpr uint32_t V230 = 0x2300000;
static constexpr uint32_t V250 = 0x2500000;
static constexpr uint32_t V270 = 0x2700000;
static constexpr uint32_t V300 = 0x3000000;
static constexpr uint32_t V310 = 0x3100000;
static constexpr uint32_t V320 = 0x3200000;
static constexpr uint32_t V321 = 0x3210000;
static constexpr uint32_t V400 = 0x4000000;
static constexpr uint32_t V402 = 0x4020000;
static constexpr uint32_t V403 = 0x4030000;
static constexpr uint32_t V450 = 0x4500000;
static constexpr uint32_t V451 = 0x4510000;
static constexpr uint32_t V500 = 0x5000000;
static constexpr uint32_t V502 = 0x5020000;
static constexpr uint32_t V510 = 0x5100000;
static constexpr uint32_t V550 = 0x5500000;
static constexpr uint32_t V600 = 0x6000000;
static constexpr uint32_t V602 = 0x6020000;
static constexpr uint32_t V650 = 0x6500000;
static constexpr uint32_t V700 = 0x7000000;
static constexpr uint32_t V701 = 0x7010000;
static constexpr uint32_t V720 = 0x7200000;
static constexpr uint32_t V740 = 0x7400000;
static constexpr uint32_t V760 = 0x7600000;
static constexpr uint32_t V761 = 0x7610000;
//new
static constexpr uint32_t V800 = 0x8000000;
static constexpr uint32_t V820 = 0x8200000;
static constexpr uint32_t V840 = 0x8400000;
static constexpr uint32_t V860 = 0x8600000;
static constexpr uint32_t V900 = 0x9000000;
static constexpr uint32_t V905 = 0x9050000;
static constexpr uint32_t V920 = 0x9200000;
static constexpr uint32_t V940 = 0x9400000;
static constexpr uint32_t V960 = 0x9600000;
static constexpr uint32_t V1000 = 0x10000000;
static constexpr uint32_t V1001 = 0x10010000;
static constexpr uint32_t V1020 = 0x10200000;
static constexpr uint32_t V1040 = 0x10400000;
static constexpr uint32_t V1060 = 0x10600000;
// Global variables
char ip_address[40];
pid_t g_ShellCorePid = 0;
char backupShellCoreBytes[5] = {0};
uint64_t shellcore_offset_patch = 0;
int numb_of_tries = 0;
int retries = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t jb_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_t discordRpcServerThread = NULL;
pthread_t ftp = NULL;
pthread_t dpi_thread = NULL;
pthread_t kernelrw_thread = NULL;
extern atomic_bool not_connected;

// Function forward declarations
void *start_ftp(void *args);
void *klog(void *args);
void *krw_server(void *args);
bool RunDPIThread();
void etaHEN_log(const char *fmt, ...);
void notify(bool show_watermark, const char *text, ...);
bool if_exists(const char *path);
bool LoadSettings();
uint32_t getSystemSwVersion();
void check_addr_change(void);
int get_ip_address(char *ip_address);

// Hex lookup table for string-to-byte conversion
const uint8_t hex_lut[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

// Process management functions
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

int get_shellcore_pid() {
    int pid = -1;
    size_t NumbOfProcs = 9999;

    for (int j = 0; j <= NumbOfProcs; j++) {
        char tmp_buf[500];
        memset(tmp_buf, 0, sizeof(tmp_buf));
        sceKernelGetProcessName(j, tmp_buf);
        if (strcmp( "SceShellCore", tmp_buf) == 0) {
            pid = j;
            break;
        }
    }

    return pid == -1 ? find_pid("SceShellCore") : pid;
}


bool enable_toolbox() {
    int wait = 0, DaemonSocket = 0;
    const char *path = "/system_tmp/etaHEN_crit_service";
    while (!if_exists(path)) {
        sleep(1);

        if (wait > 20) {
            notify(true, "Failed to load the etaHEN toolbox");
            return false;
        }

        wait++;
    }

    sockaddr_un server;
    DaemonSocket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (DaemonSocket == -1) {
        etaHEN_log("Failed to create socket");
        return false;
    }
    
    server.sun_family = AF_UNIX;
    strncpy(server.sun_path, path, sizeof(server.sun_path) - 1);
    if (connect(DaemonSocket, (struct sockaddr *)&server, SUN_LEN(&server)) == -1) {
        close(DaemonSocket);
        etaHEN_log("Failed to connect to socket");
        return false;
    }

    IPCMessage msg;
    msg.cmd = BREW_ENABLE_TOOLBOX;
    snprintf(msg.msg, sizeof(msg.msg), "{ \"titleId\": \"ETAH00002\" }");
    if (send(DaemonSocket, reinterpret_cast<const void *>(&msg), sizeof(msg),
            MSG_NOSIGNAL) < 0) {
        close(DaemonSocket);
        etaHEN_log("Failed to send message to daemon");
        return false;
    }

    if (recv(DaemonSocket, reinterpret_cast<void *>(&msg), sizeof(msg),
            MSG_NOSIGNAL) < 0) {
        close(DaemonSocket);
        etaHEN_log("Failed to receive message from daemon");
        return false;
    }

    close(DaemonSocket);
    return msg.error == 0;
}

bool isProcessAlive(int pid) noexcept {
    int mib[]{CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    return sysctl(mib, 4, nullptr, nullptr, nullptr, 0) == 0;
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

// Pattern scanning and memory functions
static uint32_t pattern_to_byte(const char *pattern, uint8_t *bytes) {
    uint32_t count = 0;
    const char *start = pattern;
    const char *end = pattern + strlen(pattern);

    for (const char *current = start; current < end; ++current) {
        if (*current == '?') {
            ++current;
            if (*current == '?') {
                ++current;
            }
            bytes[count++] = -1;
        } else {
            bytes[count++] = strtoul(current, (char **)&current, 16);
        }
    }
    return count;
}

__attribute__((noinline)) static uint8_t* hexstrtochar2(const char* hexstr, size_t* size) {
    if (!hexstr || *hexstr == '\0' || !size || *size < 0) {
        return nullptr;
    }

    uint32_t str_len = strlen(hexstr);
    size_t data_len = ((str_len + 1) / 2) * sizeof(uint8_t);
    *size = (str_len) * sizeof(uint8_t);
    uint8_t* data = (uint8_t*)malloc(*size);

    if (!data) {
        return nullptr;
    }

    uint32_t j = 0; // hexstr position
    uint32_t i = 0; // data position

    if (str_len % 2 == 1) {
        data[i] = (uint8_t)(hex_lut[0] << 4) | hex_lut[(uint8_t)hexstr[j]];
        j = ++i;
    }

    for (; j < str_len; j += 2, i++) {
        data[i] = (uint8_t)(hex_lut[(uint8_t)hexstr[j]] << 4) |
            hex_lut[(uint8_t)hexstr[j + 1]];
    }

    *size = data_len;
    return data;
}

void write_bytes32(pid_t pid, uint64_t addr, const uint32_t val) {
    etaHEN_log("addr: 0x%lx", addr);
    etaHEN_log("val: 0x%08x", val);
    dbg::write(pid, addr, (void*)&val, sizeof(uint32_t));
}

void write_bytes(pid_t pid, uint64_t addr, const char* hexString) {
    uint8_t* byteArray = nullptr;
    size_t bytesize = 0;
    byteArray = hexstrtochar2(hexString, &bytesize);

    if (!byteArray) {
        return;
    }

    etaHEN_log("addr: 0x%lx", addr);
    dbg::write(pid, addr, byteArray, bytesize);

    dbg::read(pid, addr, byteArray, bytesize);
    if (byteArray) {
        etaHEN_log("freeing byteArray at 0x%p", byteArray);
        free(byteArray);
    }
}
uint8_t *PatternScan(const uint64_t module_base, const uint64_t module_size, const char *signature) {
    etaHEN_log("module_base: 0x%lx module_size: 0x%lx", module_base, module_size);
    if (!module_base || !module_size) {
        return nullptr;
    }

    uint8_t patternBytes[256];
    (void)memset(patternBytes, 0, 256);
    int32_t patternLength = pattern_to_byte(signature, patternBytes);
    
    if (patternLength <= 0 || patternLength >= 256) {
        etaHEN_log("Pattern length too large or invalid! %i (0x%08x)", patternLength, patternLength);
        etaHEN_log("Input Pattern %s", signature);
        return nullptr;
    }
    
    uint8_t *scanBytes = (uint8_t *)module_base;
    for (uint64_t i = 0; i < module_size; ++i) {
        bool found = true;
        for (int32_t j = 0; j < patternLength; ++j) {
            if (scanBytes[i + j] != patternBytes[j] && patternBytes[j] != 0xff) {
                found = false;
                break;
            }
        }
        if (found) {
            etaHEN_log("found pattern at 0x%p", &scanBytes[i]);
            return &scanBytes[i];
        }
    }
    
    return nullptr;
}
// Shell patch functions
bool patchShellCore() {
    const UniquePtr<Hijacker> executable = Hijacker::getHijacker(get_shellcore_pid());
    uintptr_t shellcore_base = 0;
    uint64_t shellcore_size = 0;

    if (executable) {
        shellcore_base = executable->getEboot()->getTextSection()->start();
        shellcore_size = executable->getEboot()->getTextSection()->sectionLength();
        g_ShellCorePid = executable->getPid();
    }
    else {
        notify(true, "SceShellCore not found");
        return false;
    }

    bool status = false;
    (void)memset(backupShellCoreBytes, 0, sizeof(backupShellCoreBytes));
    shellcore_offset_patch = 0;

    if (!shellcore_base || !shellcore_size) {
        return false;
    }

    etaHEN_log("allocating 0x%lx bytes", shellcore_size);
    char* shellcore_copy = (char*)malloc(shellcore_size);
    etaHEN_log("shellcore_copy: 0x%p", shellcore_copy);

    if (!shellcore_copy) {
        etaHEN_log("shellcore_copy is nullptr");
        return false;
    }

    if (dbg::read(g_ShellCorePid, shellcore_base, shellcore_copy, shellcore_size)) {
        uint8_t* shellcore_offset_data1 = nullptr;
        uint8_t* shellcore_offset_data2 = nullptr;
        uint8_t* patch_checker_offset = 0;

        switch (getSystemSwVersion() & VERSION_MASK) {
        case V200:
        case V220:
        case V225:
        case V226:
        case V230:
        case V250:
        case V270:
            shellcore_offset_data1 = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "e8 ?? ?? ec 00 48 89 9d"
            );
            shellcore_offset_data2 = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "e8 ?? ?? b1 00 83 f8"
            );
            patch_checker_offset = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec 00 02 00 00 49"
            );
            break;
        case V300:
        case V310:
        case V320:
        case V321:
            shellcore_offset_data1 = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "e8 ?? ?? 00 01 ?? 89 ?? 40"
            );
            shellcore_offset_data2 = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "e8 ?? ?? c5 00 83 f8 01 75 5f"
            );
            patch_checker_offset = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec 00 02 00 00 49"
            );
            break;
        case V400:
        case V402:
        case V403:
        case V450:
        case V451:
            shellcore_offset_data1 = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "e8 ?? ?? ?? ?? 4c 89 bd ?? ?? ?? ?? 48 89 9d ?? ?? ?? ??"
            );
            shellcore_offset_data2 = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "e8 ?? ?? ?? ?? 83 f8 01 75 ?? 41 80 3c 24 00"
            );
            patch_checker_offset = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec 00 02 00 00 49"
            );
            break;
        case V500:
        case V502:
        case V510:
        case V550:
            shellcore_offset_data1 = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "e8 ?? ?? fb 00 85 c0 75 0d e8 ?? ?? fb 00 85 c0 0f 84 47"
            );
            shellcore_offset_data2 = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "e8 ?? ?? c7 00 83 f8 01 75 5e"
            );
            patch_checker_offset = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec e0 01 00 00 49"
            );
            break;
        case V600:
        case V602:
        case V650:
            shellcore_offset_data1 = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "e8 ?? ?? ?? 01 4c 89 a5 80"
            );
            shellcore_offset_data2 = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "e8 ?? ?? ?? 00 83 f8 01 75 66"
            );
            patch_checker_offset = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec e0 01 00 00 49"
            );
            break;
        case V700: case V701: case V720: case V740: case V760: case V761:
            shellcore_offset_data1 = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "e8 ?? ?? ?? 01 4c 89 b5 80"
            );
            shellcore_offset_data2 = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "e8 ?? ?? d7 00 83 f8 01 0f 85 cd"
            );
            patch_checker_offset = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec e0 01 00 00 49 89 cd"
            );
            break;
        case V800: case V820:
            shellcore_offset_data1 = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 c1"
            );
            shellcore_offset_data2 = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "e8 ?? ?? dc 00 83 f8 01 0f"
            );
            patch_checker_offset = PatternScan(
                (uint64_t)shellcore_copy, shellcore_size,
                "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 49 89 cd"
            );
            break;
        default:
            etaHEN_log("Unknown firmware: 0x%08x", getSystemSwVersion());
            break;
        }

        etaHEN_log("shellcore_offset_data1: 0x%p", shellcore_offset_data1);
        etaHEN_log("shellcore_offset_data2: 0x%p", shellcore_offset_data2);
        etaHEN_log("patch_checker_offset: 0x%p", patch_checker_offset);


        // uint64_t addr = shellcore_base +  (uint64_t)0x10C01F0;
        // write_bytes(g_ShellCorePid, addr, "554889E5B8142618805DC3");




        if (shellcore_offset_data1 && shellcore_offset_data2) {
            const uint64_t shellcore_offset_patch1 = shellcore_base +
                ((uint64_t)shellcore_offset_data1 - (uint64_t)shellcore_copy);
            const uint64_t shellcore_offset_patch2 = shellcore_base +
                ((uint64_t)shellcore_offset_data2 - (uint64_t)shellcore_copy);

            write_bytes(g_ShellCorePid, shellcore_offset_patch1, "b801000000");
            write_bytes(g_ShellCorePid, shellcore_offset_patch2, "b801000000");

            etaHEN_log("Patched shellcore for `/data` mount\n"
                "g_ShellCorePid: 0x%08x\n"
                "mkdir(\"/user/devbin\", 0777): 0x%08x\n"
                "mkdir(\"/user/devlog\", 0777): 0x%08x",
                g_ShellCorePid, mkdir("/user/devbin", 0777),
                mkdir("/user/devlog", 0777));
        }

        if (patch_checker_offset) {
            shellcore_offset_patch = shellcore_base +
                ((uint64_t)patch_checker_offset - (uint64_t)shellcore_copy);
            etaHEN_log("shellcore_offset_patch: 0x%lx", shellcore_offset_patch);
            write_bytes(g_ShellCorePid, shellcore_offset_patch, "554889E5B8142618805DC3");
        }
    }

    if (shellcore_copy) {
        etaHEN_log("freeing shellcore_copy from 0x%p", shellcore_copy);
        free(shellcore_copy);
        shellcore_copy = nullptr;
    }

    return status;
}

// Command server functions
static void replyError(int sock) {
    Command cmd;
    cmd.ret = -1;
    send(sock, reinterpret_cast<void *>(&cmd), sizeof(cmd), MSG_NOSIGNAL);
}

static void replyOk(int sock) {
    const Command cmd{};
    send(sock, &cmd, sizeof(cmd), MSG_NOSIGNAL);
}

void cmd_server(int sock, Command &cmd) {
    pthread_mutex_lock(&jb_lock);
    UniquePtr<Hijacker> spawned = nullptr;
    etaHEN_log("command: %u", cmd.cmd);
    
    if (cmd.cmd == 0) {
        numb_of_tries++;
    }

    if (numb_of_tries > 40) {
        numb_of_tries = 0;
    }

    switch (cmd.cmd) {
    case JAILBREAK_CMD:
        if (cmd.magic != 0xDEADBEEF) {
            notify(true, "Jailbreak failed, magic is invaild");
            replyError(sock);
            break;
        }
        if (cmd.PID == -1 || !isProcessAlive(cmd.PID)) {
            notify(true, "Jailbreak failed, PID is invaild");
            replyError(sock);
            break;
        }
        
        etaHEN_log("WRONG Jailbreak command received: jailbreaking...");
        {
            do { 
                spawned = Hijacker::getHijacker(cmd.PID);
                if (spawned == nullptr) {
                    if (isProcessAlive(cmd.PID)) {
                        etaHEN_log("process died");
                        break;
                    }
                    retries++;
                    if (retries > 30) {
                        notify(true, "Jailbreak failed, PID is invaild");
                        etaHEN_log("Jailbreak failed, PID is invaild");
                        break;
                    }
                }
                etaHEN_log("is null for PID %d", cmd.PID);
            } while (spawned == nullptr);

            retries = 0;

            notify(true, "[Legacy] App has been granted a jailbreak\n\nAn update for "
                      "this PKG is available");
            spawned->jailbreak(true);
            etaHEN_log("jailbroke app %s", cmd.msg1);
        }
        replyOk(sock);
        break;
        
    case INVALID_CMD:
        puts("invalid command");
        replyError(sock);
        break;
        
    default:
        puts("default command");
        notify(true, "Update the PKG you are using before continuing\nGot Command %i",
              cmd.cmd);
        replyError(sock);
        break;
    }
    
    pthread_mutex_unlock(&jb_lock);
}

void *runCommandNControlServer(void *) {
    int client = -1;
    int s = -1;
    int readSize = 0;
    Command cmd;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1) {
        notify(true, "Failed to create socket %s", strerror(errno));
        return nullptr;
    }

    struct sockaddr_in sockaddr;
    bzero(&sockaddr, sizeof(sockaddr));

    int optval = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(9028);
    sockaddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (const struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
        notify(true, "Failed to bind to port 9028 %s", strerror(errno));
        return nullptr;
    }

    if (listen(s, 5) < 0) {
        notify(true, "Failed to listen on port 9028 %s", strerror(errno));
        return nullptr;
    }

    if(global_conf.legacy_cmd_server)
	   etaHEN_log("[Daemon LEGACY IPC] Server started on port 9028");

    // Accept clients
    while (!global_conf.legacy_cmd_server_exit) {
        client = accept(s, 0, 0);
        if (errno == 0xA3) {
            pthread_mutex_lock(&jb_lock);
            rest_mode_action = true;
            pthread_mutex_unlock(&jb_lock);
            break;
        }
        if (client > 0 && global_conf.legacy_cmd_server) {
            etaHEN_log("[Daemon IPC] Client connected");
            while ((readSize = recv(client, reinterpret_cast<void *>(&cmd),
                                  sizeof(cmd), MSG_NOSIGNAL)) > 0) {
                if (cmd.magic == 0xDEADBEEF ) {
                    cmd_server(client, cmd);
                } else {
                    etaHEN_log("[Daemon IPC] Invalid magic number");
                }
            }
        }
    }

    if (client >= 0)
        close(client), client = -1;

    if (s >= 0)
        close(s), s = -1;

    etaHEN_log("[Daemon IPC] Server stopped");

    if (global_conf.legacy_cmd_server_exit) {
        global_conf.legacy_cmd_server_exit = false;
		return runCommandNControlServer(nullptr);
    }
    return nullptr;
}

// Network monitoring and restart functionality
void check_addr_change(void) {
    pthread_mutex_lock(&jb_lock);
    char func_ip_address[40];

    if (get_ip_address(&func_ip_address[0]) < 0) {
        pthread_mutex_unlock(&jb_lock);
        return;
    }

    if (get_ip_address(&ip_address[0]) < 0) {
        pthread_mutex_unlock(&jb_lock);
        return;
    }

    bool ip_changed = strcmp(&ip_address[0], &func_ip_address[0]) != 0;
    if (ip_changed || rest_mode_action) {
        if (ip_changed || !real_rest_mode_detected) {
            notify(true, "IP Address changed to %s, restarting server(s)",
                  func_ip_address);
        } else if (rest_mode_action && !no_network_patched && !not_connected &&
                  real_rest_mode_detected) {
            LoadSettings();
            etaHEN_log("sleeping for %lld secs", global_conf.seconds);
            sleep(global_conf.seconds);
            notify(true, "Coming out of Rest Mode detected, restarting server(s)");
            etaHEN_log("waiting for logged in user");
            
            while (!isUserLoggedIn()) {
                sleep(2);
            }
            
            etaHEN_log("user is logged in");
            etaHEN_log("Coming out rest mode, activating patches");
            

            if (global_conf.toolbox_auto_start  && !global_conf.disable_toolbox_for_rest && !enable_toolbox()) {
                notify(true, "Failed to inject toolbox");
            }
        }
        
        real_rest_mode_detected = not_connected = no_network_patched = rest_mode_action = false;
    }
    
    pthread_mutex_unlock(&jb_lock);
}

void *ip_thread(void *arg) {
    (void)arg;
    do {
        sleep(1);
    } while (get_ip_address(&ip_address[0]) < 0);

    while (true) {
        check_addr_change();
        sleep(2);
    }
}

void start_ip_thread(void) {
    pthread_t ip_thread_thr;
    pthread_create(&ip_thread_thr, NULL, ip_thread, NULL);
    pthread_detach(ip_thread_thr);
}

// System recovery and patch checker
void patch_checker() {
    if (!isUserLoggedIn()) {
        etaHEN_log("User is not logged in yet, skipping...");
        return;
    }

    LoadSettings();
    if(global_conf.disable_toolbox_for_rest){
        etaHEN_log("Toolbox auto start for rest mode is disabled");
        return;
    }
    etaHEN_log("sleeping for %lld secs", global_conf.seconds);
    sleep(global_conf.seconds);

    notify(true, "(No Network) Coming out of Rest Mode detected\nre-activating "
                "the etaHEN toolbox...");

    etaHEN_log("************************************\n\nShellUI is not "
              "patched\n\n************************************");

    if (!enable_toolbox()) {
        notify(true, "Failed to inject toolbox");
    }
    
    no_network_rest_mode_action = false;
    no_network_patched = true;
    real_rest_mode_detected = false;
}

bool patchShellActi() {

   return false;
}
