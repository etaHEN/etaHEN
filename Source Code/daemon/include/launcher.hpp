#pragma once

#include <stdint.h>

#define SCE_LNC_UTIL_ERROR_ALREADY_RUNNING 0x8094000c
#define SCE_LNC_ERROR_APP_NOT_FOUND 0x80940031

enum Flag : uint64_t {
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
};


struct LncAppParam {
    uint32_t sz;
    int user_id;
    uint32_t app_opt;
    uint64_t crash_report;
    Flag check_flag;
};

extern "C" int sceUserServiceGetForegroundUser(int *userId);
extern "C" int sceLncUtilLaunchApp(const char* tid, const char* argv[], LncAppParam* param);
extern "C" uint32_t sceLncUtilKillApp(uint32_t appId);
