#pragma once

extern "C" {
	#include <stdint.h>
	#include <stddef.h>
}

namespace {

static constexpr size_t NID_LENGTH = 11;

}

union Nid {

	char str[NID_LENGTH + 1]; // 12th character is for NULL terminator to allow constexpr constructor
	struct __attribute__((packed)) data_t {
		int_fast64_t low;
		int_fast32_t hi;
	} data;

	Nid() noexcept = default;

	explicit constexpr Nid(const char *nid) noexcept : str{} {
		__builtin_memcpy(str, nid, NID_LENGTH);
		str[NID_LENGTH] = '\0';
	}

	constexpr int_fast64_t operator<=>(const Nid& rhs) const {
		auto i = data.low - rhs.data.low;
		if (i == 0) [[unlikely]] {
			return data.hi - rhs.data.hi;
		}
    	return i;
	}

	constexpr bool operator==(const Nid &rhs) const {
		return data.low == rhs.data.low && data.hi == rhs.data.hi;
	}

	constexpr void setNullTerminator() {
		str[NID_LENGTH] = '\0';
	}
};

namespace nid {

static inline constexpr Nid get_authinfo{"igMefp4SAv0"};
static inline constexpr Nid sceFsUmountGamePkg{"UQTSykySQ40"};
static inline constexpr Nid abort{"L1SBTkC+Cvw"};
static inline constexpr Nid strstr{"viiwFMaNamA"};
static inline constexpr Nid sceSystemServiceGetAppStatus{"t5ShV0jWEFE"};
static inline constexpr Nid sceSystemServiceAddLocalProcess{"0cl8SuwosPQ"};
static inline constexpr Nid socketpair{"MZb0GKT3mo8"};
static inline constexpr Nid usleep{"QcteRwbsnV0"};
static inline constexpr Nid _errno{"9BcDykPmo1I"};
static inline constexpr Nid sceSysmoduleLoadModuleInternal{"39iV5E1HoCk"};
static inline constexpr Nid sceSysmoduleLoadModuleByNameInternal{"CU8m+Qs+HN4"};
static inline constexpr Nid mmap{"BPE9s9vQQXo"};
static inline constexpr Nid sceSysmoduleLoadModule{"g8cM39EUZ6o"};
static inline constexpr Nid munmap{"UqDGjXA5yUM"};
static inline constexpr Nid sceKernelJitCreateSharedMemory{"avvJ3J0H0EY"};
static inline constexpr Nid sceKernelUnloadModule{"QKd0qM58Qes"};
static inline constexpr Nid socket{"TU-d9PfIHPM"};
static inline constexpr Nid pipe{"-Jp7F+pXxNg"};
static inline constexpr Nid sceKernelDlsym{"LwG8g3niqwA"};
static inline constexpr Nid setsockopt{"fFxGkxF2bVo"};
static inline constexpr Nid execve{"kdguLiAheLI"};
static inline constexpr Nid _nanosleep{"NhpspxdjEKU"};
static inline constexpr Nid close{"bY-PO6JhzhQ"};
static inline constexpr Nid connect{"XVL8So3QJUk"};
static inline constexpr Nid send{"fZOeZIOEmLw"};
static inline constexpr Nid recv{"Ez8xjo9UF4E"};
static inline constexpr Nid rfork_thread{"bSDxEpGzmUE"};
static inline constexpr Nid access{"8vE6Z6VEYyk"};
static inline constexpr Nid sceKernelOpen{"1G3lF1Gg1k8"};
static inline constexpr Nid mono_aot_get_method{"6t5G5dYpMVg"};
static inline constexpr Nid sceKernelLoadStartModule{"wzvqT4UqKX8"};
static inline constexpr Nid sceKernelDebugOutText("9JYNqN6jAKI");
static inline constexpr Nid sceKernelGetFsSandboxRandomWord("JGfTMBOdUJo");
static inline constexpr Nid open("wuCroIGjt2g");

static inline constexpr Nid ioctl("PfccT7qURYE");
static inline constexpr Nid getpid("HoLVWNanBBc"); 

static inline constexpr Nid gettimeofday("n88vx3C5nW8");
static inline constexpr Nid sceKernelSendNotificationRequest("zl7hupSO0C0");

static inline constexpr Nid sceGnmSubmitAndFlipCommandBuffersForWorkload("Ga6r7H6Y0RI");


static inline constexpr Nid mono_get_root_domain{"5a8b+s6HtaA"};
static inline constexpr Nid mono_property_get_get_method{"uzLsJUMjvLY"};
static inline constexpr Nid mono_property_get_set_method{"BhrEyM1kGW8"};
static inline constexpr Nid mono_class_get_property_from_name{"KK8Cr0wE81M"};
static inline constexpr Nid mono_class_from_name{"bzxTZSnnB38"};
static inline constexpr Nid mono_runtime_invoke{"pre9BjkyDhs"};
static inline constexpr Nid mono_string_new{"pXv-WCokNsY"};
static inline constexpr Nid mono_assembly_get_image{"xP4EC4Sp9GI"};
static inline constexpr Nid mono_domain_assembly_open{"dCeihPtadCM"};
static inline constexpr Nid mono_thread_attach{"qqUxjwJzc2I"};

static inline constexpr Nid mono_class_get_method_from_name{"H5IByLixeaI"};
static inline constexpr Nid scePadReadState{"YndgXqQVV7c"};
static inline constexpr Nid strlen{"j4ViWNHEgww"};
static inline constexpr Nid sceAppInstUtilInstallByPackage{"tDtjgaXYmuo"};

static inline constexpr Nid sceKernelIsDevelopmentMode{"UtO0OHMCgmI"};
}
