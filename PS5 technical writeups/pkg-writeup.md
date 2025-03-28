# PS5 Package Installation: Writeup

## Introduction

Years ago we got [Flatz's Writeup](https://flatz.github.io/) on Installing PKGs on the PS4, however, the same method no longer works on the PS5, so today I am carrying the torch and releasing an updated PKG Installation writeup for the PS5

## Prerequisites

This implementation requires one of the following privilege escalation methods:

1. **Auth ID Modification**: Modify the auth ID within the `struct ucred` authentication information to match ShellCore's identifier (`0x3800000000000010`)

2. **Other Options**:
   - For FPKG applications: Utilize etaHEN's [Jailbreak IPC Command](https://github.com/etaHEN/etaHEN?tab=readme-ov-file#jailbreaking-an-app-fpkg-using-etahen-non-whitelist-method-network-required) functionality
   - For integrated solutions: Leverage the automatic privilege handling via [etaHEN Plugins System](https://github.com/etaHEN/etaHEN-Plugins) or [ps5-payload-dev SDK](https://github.com/ps5-payload-dev/sdk)

## Module Requirements

The procedure necessitates loading and initializing the system module:
```
/system/common/lib/libSceAppInstUtil.sprx
```

Note: When developing for the etaHEN Plugin System or building ELF executables with the ps5-payload-dev SDK, this module dependency is automatically resolved when the SceAppInstallUtil stub is properly linked.

## Step 1, Identifying the problem

As established previously, Flatz's BGFT (Background File Transfer) methodology is incompatible with the PS5, with all `sceBgftServiceIntDownloadRegisterTaskBy*` function calls consistently returning error code `0x80990006 (SCE_BGFT_ERROR_NOT_SUPPORTED)` despite proper initialization. Tracing BGFT IPC calls within shellcore revealed that PS5 deliberately returns this error even with the correct authid, representing an intentional change rather than a simple implementation difference; having identified this change as the source of incompatibility, our investigation now shifts toward discovering the alternative package installation implementation that has replaced the previous BGFT methodology.

```cpp
uint FUN_0100ee70(Session *session,int user_id,int entitlement_type,char *id,char *package_type,
                 char *package_sub_type,char *content_url,char *content_name,char *icon_path,
                 char *sku_id,char *playgo_scenario_id,char *release_date,size_t package_size,
                 bgft_task_option_t options,uint slot,void *result) {

  undefined auVar1 [32];
  long lVar2;
  pid_t pid;
  uint uVar3;
  uint uVar4;
  bgft_download_param args;
  
  lVar2 = __stack_chk_guard;
  if (session == NULL) {
    uVar4 = 0x80990050;
  }
  else {
    pid = (*session->_vptr->getClientPid)(session);
    uVar3 = check_authid(pid);
    uVar4 = 0x80990007;
    if (uVar3 == 1) {
      args._60_4_ = 0;
      args.content_url = content_url;
      auVar1._8_8_ = icon_path;
      auVar1._0_8_ = content_name;
      auVar1._16_8_ = sku_id;
      auVar1._24_8_ = 0;
      args._24_32_ = auVar1 << 0x40;
      args.options = options;
      args.playgo_scenario_id = playgo_scenario_id;
      args.release_date = release_date;
      args.package_size = package_size;
      args.user_id = user_id;
      args.entitlement_type = entitlement_type;
      args.id = id;
      args.package_type = package_type;
      args.package_sub_type = package_sub_type;
      uVar4 = DownloadRegisterTaskByStorageEx(&args,result);
    }
  }
  if (__stack_chk_guard == lVar2) {
    return uVar4;
  }

  __stack_chk_fail();
}

uint DownloadRegisterTaskByStorageEx(bgft_download_param *param_1,void *param_2) {
  printf("[BGFT] ERROR: [%d] ",0x18);
  puts("NOT SUPPORTED API");
  return 0x80990006;
}
```

## Step 2, what and where is the new function for installing PKGs

From extensive experience developing PS4 homebrew applications, I identified shellui as the component responsible for Debug Settings menu functionality, including package installation services. Initial reverse engineering targeted ShellUI's components through mono module analysis using DnSpy. This revealed the PS5's UI3 Settings implementation—a logical progression from UI (early PS4 firmware) to UI2 (later PS4 firmware). Within this framework, I located the critical PKG installer implementation, specifically the `ExecuteInstall` and `OnUpdate` mono functions with their associated data structures (`mTargetList` containing the package queue and `mInstallIndex` identifying the target package). While these functions expose the requisite installation APIs, it's important to note they cannot be invoked directly through conventional mono method calls, necessitating an alternative implementation approach.

```c#
private Task<int> ExecuteInstall()
{
	return Task.Run<int>(delegate()
	{
		this.Lock();
		AppInstUtilWrapper.SceAppInstallPkgInfo sceAppInstallPkgInfo = default(AppInstUtilWrapper.SceAppInstallPkgInfo);
		string[] array = new string[30];
		string[] array2 = new string[64];
		string[] array3 = new string[64];
		for (int i = 0; i < array.Length; i++)
		{
			array[i] = "";
		}
		for (int j = 0; j < array2.Length; j++)
		{
			array2[j] = "";
		}
		for (int k = 0; k < array3.Length; k++)
		{
			array3[k] = "";
		}
		int num = AppInstUtilWrapper.AppInstUtilInstallByPackage(this.mTargetList[this.mInstallIndex], "", "", "", "", "", 0U, false, ref sceAppInstallPkgInfo, array, array2, array3);
		if (num == 0)
		{
			this.mTimer = new UITimer(0.1f, true);
			UITimer uitimer = this.mTimer;
			uitimer.Executed = (UITimer.ExecutedHandler)Delegate.Combine(uitimer.Executed, new UITimer.ExecutedHandler(this.OnUpdate));
			this.mTimer.Start();
		}
		else
		{
			this.Unlock();
		}
		return num;
	});
}

private bool OnUpdate()
{
	ShellCoreUtilWrapper.sceShellCoreUtilResetAutoPowerDownTimer();
	AppInstUtilWrapper.SceAppInstallStatusInstalled sceAppInstallStatusInstalled = default(AppInstUtilWrapper.SceAppInstallStatusInstalled);
	int num = AppInstUtilWrapper.AppInstUtilGetInstallStatus(this.mContentId, ref sceAppInstallStatusInstalled);
	if (num == 0)
	{
		if (sceAppInstallStatusInstalled.total_size != 0UL)
		{
			this.mProgressBar.Progress = sceAppInstallStatusInstalled.downloaded_size / sceAppInstallStatusInstalled.total_size;
		}
		if (sceAppInstallStatusInstalled.status == "playable" || sceAppInstallStatusInstalled.status == "error" || sceAppInstallStatusInstalled.status == "none")
		{
			this.Unlock();
			this.mTimer.Stop();
			if (sceAppInstallStatusInstalled.status == "error" || sceAppInstallStatusInstalled.status == "none")
			{
				int error_code = sceAppInstallStatusInstalled.error_info.error_code;
				this.ShowError(error_code);
				return false;
			}
			this.Next();
		}
		return false;
	}
	this.Unlock();
	this.mTimer.Stop();
	this.ShowErrorDialog(num);
	return false;
}
```

## Step 3, using sceAppInstUtilInstallByPackage in C/C++

Following the trail from mono to native code required deeper reverse engineering, as direct replication of mono function definitions in C/C++ results in the SCE_APP_INSTALLER_ERROR_PARAM error. This parameter mismatch occurs because mono wrappers handle various transformations that aren't immediately apparent in the high-level code. To resolve this issue, I decompiled the underlying C/C++ implementation that these mono wrappers actually invoke, revealing the true parameter structure and count expected by the system. This step was critical since the native function signatures differ significantly from their managed counterparts, particularly in memory management and parameter marshalling approaches that the mono runtime normally handles transparently.



```cpp
void UndefinedFunction_001b8aa0
               (long param_1,long param_2,long param_3,long param_4,long param_5,long param_6,
               undefined4 param_7,byte param_8,long param_9,long param_10,long param_11,
               long param_12)

{
  undefined auVar1 [16];
  long lVar2;
  undefined *puVar3;
  undefined *puVar4;
  undefined in_YMM0 [32];
  long lStack10144;
  long lStack10136;
  long lStack10128;
  long lStack10120;
  long lStack10112;
  long lStack10104;
  undefined4 uStack10096;
  uint uStack10092;
  undefined auStack10080 [240];
  undefined auStack9840 [192];
  undefined auStack9648 [9552];
  long lStack96;
  
  lStack96 = f7uOxY9mM1U#1#u;
  if ((((((param_1 != 0) && (param_2 != 0)) && (param_3 != 0)) && ((param_4 != 0 && (param_5 != 0)) )
       ) && ((param_6 != 0 && ((param_9 != 0 && (param_10 != 0)))))) &&
     ((param_11 != 0 && (param_12 != 0)))) {
    auVar1 = vxorps_avx(SUB3216(in_YMM0,0),SUB3216(in_YMM0,0));
    uStack10096 = param_7;
    uStack10092 = (uint)param_8;
    lVar2 = 0;
    lStack10144 = param_1;
    lStack10136 = param_2;
    lStack10128 = param_3;
    lStack10120 = param_4;
    lStack10112 = param_5;
    lStack10104 = param_6;
    memset(SUB168(auVar1,0),auStack10080,0,0x2700);
    do {
      strncpy(auStack10080 + lVar2,*(undefined8 *)(param_10 + lVar2),7);
      lVar2 = lVar2 + 8;
    } while (lVar2 != 0xf0);
    puVar4 = auStack9840;
    puVar3 = auStack9648;
    lVar2 = 0;
    do {
      strncpy(puVar4,*(undefined8 *)(param_11 + lVar2 * 8),2);
      strncpy(puVar3,*(undefined8 *)(param_12 + lVar2 * 8),0x2f);
      lVar2 = lVar2 + 1;
      puVar4 = puVar4 + 3;
      puVar3 = puVar3 + 0x30;
    } while (lVar2 != 0x40);
    InstallByPackage(&lStack10144,param_9,auStack10080);
  }
  if (f7uOxY9mM1U#1#u == lStack96) {
    return;
  }
  __stack_chk_fail();
  do {
    invalidInstructionException();
  } while( true );
}
```

Through careful analysis of the decompiled implementation, it was identified that `sceAppInstUtilInstallByPackage` requires three struct parameters. Tracing the function's implementation patterns revealed the complete parameter definitions and their expected values. Further investigation into the mono implementation provided additional insights regarding parameter functionality: `content_name` defines the display name shown during package installation (typically the application title), while the `url` parameter supports multiple source formats including local paths (`/data/test.pkg`) and remote HTTP URLs (`http://127.0.0.1/test.pkg`). This URL flexibility likely extends to update manifest handling similar to PS4 implementation. Additional parameters like `icon_url` provide customization options for the installation process and UI representation.

```cpp
#define PLAYGOSCENARIOID_SIZE 3
#define CONTENTID_SIZE 0x30
#define LANGUAGE_SIZE 8

#define NUM_LANGUAGES 30
#define NUM_IDS 64

typedef char playgo_scenario_id_t[PLAYGOSCENARIOID_SIZE];
typedef char language_t[LANGUAGE_SIZE];
typedef char content_id_t[CONTENTID_SIZE];

typedef struct {
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

typedef struct {
    language_t languages[NUM_LANGUAGES];
    playgo_scenario_id_t playgo_scenario_ids[NUM_IDS];
    content_id_t content_ids[NUM_IDS];
    unsigned char unknown[6480]; // standard sony practice of wasting memory?
} PlayGoInfo;

sceAppInstUtilInstallByPackage(MetaInfo* arg1, SceAppInstallPkgInfo* pkg_info, PlayGoInfo* arg2);
```

The investigation process extends beyond simply identifying function signatures. Proper implementation requires adhering to the initialization sequence documented in Flatz's original writeup and confirmed in the mono codebase. Specifically, before any installation functions can be called, the AppInstUtil module must be explicitly initialized via `sceAppInstUtilInitialize`. This initialization step is mandatory and must be preceded by loading the module itself (if not already present in memory). This precise initialization sequence is critical for FPKG installation, as improper module initialization will result in crashing. 

```cpp

int(*sceAppInstUtilInstallByPackage)(MetaInfo* arg1, SceAppInstallPkgInfo* pkg_info, PlayGoInfo* arg2) = nullptr;

extern bool sceAppInst_done;
int app_inst_module_id = -1;

bool app_inst_util_init(int &m_id) {
    int ret;

    if (sceAppInst_done) {
        m_id = app_inst_module_id;
        return true;
    }

    int lib_appinstutil = sceKernelLoadStartModule("/system/common/lib/libSceAppInstUtil.sprx", 0, NULL, 0, NULL, NULL);
    if (lib_appinstutil < 0) {
        return PKG_ERROR("AppInstUtil System Module failed to load.", lib_appinstutil);
    }

    m_id = app_inst_module_id = lib_appinstutil;

    ret = sceAppInstUtilInitialize();
    if (ret) {
        log_debug("sceAppInstUtilInitialize failed: 0x%08X", ret);
        goto err;
    }

    sceAppInst_done = true;
    return true;
err:
    log_error("error inilizing appinstlutil");
    sceAppInst_done = false;
    m_id = -1;
    return false;
}

int pkginstall(const char* fullpath,
    const char* filename) {

    int lib_appinstutil = -1;
    if (!if_exists(fullpath)) {
        return PKG_ERROR("PKG Doesnt exist", -1);
    }

    log_info("Initializing AppInstUtil...");
    if (!app_inst_util_init(lib_appinstutil))
        return PKG_ERROR("AppInstUtil", 1337);

    log_info("AppInstUtil Initialized...");

    sceAppInstUtilInstallByPackage = (int(*)(astruct_1*, SceAppInstallPkgInfo*, astruct_2*)) LOAD_FUNCTION_AND_CHECK(lib_appinstutil, "sceAppInstUtilInstallByPackage");

    astruct_2 arg3;
    SceAppInstallPkgInfo pkg_info;
    memset(&arg3, 0, sizeof(arg3));

    for (size_t i = 0; i < NUM_LANGUAGES; i++) {
        strncpy(arg3.languages[i], "", sizeof(language_t) - 1);
    }

    for (size_t i = 0; i < NUM_IDS; i++) {
        strncpy(arg3.playgo_scenario_ids[i], "", sizeof(playgo_scenario_id_t) - 1);
        strncpy(*arg3.content_ids, "", sizeof(content_id_t) - 1);
    }

    astruct_1 arg1 = (astruct_1){
        .uri = fullpath,
        .ex_uri = "",
        .playgo_scenario_id = "",
        .content_id = "",
        .content_name = filename,
        .icon_url = ""
    };

    int num = sceAppInstUtilInstallByPackage(&arg1, &pkg_info, &arg3);
    if (num == 0) {
        log_info("install successful");
    }
    else {
        log_info("install failed");
        return PKG_ERROR("install_pkg", num);

    }

    log_info("%s(%s) done.", __FUNCTION__, fullpath);

    return 0;
}
```

We also have this nice list of SCE_APP_INSTALLER_ errors provided by ShellUI

```cpp
enum  AppInstErrorCodes
{
    SCE_APP_INSTALLER_ERROR_UNKNOWN = -2136801279,
    SCE_APP_INSTALLER_ERROR_NOSPACE,
    SCE_APP_INSTALLER_ERROR_PARAM,
    SCE_APP_INSTALLER_ERROR_APP_NOT_FOUND,
    SCE_APP_INSTALLER_ERROR_DISC_NOT_INSERTED,
    SCE_APP_INSTALLER_ERROR_PKG_INVALID_DRM_TYPE,
    SCE_APP_INSTALLER_ERROR_OUT_OF_MEMORY,
    SCE_APP_INSTALLER_ERROR_APP_BROKEN,
    SCE_APP_INSTALLER_ERROR_PKG_INVALID_CONTENT_TYPE,
    SCE_APP_INSTALLER_ERROR_USED_APP_NOT_FOUND,
    SCE_APP_INSTALLER_ERROR_ADDCONT_BROKEN,
    SCE_APP_INSTALLER_ERROR_APP_IS_RUNNING,
    SCE_APP_INSTALLER_ERROR_SYSTEM_VERSION,
    SCE_APP_INSTALLER_ERROR_NOT_INSTALL,
    SCE_APP_INSTALLER_ERROR_CONTENT_ID_DISAGREE,
    SCE_APP_INSTALLER_ERROR_NOSPACE_KERNEL,
    SCE_APP_INSTALLER_ERROR_APP_VER,
    SCE_APP_INSTALLER_ERROR_DB_DISABLE,
    SCE_APP_INSTALLER_ERROR_CANCELED,
    SCE_APP_INSTALLER_ERROR_ENTRYDIGEST,
    SCE_APP_INSTALLER_ERROR_BUSY,
    SCE_APP_INSTALLER_ERROR_DLAPP_ALREADY_INSTALLED,
    SCE_APP_INSTALLER_ERROR_NEED_ADDCONT_INSTALL,
    SCE_APP_INSTALLER_ERROR_APP_MOUNTED_BY_HOST_TOOL,
    SCE_APP_INSTALLER_ERROR_INVALID_PATCH_PKG,
    SCE_APP_INSTALLER_ERROR_NEED_ADDCONT_INSTALL_NO_CHANGE_TYPE = -2136801248,
    SCE_APP_INSTALLER_ERROR_ADDCONT_IS_INSTALLING,
    SCE_APP_INSTALLER_ERROR_ADDCONT_ALREADY_INSTALLED,
    SCE_APP_INSTALLER_ERROR_CANNOT_READ_DISC,
    SCE_APP_INSTALLER_ERROR_DATA_DISC_NOT_INSTALLED,
    SCE_APP_INSTALLER_ERROR_NOT_TRANSFER_DISC_VERSION,
    SCE_APP_INSTALLER_ERROR_NO_SLOT_SPACE,
    SCE_APP_INSTALLER_ERROR_NO_SLOT_INFORMATION,
    SCE_APP_INSTALLER_ERROR_INSTALL_MAIN_MISSING,
    SCE_APP_INSTALLER_ERROR_INSTALL_TIME_VALID_IN_FUTURE,
    SCE_APP_INSTALLER_ERROR_SYSTEM_FILE_DISAGREE,
    SCE_APP_INSTALLER_ERROR_INSTALL_BLANK_SLOT,
    SCE_APP_INSTALLER_ERROR_INSTALL_LINK_SLOT,
    SCE_APP_INSTALLER_ERROR_INSTALL_PKG_NOT_COMPLETED,
    SCE_APP_INSTALLER_ERROR_NOSPACE_IN_EXTERNAL_HDD,
    SCE_APP_INSTALLER_ERROR_NOSPACE_KERNEL_IN_EXTERNAL_HDD,
    SCE_APP_INSTALLER_ERROR_COMPILATION_DISC_INSERTED,
    SCE_APP_INSTALLER_ERROR_COMPILATION_DISC_INSERTED_NOT_VISIBLE_DISC_ICON,
    SCE_APP_INSTALLER_ERROR_ACCESS_FAILED_IN_EXTERNAL_HDD,
    SCE_APP_INSTALLER_ERROR_MOVE_FAILED_SOME_APPLICATIONS,
    SCE_APP_INSTALLER_ERROR_DUPLICATION,
    SCE_APP_INSTALLER_ERROR_INVALID_STATE,
    SCE_APP_INSTALLER_ERROR_NOSPACE_DISC,
    SCE_APP_INSTALLER_ERROR_NOSPACE_DISC_IN_EXTERNAL_HDD,
    SCE_APP_INST_UTIL_ERROR_NOT_INITIALIZED = -2136797184,
    SCE_APP_INST_UTIL_ERROR_OUT_OF_MEMORY
}

```

## Step 4, using sceAppInstUtilGetInstallStatus in C/C++

The implementation of `sceAppInstUtilGetInstallStatus` maintains close functional parity with its C# counterpart. I converted the managed data structures to their native C/C++ equivalents with proper memory alignment and type definitions. This direct correlation between implementations facilitates consistent behavior across different access methods while maintaining the expected parameter layouts and return value semantics.



```cpp
typedef struct {
    int32_t error_code;
    int32_t version;
    char description[512];
    char type[9];
} SceAppInstallErrorInfo;

typedef struct {
    char status[16];
    char src_type[8];
    uint32_t remain_time;
    uint64_t downloaded_size;
    uint64_t initial_chunk_size;
    uint64_t total_size;
    uint32_t promote_progress;
    SceAppInstallErrorInfo error_info;
    int32_t local_copy_percent;
    bool is_copy_only;
} SceAppInstallStatusInstalled;

int sceAppInstUtilGetInstallStatus(const char* content_id, SceAppInstallStatusInstalled* status);
```

The `sceAppInstUtilGetInstallStatus` function provides a streamlined interface for monitoring installation progress. It accepts a content ID parameter and populates the previously defined status structure with installation metrics. This content ID can be extracted directly from a PKGs metadata or programmatically obtained through the method outlined in the subsequent implementation section. This status monitoring capability is essential for implementing progress tracking and error handling during the installation.

## Step 5, using both functions to do what BGFT used to do

The integration of `sceAppInstUtilInstallByPackage` and `sceAppInstUtilGetInstallStatus` provides a comprehensive package installation solution equivalent to the system's native Debug Settings implementation. This workflow begins with installation initiation via `sceAppInstUtilInstallByPackage`, which returns immediately while the installation continues asynchronously. The returned content ID serves as the reference key for subsequent status tracking.

By implementing a monitoring loop with `sceAppInstUtilGetInstallStatus`, applications can:

1. Track download progress (percentage complete)
2. Monitor installation state transitions (transferring → promoting → playable)
3. Detect and respond to installation errors
4. Determine when installation has successfully completed

This approach enables developers to create custom installation interfaces with progress visualization, error handling, and completion notifications—effectively replicating the functionality of the system's Debug Settings while providing greater control over the presentation layer and integration with application-specific logic.

```cpp

int ret = sceAppInstUtilInitialize();
if(ret){
   printf("sceAppInstUtilInitialize failed: 0x%08X\n", ret);
   return -1;
}

PlayGoInfo arg3;
SceAppInstallPkgInfo pkg_info;
(void)memset(&arg3, 0, sizeof(arg3));

for (size_t i = 0; i < NUM_LANGUAGES; i++) {
    strncpy(arg3.languages[i], "", sizeof(arg3.languages[i]) - 1);
}

for (size_t i = 0; i < NUM_IDS; i++) {
     strncpy(arg3.playgo_scenario_ids[i], "",
                sizeof(playgo_scenario_id_t) - 1);
     strncpy(*arg3.content_ids, "", sizeof(content_id_t) - 1);
}

MetaInfo in = {
    .uri = "/path/to/pkg.pkg",
    .ex_uri = "",
    .playgo_scenario_id = "",
    .content_id = "",
    .content_name = "PKG TITLE",
    .icon_url = ""
};

int num = sceAppInstUtilInstallByPackage(&in, &pkg_info, &arg3);
if (num == 0) {
    puts("Download and Install console Task initiated");
} else {
    printf("DPI: Install failed with error code %d\n", num);
}
float prog = 0;
SceAppInstallStatusInstalled status;

while (strcmp(status.status, "playable") != 0) {
    sceAppInstUtilGetInstallStatus(pkg_info.content_id, &status);
    
    if (status.total_size != 0) {
        prog = ((float)status.downloaded_size / status.total_size) * 100.0f;
    }

    printf("DPI: Status: %s | error: %d | progress %.2f%% (%llu/%llu)\n", 
               status.status, status.error_info.error_code, 
               prog, status.downloaded_size, status.total_size);
}

```


## Credits
- Astrelsky, for all the help they provided, without them it may have taken longer

