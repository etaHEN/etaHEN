#pragma once

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "mempack.h"

#define CONSOLE_ENABLE 1

#if CONSOLE_ENABLE == 1
extern int kprintf(const char *fmt, ...);
#define CONSOLE_Printf kprintf
#else
#define CONSOLE_Printf ;
#endif
#define	ORBIS_KERNEL_PROT_CPU_READ  0x01
#define	ORBIS_KERNEL_PROT_CPU_RW	  0x02
#define	ORBIS_KERNEL_PROT_CPU_EXEC  0x04
#define	ORBIS_KERNEL_PROT_CPU_ALL	  0x07
#define ORBIS_KERNEL_PROT_GPU_READ  0x10
#define ORBIS_KERNEL_PROT_GPU_WRITE 0x20
#define ORBIS_KERNEL_PROT_GPU_RW	  0x30
#define ORBIS_KERNEL_PROT_GPU_ALL	  0x30
#define	ORBIS_KERNEL_PROT_AMPR_READ	0x40
#define	ORBIS_KERNEL_PROT_AMPR_WRITE	0x80
#define	ORBIS_KERNEL_PROT_AMPR_RW		0xc0
#define	ORBIS_KERNEL_PROT_AMPR_ALL	0xc0
#define	ORBIS_KERNEL_PROT_ACP_READ	0x100
#define	ORBIS_KERNEL_PROT_ACP_WRITE	0x200
#define	ORBIS_KERNEL_PROT_ACP_RW		0x300
#define	ORBIS_KERNEL_PROT_ACP_ALL		0x300
#define ORBIS_KERNEL_PAGE_SIZE	  16384


typedef struct OrbisUserServiceInitializeParams {
	int32_t priority;
} OrbisUserServiceInitializeParams;

#define SCE_KERNEL_APP_MAP_AREA_START_ADDR		0x1000000000UL
#define SCE_KERNEL_APP_MAP_AREA_END_ADDR		0xfc00000000UL
#define SCE_KERNEL_APP_MAP_AREA_SIZE \
 (SCE_KERNEL_APP_MAP_AREA_END_ADDR - SCE_KERNEL_APP_MAP_AREA_START_ADDR)
  
  typedef enum {
  SCE_KERNEL_MTYPE_C = 11,
  SCE_KERNEL_MTYPE_C_SHARED,
  SCE_KERNEL_MEMORY_TYPE_END = 21
} SceKernelMemoryType;

#define SCE_KERNEL_MAX_MAP_ALIGNMENT		31
#define	ORBIS_KERNEL_PROT_CPU_WRITE	ORBIS_KERNEL_PROT_CPU_RW
typedef uint64_t OrbisKernelEqueue;
struct APP
{	
	int videoOutHandle;
	struct Mempack ram;
	struct Mempack onion;
	struct Mempack garlic;
	OrbisKernelEqueue sync_equeue;
	
	int renderW;
	int renderH;
	
	#define NUM_SWAP_IMAGES 2
	int currBuff;
	void* surfaceAddr[NUM_SWAP_IMAGES];
};

struct SceVideoOutBufferAttribute2 {
	int32_t _reserved0;
	int32_t tilingMode;			// SceVideoOutTilingMode
	int32_t aspectRatio;		// =0
	uint32_t width;
	uint32_t height;
	uint32_t pitchInPixel; // =0
	uint64_t option;           // SceVideoOutBufferAttributeOption
	uint64_t pixelFormat;
	uint64_t dccCbRegisterClearColor;
	uint32_t dccControl;
	uint32_t pad0;
	uint64_t _reserved1[3];
};

#define SCE_VIDEO_OUT_OK			0	/* 0 */

enum {
	SCE_VIDEO_OUT_TRUE  = 1,
	SCE_VIDEO_OUT_FALSE = 0,
};

enum {
	SCE_VIDEO_OUT_BUFFER_NUM_MAX =16,
	SCE_VIDEO_OUT_BUFFER_ATTRIBUTE_NUM_MAX =4,
	SCE_VIDEO_OUT_BUFFER_FLIP_RATE_MAX =2,

	SCE_VIDEO_OUT_BUFFER_INDEX_BLANK = -1,  /* special buffer index to transparent blank screen */
	SCE_VIDEO_OUT_BUFFER_INDEX_BLACK = -2,  /* special buffer index to opaque black screen */	
	SCE_VIDEO_OUT_BUFFER_INITIAL_FLIP_ARG = -1,  /* initial flipArg valu at sceVideoOutOpen() */
};

typedef enum SceVideoOutBusType {
	SCE_VIDEO_OUT_BUS_TYPE_MAIN = 0,
	SCE_VIDEO_OUT_BUS_TYPE_OVERLAY = 1,
	SCE_VIDEO_OUT_BUS_TYPE_SUB = 2,
} SceVideoOutBusType;


typedef enum SceVideoOutFlipMode {
	SCE_VIDEO_OUT_FLIP_MODE_VSYNC	      = 1,  /* on real video out vsync */
	SCE_VIDEO_OUT_FLIP_MODE_ASAP	      = 2,  /* ASAP (but not immediate) */
	SCE_VIDEO_OUT_FLIP_MODE_WINDOW        = 3, /* similar to vsync but may flip on some windows at the top and the bottom of the display. */
	SCE_VIDEO_OUT_FLIP_MODE_VSYNC_MULTI   = 4, /* vsync mode but allows multiple flips per vsync. flipRate is not valid. */

	SCE_VIDEO_OUT_FLIP_MODE_SLAVE=8,
	SCE_VIDEO_OUT_FLIP_MODE_MASTER=9,

} SceVideoOutFlipMode;

typedef enum SceVideoOutTilingMode {
	SCE_VIDEO_OUT_TILING_MODE_TILE=0, 
	SCE_VIDEO_OUT_TILING_MODE_LINEAR=1, /* development only */

} SceVideoOutTilingMode;


typedef enum SceVideoOutEventId {
	SCE_VIDEO_OUT_EVENT_FLIP=0,
	SCE_VIDEO_OUT_EVENT_VBLANK=1,
	SCE_VIDEO_OUT_EVENT_PRE_VBLANK_START=2,
} SceVideoOutEventId;

enum {
	SCE_VIDEO_OUT_A2LUT_NUM = 4,  /* element num of a2lut */
};

typedef enum SceVideoOutGlobalAlphaMode {
	SCE_VIDEO_OUT_GLOBAL_ALPHA_MODE_NORMAL=0,
	SCE_VIDEO_OUT_GLOBAL_ALPHA_MODE_GLOBAL_ALPHA_ONLY=1,
} SceVideoOutGlobalAlphaMode;


typedef enum SceVideoOutBufferAttributeCategory {
	SCE_VIDEO_OUT_BUFFER_ATTRIBUTE_CATEGORY_UNCOMPRESSED = 0,
	SCE_VIDEO_OUT_BUFFER_ATTRIBUTE_CATEGORY_COMPRESSED = 1,
} SceVideoOutBufferAttributeCategory;




static const uint64_t SCE_VIDEO_OUT_BUFFER_ATTRIBUTE_OPTION_NONE = 0;
static const uint64_t SCE_VIDEO_OUT_BUFFER_ATTRIBUTE_OPTION_STRICT_COLORIMETRY = (1UL<<3);
static const uint64_t SCE_VIDEO_OUT_BUFFER_ATTRIBUTE_OPTION_ALPHA_NON_PREMULTIPLIED = (0UL<<5);
static const uint64_t SCE_VIDEO_OUT_BUFFER_ATTRIBUTE_OPTION_ALPHA_PREMULTIPLIED = (1UL<<5);
static const uint64_t SCE_VIDEO_OUT_BUFFER_ATTRIBUTE_OPTION_ALPHA_PREMULTIPLIED_MASK = (1UL<<5);
static const uint64_t SCE_VIDEO_OUT_BUFFER_ATTRIBUTE_OPTION_MASK=(SCE_VIDEO_OUT_BUFFER_ATTRIBUTE_OPTION_STRICT_COLORIMETRY|SCE_VIDEO_OUT_BUFFER_ATTRIBUTE_OPTION_ALPHA_PREMULTIPLIED);


typedef struct SceVideoOutFlipStatus {
	uint64_t count; // count of flips executed after sceVideoOutOpen()
	uint64_t processTime; // processTime of the time of the latest flip executed
	uint64_t reserved0;
	int64_t flipArg; // flipArg submitted with the latest flip
	uint64_t reserved1;
	uint64_t processTimeCounter; // processTimeCounter value of the time the latest flip executed
	int32_t gcQueueNum; // number of non-finished flips that are waiting for the setFlip command to execute on the GPU
	int32_t flipPendingNum;		// number of total non-finished flips
	int32_t currentBuffer;		// current buffer index on display
	uint32_t reserved2;
	uint64_t submitProcessTimeCounter; // Process Time Counter Value value of the time the latest flip was requested on the GPU
	uint64_t reserved3[7];
} SceVideoOutFlipStatus;

typedef struct SceVideoOutVblankStatus {
	uint64_t count; // count of vblanks after sceVideoOutOpen()
	uint64_t processTime; // processTime of the time of the latest vblank event
	uint64_t reserved;		  // Timestamp counter value when the latest vblank event
	uint64_t processTimeCounter; // ProcessTimeCounter value when the latest vblank event
	uint8_t flags; // SceVideoOutVblankStatusFlags
	uint8_t pad1[7];
} SceVideoOutVblankStatus;

typedef enum SceVideoOutVblankStatusFlags {
	SCE_VIDEO_OUT_VBLANK_STATUS_FLAG_NONE=0,
} SceVideoOutVblankStatusFlags;

#include <sys/types.h>


typedef uint64_t SceKernelEqueue;
#define SCE_VIDEO_OUT_PARAM_PRIMARY_VERSION (1<<4)
#define SCE_VIDEO_OUT_PARAM_MAIN_VERSION SCE_VIDEO_OUT_PARAM_PRIMARY_VERSION 

/* 
 * new buffer handling functions
 */
typedef struct SceVideoOutBuffers {
	const void *data;
	const void *metadata;
	const void *reserved[2];
} SceVideoOutBuffers;

void sceVideoOutSetBufferAttribute2(struct SceVideoOutBufferAttribute2 *attribute, uint64_t pixelFormat, uint32_t tilingMode, uint32_t width, uint32_t height, uint64_t option, uint32_t dccControl, uint64_t dccCbRegisterClearColor);

int32_t sceVideoOutRegisterBuffers2(int32_t handle, int32_t setIndex, int32_t bufferIndexStart, const struct SceVideoOutBuffers *buffers, int32_t bufferNum, const struct SceVideoOutBufferAttribute2 *attribute, int32_t category, void *option);

typedef unsigned int SceKernelUseconds;

#define ORBIS_VIDEO_USER_MAIN		0xFF

#define ORBIS_VIDEO_OUT_BUS_MAIN	0
#define ORBIS_VIDEO_OUT_BUS_SOCIAL	5
#define ORBIS_VIDEO_OUT_BUS_LIVE	6

typedef enum OrbisFlipType : int32_t
{
	ORBIS_VIDEO_OUT_FLIP_VSYNC = 1,
	ORBIS_VIDEO_OUT_FLIP_HSYNC = 2,
} OrbisFlipType;

typedef enum OrbisFlipRate : int32_t
{
	ORBIS_VIDEO_OUT_FLIP_60HZ = 0,
	ORBIS_VIDEO_OUT_FLIP_30HZ = 1,
	ORBIS_VIDEO_OUT_FLIP_20HZ = 2,
} OrbisFlipRate;

typedef enum OrbisVideoOutTilingMode {
	ORBIS_VIDEO_OUT_TILING_MODE_TILE = 0x0,
	ORBIS_VIDEO_OUT_TILING_MODE_LINEAR = 0x1,
} OrbisVideoOutTilingMode;

typedef enum OrbisVideoOutAspectRatio {
	ORBIS_VIDEO_OUT_ASPECT_RATIO_16_9 = 0x0,
} OrbisVideoOutAspectRatio;

#define ORBIS_VIDEO_OUT_PIXEL_FORMAT_A8B8G8R8_SRGB 0x80002200


struct sce_kevent 
{
	uintptr_t	ident;		/* identifier for this event */
	short		filter;		/* filter for event */
	uint16_t	flags;
	uint32_t	fflags;
	intptr_t	data;
	void		*udata;		/* opaque user data identifier */
};

typedef struct sce_kevent SceKernelEvent;

static const uint64_t SCE_VIDEO_OUT_PIXEL_FORMAT2_R8_G8_B8_A8_SRGB =                    0x8000000022000000UL;
static const uint64_t SCE_VIDEO_OUT_PIXEL_FORMAT2_B8_G8_R8_A8_SRGB =                    0x8000000000000000UL;
static const uint64_t SCE_VIDEO_OUT_PIXEL_FORMAT2_R10_G10_B10_A2 =                      0x8100000622000000UL;
static const uint64_t SCE_VIDEO_OUT_PIXEL_FORMAT2_B10_G10_R10_A2 =                      0x8100000600000000UL;
static const uint64_t SCE_VIDEO_OUT_PIXEL_FORMAT2_R10_G10_B10_A2_SRGB =                 0x8100000022000000UL;
static const uint64_t SCE_VIDEO_OUT_PIXEL_FORMAT2_B10_G10_R10_A2_SRGB =                 0x8100000000000000UL;
static const uint64_t SCE_VIDEO_OUT_PIXEL_FORMAT2_R10_G10_B10_A2_BT2100_PQ =            0x8100070422000000UL;
static const uint64_t SCE_VIDEO_OUT_PIXEL_FORMAT2_B10_G10_R10_A2_BT2100_PQ =            0x8100070400000000UL;
static const uint64_t SCE_VIDEO_OUT_PIXEL_FORMAT2_R16_G16_B16_A16_FLOAT =               0xC001000622000000UL;
static const uint64_t SCE_VIDEO_OUT_PIXEL_FORMAT2_B16_G16_R16_A16_FLOAT =               0xC001000600000000UL;
static const uint64_t SCE_VIDEO_OUT_PIXEL_FORMAT2_R16_G16_B16_A16_FLOAT_FOR_BT2100_PQ = 0xC001070722000000UL;
static const uint64_t SCE_VIDEO_OUT_PIXEL_FORMAT2_B16_G16_R16_A16_FLOAT_FOR_BT2100_PQ = 0xC001070700000000UL;

// Struct Credits - psxdev
typedef struct OrbisVideoOutBufferAttribute {
	int32_t format;
	int32_t tmode;
	int32_t aspect;
	uint32_t width;
	uint32_t height;
	uint32_t pixelPitch;
	uint64_t reserved[2];
} OrbisVideoOutBufferAttribute;

// Struct Credits - psxdev
typedef struct OrbisVideoOutFlipStatus {
	uint64_t num;
	uint64_t ptime;
	uint64_t stime;
	int64_t flipArg;
	uint64_t reserved[2];
	int32_t numGpuFlipPending;
	int32_t numFlipPending;
	int32_t currentBuffer;
	uint32_t reserved1;
} OrbisVideoOutFlipStatus;

// Struct Credits - Inori
typedef struct OrbisVideoOutResolutionStatus {
	uint32_t width;
	uint32_t height;
	uint32_t paneWidth;
	uint32_t paneHeight;
	uint64_t refreshRate;
	float screenSize;
	uint16_t flags;
	uint16_t reserved0;
	uint32_t reserved1[3];
} OrbisVideoOutResolutionStatus;


extern struct APP gApp;


#define SCE_KERNEL_EVFILT_TIMER    EVFILT_TIMER
#define SCE_KERNEL_EVFILT_READ     EVFILT_READ
#define SCE_KERNEL_EVFILT_WRITE    EVFILT_WRITE
#define SCE_KERNEL_EVFILT_USER     EVFILT_USER
#define SCE_KERNEL_EVFILT_FILE     EVFILT_VNODE
#define SCE_KERNEL_EVFILT_GNM      EVFILT_GRAPHICS_CORE
#define SCE_KERNEL_EVFILT_VIDEO_OUT      EVFILT_DISPLAY
#define SCE_KERNEL_EVFILT_HRTIMER  EVFILT_HRTIMER
#define SCE_KERNEL_EVFILT_AMPR	   EVFILT_AMPR

#define SCE_KERNEL_EVNOTE_DELETE   NOTE_DELETE
#define SCE_KERNEL_EVNOTE_WRITE    NOTE_WRITE
#define SCE_KERNEL_EVNOTE_EXTEND   NOTE_EXTEND
#define SCE_KERNEL_EVNOTE_ATTRIB   NOTE_ATTRIB
#define SCE_KERNEL_EVNOTE_RENAME   NOTE_RENAME
#define SCE_KERNEL_EVNOTE_REVOKE   NOTE_REVOKE

#define SCE_KERNEL_EVFLAG_EOF       EV_EOF
#define SCE_KERNEL_EVFLAG_ERROR     EV_ERROR

int          sceKernelGetEventFilter(const SceKernelEvent *ev);
uintptr_t    sceKernelGetEventId(const SceKernelEvent *ev);
intptr_t     sceKernelGetEventData(const SceKernelEvent *ev);
unsigned int sceKernelGetEventFflags(const SceKernelEvent *ev);
int          sceKernelGetEventError(const SceKernelEvent *ev);
void *       sceKernelGetEventUserData(const SceKernelEvent *ev);

int sceKernelCreateEqueue(SceKernelEqueue *eq, const char *name);
int sceKernelDeleteEqueue(SceKernelEqueue eq);



typedef enum {
    EventType_Invalid,
    EventType_AppLaunchStart,
    EventType_AppLaunchEnd,
    EventType_AppKillStart,
    EventType_AppKillEnd,
    EventType_AppSuspending,
    EventType_AppSuspended,
    EventType_AppResuming,
    EventType_AppResumed,
    EventType_CdlgActive = 17,
    EventType_CdlgDeactive,
    EventType_CoredumpStart = 241,
    EventType_AppFocusStart = 4097,
    EventType_AppFocusEnd,
    EventType_ControllerFocusStart,
    EventType_ControllerFocusEnd
} EventType;

// Define AppType enum
typedef enum {
    AppType_Invalid = -1,
    AppType_Unknown,
    AppType_ShellUI,
    AppType_Daemon,
    AppType_CDLG,
    AppType_MiniApp,
    AppType_BigApp,
    AppType_ShellCore,
    AppType_ShellApp
} AppType;

// Define AppAttr enum
typedef enum {
    AppAttr_None = 0,
    AppAttr_DisableSystemBG = 1,
    AppAttr_LaunchByDebugger = 2,
    AppAttr_LaunchByAppHomeData = 4,
    AppAttr_VRMode = 16,
    AppAttr_NonVRMode = 32,
    AppAttr_LaunchSfFromGame = 64,
    AppAttr_LaunchBackFromSf = 128,
    AppAttr_LaunchTitleIdByHost = 256,
    AppAttr_EnlargeFmem256mb = 512,
    AppAttr_LaunchByAppHomeWs1 = 1024,
    AppAttr_LaunchByAppHomeWs2 = 2048,
    AppAttr_LaunchByAppHomeWs3 = 4096,
    AppAttr_LaunchByAppHomeWs4 = 8192,
    AppAttr_LaunchByAppHomeWs5 = 16384,
    AppAttr_LaunchByAppHomeWs6 = 32768,
    AppAttr_LaunchByAppHomeWs7 = 65536,
    AppAttr_LaunchByAppHomeM2 = 131072
} AppAttr;

// Define CrashReportMode enum
typedef enum {
    CrashReportMode_KillApp,
    CrashReportMode_KillLocalProcess
} CrashReportMode;

// Function prototype (assuming similar to C# method)
// Define the AppStatus struct in C
typedef struct {
    int32_t appId;
    int32_t launchRequestAppId;
    AppType appType;
    AppAttr appAttr;
    char titleId[128]; // Assuming the titleId length as 128, adjust as needed
    uint32_t appCategoryType;
} AppStatus;


/*
 * reading status
 */
int32_t sceVideoOutGetFlipStatus(int32_t handle, SceVideoOutFlipStatus *status);
int32_t sceVideoOutGetVblankStatus(int32_t handle, SceVideoOutVblankStatus *status);
int32_t sceVideoOutIsFlipPending(int32_t handle);


/* 
 * event API's
 */ 

int32_t sceVideoOutAddFlipEvent(SceKernelEqueue eq, int32_t handle, void *udata);
int32_t sceVideoOutAddVblankEvent(SceKernelEqueue eq, int32_t handle, void *udata);
int32_t sceVideoOutDeleteFlipEvent(SceKernelEqueue eq, int32_t handle);
int32_t sceVideoOutDeleteVblankEvent(SceKernelEqueue eq, int32_t handle);
int32_t sceVideoOutAddPreVblankStartEvent(SceKernelEqueue eq, int32_t handle, void *udata);
int32_t sceVideoOutDeletePreVblankStartEvent(SceKernelEqueue eq, int32_t handle);

int sceKernelDeleteTimerEvent(SceKernelEqueue eq, int id);
int sceKernelAddReadEvent(SceKernelEqueue eq, int fd, size_t size, void *udata);
int sceKernelDeleteReadEvent(SceKernelEqueue eq, int fd);
int sceKernelAddWriteEvent(SceKernelEqueue eq, int fd, size_t size, void *udata);
int sceKernelDeleteWriteEvent(SceKernelEqueue eq, int fd);
int sceKernelAddFileEvent(SceKernelEqueue eq, int fd, int watch, void *udata);
int sceKernelDeleteFileEvent(SceKernelEvent eq, int fd);
int sceKernelAddUserEvent(SceKernelEqueue eq, int id);
int sceKernelAddUserEventEdge(SceKernelEqueue eq, int id);
int sceKernelDeleteUserEvent(SceKernelEqueue eq, int id);
int sceKernelTriggerUserEvent(SceKernelEqueue eq, int id, void *udata);
int sceKernelDeleteHRTimerEvent(SceKernelEqueue eq, int id);
int sceKernelAddAmprEvent(SceKernelEqueue eq, int id, void *udata);
int sceKernelDeleteAmprEvent(SceKernelEqueue eq, int id);
int sceKernelWaitEqueue(SceKernelEqueue eq, SceKernelEvent *ev, int num, int *out, SceKernelUseconds *timo);


typedef enum ScePadButtonDataOffset {
	SCE_PAD_BUTTON_L3        = 0x00000002,
	SCE_PAD_BUTTON_R3        = 0x00000004,
	SCE_PAD_BUTTON_OPTIONS   = 0x00000008,
	SCE_PAD_BUTTON_UP        = 0x00000010,
	SCE_PAD_BUTTON_RIGHT     = 0x00000020,
	SCE_PAD_BUTTON_DOWN      = 0x00000040,
	SCE_PAD_BUTTON_LEFT      = 0x00000080,
	SCE_PAD_BUTTON_L2        = 0x00000100,
	SCE_PAD_BUTTON_R2        = 0x00000200,
	SCE_PAD_BUTTON_L1        = 0x00000400,
	SCE_PAD_BUTTON_R1        = 0x00000800,
	SCE_PAD_BUTTON_TRIANGLE  = 0x00001000,
	SCE_PAD_BUTTON_CIRCLE    = 0x00002000,
	SCE_PAD_BUTTON_CROSS     = 0x00004000,
	SCE_PAD_BUTTON_SQUARE    = 0x00008000,
	SCE_PAD_BUTTON_TOUCH_PAD = 0x00100000,
	SCE_PAD_BUTTON_INTERCEPTED = 0x80000000,
} ScePadButtonDataOffset;

/* This definietion is alias for support old style. */
#define SCE_PAD_BUTTON_START	SCE_PAD_BUTTON_OPTIONS


typedef struct ScePadAnalogStick {
	uint8_t x;
	uint8_t y;
} ScePadAnalogStick;

typedef struct ScePadAnalogButtons{
	uint8_t l2;
	uint8_t r2;
	uint8_t padding[2];
} ScePadAnalogButtons;

/**
 *E  
 *   @brief Maximum number of touch points.
 **/
#define SCE_PAD_MAX_TOUCH_NUM		2

/**
 *E  
 *   @brief device unique data size
 **/
#define SCE_PAD_MAX_DEVICE_UNIQUE_DATA_SIZE		12

/**
 *E  
 *   @brief Structure for touch point.
 *
 **/
typedef struct ScePadTouch {
	uint16_t  x;			/*E X position                */
	uint16_t  y;			/*E Y position                */
	uint8_t   id;			/*E Touch ID                  */
	uint8_t   reserve[3];	/*E reserved                  */
} ScePadTouch;

/**
 *E  
 *   @brief Structure for touch data.
 *
 **/
typedef struct ScePadTouchData {
	uint8_t touchNum;	/*E Number of touch reports */
	uint8_t reserve[3];	/*E reserved                */
	uint32_t reserve1;	/*E reserved                */
	ScePadTouch touch[SCE_PAD_MAX_TOUCH_NUM];	/*E actual touch data */
} ScePadTouchData;

/**
 *E  
 *   @brief Structure for extension unit data.
 *
 **/
typedef struct ScePadExtensionUnitData {
	uint32_t extensionUnitId;
	uint8_t  reserve[1];
	uint8_t  dataLength;
	uint8_t  data[10];
} ScePadExtensionUnitData;

struct UserServiceLoginUserIdList
{
	int user_id[4];
};


typedef struct vec_float3
{
	float x;
	float y;
	float z;
}vec_float3;

typedef struct vec_float4
{
	float x;
	float y;
	float z;
	float w;
}vec_float4;

typedef struct SceFQuaternion {
	float x, y, z, w;
} SceFQuaternion;


/**
 * @e @brief 32 bits integer 2D vector type @ee
 * @j @brief 32ビット整数型2次元ベクトル @ej
 */
typedef struct SceFVector3 {
	float x, y, z;
} SceFVector3;



typedef struct ScePadData {
	uint32_t				buttons;		/*E Digital buttons       */
	ScePadAnalogStick		leftStick;		/*E Left stick            */
	ScePadAnalogStick		rightStick;		/*E Right stick           */
	ScePadAnalogButtons		analogButtons;	/*E Analog buttons(R2/L2) */
	SceFQuaternion			orientation;	/*E Controller orientation as a Quaternion <x,y,z,w>
	                                         *E   It is calculated as an accumulation value when controller is connected.
											 *E   It can reset by scePadResetOrientation function. */
	SceFVector3				acceleration;	/*E Acceleration of the controller(G).    */
	SceFVector3				angularVelocity;/*E Angular velocity of the controller(radians/s). */
	ScePadTouchData         touchData;		/*E Touch pad data. */
	bool					connected;		/*E Controller connection status. true:connected  false:removed */
	uint64_t                timestamp;		/*E System timestamp of this data(micro seconds). */
	ScePadExtensionUnitData extensionUnitData; /*E Data area for retrieve the extension unit. */
	uint8_t                 connectedCount;
	uint8_t                 reserve[2];	/*E Reserved area */
	uint8_t                 deviceUniqueDataLen;	/*E Device unique data length(for special controllers) */
	uint8_t                 deviceUniqueData[SCE_PAD_MAX_DEVICE_UNIQUE_DATA_SIZE];	/*E Device unique data(for special controllers)        */
	
} ScePadData;

typedef struct ScePadOpenParam{
	uint8_t reserve[8]; /* reserved */
} ScePadOpenParam;

int scePadOpen(int userId, int32_t type, int32_t index, const ScePadOpenParam* pParam);
int scePadReadState(int32_t handle, ScePadData *pData);
int scePadInit(void);
int sceUserServiceGetLoginUserIdList(struct UserServiceLoginUserIdList *list);
