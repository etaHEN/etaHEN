#pragma once
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm> 
#include <iterator> 
#include <filesystem>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <json.hpp>
#include "../extern/tiny-json/tiny-json.hpp"
#include "../extern/pugixml-1.15/pugixml.hpp"


extern "C"
{    
    #include "pt.h"
    #include "mc4/mc4decrypter.h"
    #include "../lib/libmprotect.h"
    #include "ps5/mdbg.h"
    #include "ps5/kernel.h"
}
#define MAP_ANONYNMOUS 0x1000
#define NO_ASLR_ADDR_PS4 0x00400000

#define CHEATS_DIRECTORY "/data/etaHEN/cheats"
#define JSON_CHEATS_LIST "/data/etaHEN/cheats/json.txt"
#define MC4_CHEATS_LIST "/data/etaHEN/cheats/mc4.txt"
#define SHN_CHEATS_LIST "/data/etaHEN/cheats/shn.txt"

#define CACHE_LIMIT 100

#define MAX_CHEAT_FILEPATH_LEN 0x100
#define MAX_CHEAT_VERSION_LEN 20
#define MAX_CHEAT_TITLE_ID_LEN 32
#define MAX_CHEAT_GAMENAME_LEN 512
#define MAX_CHEAT_NAME 256

#define PS5_PAGE_SIZE 0x4000
#define ROUND_PG(x) (((x) + (PS5_PAGE_SIZE - 1)) & ~(PS5_PAGE_SIZE - 1))
#define ROUND_PG_DOWN(x) ((x) & ~(PS5_PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PS5_PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) |  \
		     (((x) & PF_W) ? PROT_WRITE : 0) |  \
		     (((x) & PF_X) ? PROT_EXEC  : 0))

typedef std::vector<uint8_t> ByteArray;
struct CheatMemory;
struct CheatInfo;
struct CheatMetadata;
struct GameCheat;

//
// Parse the json.txt, mc4.txt, shn.txt
//
typedef std::unordered_map<std::string, CheatMetadata> CheatCache;
//
// CheatVector type
// 
typedef std::vector<CheatInfo> Cheats;
typedef std::vector<CheatMemory> Mods;


enum  CheatExtType{
    JSON_CHEAT,
    MC4_CHEAT,
    SHN_CHEAT
};

struct CheatParsed
{
    std::vector<std::string> filepaths;
    GameCheat* parsed;
};

struct CheatMetadata
{
    std::string title_id;
    std::string game_name;
    // version : path
    std::unordered_map<std::string, CheatParsed> json;
    std::unordered_map<std::string, CheatParsed> mc4;
    std::unordered_map<std::string, CheatParsed> shn;
};

struct CheatMemory
{
    bool codeCaveReloc;
    int section; // section where the offset should be added: Default 0
    uint64_t Offset; // offset of the patch
    ByteArray On; // Data that should be inserted when the cheat is enabled
    ByteArray Off; // Data that should be inserted when the cheat is disabled
    bool absolute; // New To support section bigger than 0 when ASLR is off       // 09/10/2025 xZenithy
};

struct CheatInfo
{
    std::string name;
    std::string module_name;
    std::string description;
    bool enabled;
    Mods mods;
};

struct GameCheat
{
    //
    // The game title can hold non-ascii chars
    //
    std::string name;
    std::vector<std::string> authors;
    Cheats cheats;
    int masterCodeId;
    int cheatType;
};

#define MODULE_INFO_NAME_LENGTH 128
#define MODULE_INFO_SANDBOXED_PATH_LENGTH 1024
#define MODULE_INFO_MAX_SECTIONS 4
#define FINGERPRINT_LENGTH 20

typedef struct {
	uint64_t vaddr;
	uint64_t size;
    uint32_t prot;
} module_section_t;

typedef struct {
	char filename[MODULE_INFO_NAME_LENGTH];
	uint64_t handle;
	uint8_t unknown0[32]; // NOLINT(readability-magic-numbers)
	uint64_t init; // init
	uint64_t fini; // fini
	uint64_t eh_frame_hdr; // eh_frame_hdr
	uint64_t eh_frame_hdr_sz; // eh_frame_hdr_sz
	uint64_t eh_frame; // eh_frame
	uint64_t eh_frame_sz; // eh_frame_sz
	module_section_t sections[MODULE_INFO_MAX_SECTIONS];
	uint8_t unknown7[1176]; // NOLINT(readability-magic-numbers)
	uint8_t fingerprint[FINGERPRINT_LENGTH];
	uint32_t unknown8;
	char libname[MODULE_INFO_NAME_LENGTH];
	uint32_t unknown9;
	char sandboxed_path[MODULE_INFO_SANDBOXED_PATH_LENGTH];
	uint64_t sdk_version;
} module_info_t;

extern "C"
{
#include "freebsd-helper.h"
    void etaHEN_log(const char *fmt, ...);
    module_info_t* get_module_handle(int, const char*);    
    int sceSystemServiceGetAppIdOfRunningBigApp();
}

void* MakeInitialCheatCache(void*);
namespace CheatManager
{
    GameCheat* GetGameCheat(const std::string& name, const std::string& version);
    GameCheat* LoadCheat(CheatMetadata* meta, const std::string& version, CheatExtType type, GameCheat* cheat);
    bool ToggleCheat(int pid, const std::string& title_id, int cheat_index, std::string& cheat_name);
    //
    // Thread to monitor if the current game continue running
    //
    void* MonitorOpenGame(CheatMetadata* cheatMeta);

    namespace CheatManagerFormats
    {
        GameCheat* ParseJSONCheat(const std::string& filename, GameCheat* parsed = nullptr);
        GameCheat* ParseMC4Cheat(const std::string& filename, GameCheat* parsed = nullptr);
        GameCheat* ParseSHNCheat(const std::string& filename, GameCheat* parsed = nullptr);
        GameCheat* ParseXMLCheat(const std::string& xml, GameCheat* parsed = nullptr);
    }

    namespace Converters
    {
        //
        // based on https://gist.github.com/userx007/9020ecc81a33b304a081442512149356
        //
        int ascii2val(char c);
        ByteArray unhexlify(std::string &InBuffer);
    }
};

void* ReloadCheatsCache(void*);