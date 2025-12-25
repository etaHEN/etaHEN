#include "json.hpp"
#include <string>
#include <vector>
#include <dirent.h>
#include <unordered_map>
extern "C" {
#include "common_utils.h"

typedef struct app_launch_ctx
{
  int structsize;
  int user_id;
  int app_opt;
  uint64_t crash_report;
  int check_flag;
} app_launch_ctx_t;

int sceSystemServiceLaunchApp(const char *, char **, app_launch_ctx_t *);

#define SCE_LNC_UTIL_ERROR_ALREADY_RUNNING 0x8094000c
#define SCE_LNC_UTIL_ERROR_ALREADY_RUNNING_KILL_NEEDED 0x80940010
#define SCE_LNC_UTIL_ERROR_ALREADY_RUNNING_SUSPEND_NEEDED 0x80940011
}

#define SHELL_DEBUG 1
#include <sys/stat.h>
#include <fstream>
#include <ctime>
#include <iostream>
#include <random>
#include <sys/mount.h>
#include <sstream>

using json = nlohmann::json;

// Game Entry structure definition
struct GameEntry {
    std::string tid;         // Title ID
    std::string title;       // Game title
    std::string version;     // Game version
    std::string path;        // Displayed path
    std::string dir_name;    // Directory name
    std::string icon_path;   // Path to icon
    std::string id;          // Button ID
  };

  std::vector<GameEntry> games_list;

void escapePath(std::string& input) 
{
    std::unordered_map<std::string, std::string> escapeSequences = 
    {
        {"&", "&amp;"},
        {"<", "&lt;"},
        {">", "&gt;"},
        {"\"", "&quot;"},
        {"/", "//"}
    };
    
    for (const auto& pair : escapeSequences) 
    {
        size_t pos = 0;
        while ((pos = input.find(pair.first, pos)) != std::string::npos) 
        {
            input.replace(pos, pair.first.length(), pair.second);
            pos += pair.second.length(); // Move past the replaced part
        }
    }
}

void escapeXML(std::string& input) 
{
    std::unordered_map<std::string, std::string> escapeSequences = 
    {
        {"&", "&amp;"},
        {"<", "&lt;"},
        {">", "&gt;"},
        {"\"", "&quot;"},
    };
    
    for (const auto& pair : escapeSequences) 
    {
        size_t pos = 0;
        while ((pos = input.find(pair.first, pos)) != std::string::npos) 
        {
            input.replace(pos, pair.first.length(), pair.second);
            pos += pair.second.length(); // Move past the replaced part
        }
    }
}


bool getContentInfofromJson(const std::string& file_path, std::string& tid, std::string& title, std::string &ver) {
  try {
      std::ifstream input_file(file_path);
      if (!input_file.is_open()) {
          etaHEN_log("Failed to open file for reading: %s", file_path.c_str());
          return false;
      }

      json j;
      input_file >> j;
      input_file.close();

      if (!j.contains("titleId")) {
          etaHEN_log("JSON does not contain a required value");
          return false;
      }

      tid = j["titleId"];

      #if SHELL_DEBUG==1 
      etaHEN_log("getContentInfofromJson Title ID: %s", tid.c_str());
      #endif

      if (j.contains("localizedParameters") && j["localizedParameters"].contains("defaultLanguage")) {
          std::string defaultLanguage = j["localizedParameters"]["defaultLanguage"];
          if (j["localizedParameters"].contains(defaultLanguage) && j["localizedParameters"][defaultLanguage].contains("titleName")) {
              title = j["localizedParameters"][defaultLanguage]["titleName"];
          }
      }
      else
          title = "App Title not found";

      if (j.contains("contentVersion"))
          ver = j["contentVersion"];

  }
  catch (const std::exception& e) {
    etaHEN_log("Exception: %s", e.what());
    return false;
}

  return true;
}


// Helper function to check if path is from external storage
bool isExternalStorage(const std::string &path) {
  return path.rfind("/mnt/ext") != std::string::npos;
}

// Helper function to copy files
bool copyFile(const std::string &src, const std::string &dst) {
  std::ifstream source(src, std::ios::binary);
  if (!source.is_open()) {
    #if SHELL_DEBUG==1
    etaHEN_log("Failed to open source file: %s", src.c_str());
    #endif
    return false;
  }
  
  std::ofstream dest(dst, std::ios::binary);
  if (!dest.is_open()) {
    #if SHELL_DEBUG==1
    etaHEN_log("Failed to open destination file: %s", dst.c_str());
    #endif
    return false;
  }
  
  dest << source.rdbuf();
  source.close();
  dest.close();
  return true;
}

// Main function
void generate_games_xml(std::string &xml_buffer, bool game_shortcut_activated)
{
  struct dirent *entry;
  unlink("/data/etaHEN/games_list.xml");

  std::vector<std::string> directories = {
    "/user/data/etaHEN/games",
    "/mnt/usb0/etaHEN/games",
    "/mnt/usb1/etaHEN/games",
    "/mnt/usb2/etaHEN/games",
    "/mnt/usb3/etaHEN/games",
    "/mnt/ext1/etaHEN/games",
    "/mnt/ext2/etaHEN/games",
    "/mnt/ext0/etaHEN/games",
  };

  std::string list_id = game_shortcut_activated ? "id_debug_settings" : "id_ps5_backups";

  xml_buffer = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
      "<system_settings version=\"1.0\" plugin=\"debug_settings_plugin\">\n"
      "\n";

  xml_buffer += "<setting_list id=\"" + list_id + "\" title=\"(Beta) PS5 webMAN Games\">\n";

  // Initialize random number generator
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dist(1000, 9999);

  // Create cache directory
  mkdir("/data/etaHEN/cache", 0777);

  for (const auto &directory : directories)
  {
    DIR *dir = opendir(directory.c_str());
    if (!dir)
    {
      #if SHELL_DEBUG==1 
      etaHEN_log("Failed to open directory: %s error %s", directory.c_str(), strerror(errno));
      #endif
      continue;
    }
    
    while ((entry = readdir(dir)) != nullptr)
    {
      // Skip . and .. directories
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        continue;
        
      std::string game_dir = directory + "/" + entry->d_name;
      
      // Check if this is a directory
      struct stat st;
      if (stat(game_dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        #if SHELL_DEBUG==1 
        etaHEN_log("Skipping non-directory: %s", game_dir.c_str());
        #endif
        continue;
      }
        
      std::string param_path = game_dir + "/sce_sys/param.json";
      std::string icon_path = game_dir + "/sce_sys/icon0.png";
      
      // Check if param.json exists
      if (access(param_path.c_str(), F_OK) != 0) {
        #if SHELL_DEBUG==1 
        etaHEN_log("No param.json found in: %s", game_dir.c_str());
        #endif
        continue;
      }
      
      #if SHELL_DEBUG==1 
      etaHEN_log("Found Game: %s", game_dir.c_str());
      #endif
      
      // Parse JSON to get title_id, content_id, title, and version
      std::string title_id, title, ver;
      if (!getContentInfofromJson(param_path, title_id, title, ver)) {
        #if SHELL_DEBUG==1 
        etaHEN_log("Failed to parse param.json in: %s", game_dir.c_str());
        #endif
        continue;
      }
      
      std::string shown_path = game_dir;
      
      const std::string prefix = "/user";
      if (shown_path.find(prefix) == 0) {
         shown_path = shown_path.substr(prefix.length());
      }
      
      shown_path = (game_dir.substr(0, 4) == "/usb") ? "/mnt" + game_dir : shown_path;
      
      // Generate a random number for the ID
      int random_num = dist(gen);

      // Handle icon path and caching
      if (isExternalStorage(game_dir)) {
        // Cache icon from external storage
        // not /data but /user/data for shellui as it's not accessible from /data
        std::string cached_icon_path = "/user/data/etaHEN/cache/" + title_id + ".png";
        
        // Copy icon if it doesn't exist
        if (access(cached_icon_path.c_str(), F_OK) != 0) {
          if (!copyFile(icon_path, cached_icon_path)) {
            #if SHELL_DEBUG==1
            etaHEN_log("Failed to cache icon from: %s", icon_path.c_str());
            #endif
            cached_icon_path = icon_path; // Fallback to original
          } else {
            #if SHELL_DEBUG==1
            etaHEN_log("Cached icon: %s", cached_icon_path.c_str());
            #endif
          }
        }
        icon_path = cached_icon_path;
      } else if (icon_path.find("/mnt/usb") == 0) {
        // Transform /mnt/usb... to /usb...
        icon_path = icon_path.substr(4); // Remove "/mnt"
      }
  

      // Escape paths for XML
      escapePath(icon_path);
      escapeXML(title);
      escapeXML(shown_path);

      // Create and populate a GameEntry
      GameEntry game;
      game.tid = title_id;
      game.title = title;
      game.version = ver;
      game.path = shown_path;
      game.dir_name = entry->d_name;
      game.icon_path = icon_path;
      game.id = "id_etahen_game_loader_" + title_id + "_" + std::to_string(random_num);
      
      // Add to the games list
      games_list.push_back(game);
      
      // Format the button XML
      std::string button = "<button id=\"" + game.id + "\" title=\"(" + title_id + ") " + title + 
      "\" icon=\"" + icon_path + "\" second_title=\"" + shown_path + " | Version: " + ver + "\"/>\n";
      
      xml_buffer += button;
    }
    
    closedir(dir);
  }

  xml_buffer += "</setting_list>\n</system_settings>";
}

#define IOVEC_ENTRY(x) {x ? (char *)x : 0, x ? strlen(x) + 1 : 0}
#define IOVEC_SIZE(x) (sizeof(x) / sizeof(struct iovec))

int mount_nullfs(const char *src, const char *dst)
{
  struct iovec iov[] = {
      IOVEC_ENTRY("fstype"),
      IOVEC_ENTRY("nullfs"),
      IOVEC_ENTRY("from"),
      IOVEC_ENTRY(src),
      IOVEC_ENTRY("fspath"),
      IOVEC_ENTRY(dst),
  };

  return nmount(iov, IOVEC_SIZE(iov), 0);
}

int endswith(const char *string, const char *suffix)
{
  size_t suffix_len = strlen(suffix);
  size_t string_len = strlen(string);

  if (string_len < suffix_len)
  {
    return 0;
  }

  return strncmp(string + string_len - suffix_len, suffix, suffix_len) != 0;
}

int chmod_bins(const char *path)
{
  char buf[PATH_MAX + 1];
  struct dirent *entry;
  struct stat st;
  DIR *dir;

  if (stat(path, &st) != 0)
  {
    return -1;
  }

  if (endswith(path, ".prx") || endswith(path, ".sprx") || endswith(path, "/eboot.bin"))
  {
    chmod(path, 0755);
  }

  if (S_ISDIR(st.st_mode))
  {
    dir = opendir(path);
    while (1)
    {
      entry = readdir(dir);
      if (entry == nullptr)
      {
        break;
      }

      if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      {
        continue;
      }

      sprintf(buf, "%s/%s", path, entry->d_name);
      chmod_bins(buf);
    }

    closedir(dir);
  }

  return 0;
}

int Launch_FG_Game(const char *path, const char* title_id, const char* title){
  app_launch_ctx_t ctx = {0};
  char dst[PATH_MAX + 1];

  strcpy(dst, "/system_ex/app/");
  strcat(dst, title_id);
  mkdir(dst, 0777);

  sceUserServiceInitialize(0);
  sceUserServiceGetForegroundUser(&ctx.user_id);
  mount_nullfs(path, dst);
  chmod_bins(path);

  char *argv[] = {(char*)title, nullptr};

  return sceSystemServiceLaunchApp(title_id, &argv[0], &ctx);
}


bool Launch_Game_By_ID(const char* button_id){
   if (games_list.empty()){
        return false;
    }
    for (auto game : games_list) {
        if (game.id == button_id) {
    
            etaHEN_log("[Clicked %s] TID: %s title: %s version: %s path: %s", game.id.c_str(), game.tid.c_str(), game.title.c_str(), game.version.c_str(), game.path.c_str());
        
            notify(true, "Launching %s (%s)\nPath: %s", game.title.c_str(), game.tid.c_str(), game.path.c_str());
                //const char *path, const char* title_id, const char* title
            int res = Launch_FG_Game(game.path.c_str(), game.tid.c_str(), game.title.c_str());
            if (res < 0 && res != SCE_LNC_UTIL_ERROR_ALREADY_RUNNING_KILL_NEEDED && res != SCE_LNC_UTIL_ERROR_ALREADY_RUNNING && res != SCE_LNC_UTIL_ERROR_ALREADY_RUNNING_SUSPEND_NEEDED) {
                notify(true, "Failed to launch %s (%s)\nError: 0x%X", game.title.c_str(), game.tid.c_str(), res);
                return false;
            }

            
        }
    }
    return true;
}
