
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

#include "ipc.hpp"
#include <msg.hpp>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>
extern "C" {
#include "common_utils.h"
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>

int sceKernelMprotect(void *addr, size_t len, int prot);
pid_t elfldr_spawn(const char* cwd, int stdio, uint8_t* elf, const char* name);


extern uint8_t elfldr_start[];
extern const unsigned int elfldr_size;

int sceSystemServiceLoadExec(const char *path, const char *arg);
extern bool is_handler_enabled;
}
#include "../extern/tiny-json/tiny-json.hpp"
#include <CheatManager.hpp>
#include <fcntl.h>
#include <fstream>
#include <json.hpp>
#include <memory>
#include <sfo.hpp>
#include <sstream>

extern pthread_t cmd_server;
void* runCommandNControlServer(void*);
void generate_games_xml(std::string &xml_buffer, bool game_shortcut_activated);
bool Launch_Game_By_ID(const char* button_id);
// pop -Winfinite-recursion error for this func for clang
#define MB(x) ((size_t)(x) << 20)
#define READ_SIZE 0x1024

extern "C" void shutdown_klog(void);
extern atomic_bool no_network_rest_mode_action, real_rest_mode_detected;

extern int shellui_pid_for_comp;
extern uintptr_t code_addr;

extern char ip_address[];

int DaemonSocket = 0;

bool startDirectPKGInstaller(bool is_v2);
bool if_exists(const char *path);

extern "C" int launchApp(const char *titleId);

bool if_exists(const char *path);
void activate_shellui_patch();
bool LoadSettings();

bool rmtree(const char *path) {
  DIR *dir = opendir(path);
  if (dir == NULL) {
    etaHEN_log("Error opening directory %s", path);
    return false;
  }

  struct dirent *entry;

  while ((entry = readdir(dir)) != NULL) {
    // Skip "." and ".." entries
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    char path_1[1000];
    snprintf(path_1, sizeof(path_1), "%s/%s", path, entry->d_name);

    if (entry->d_type == DT_DIR) {
      // Recursive call for subdirectories
      rmtree(path_1);
    } else {
      // Delete files
      if (unlink(path_1) != 0) {
        // perror("Error deleting file");
        etaHEN_log("Error deleting file %s", path);
      }
    }
  }

  closedir(dir);

  // Delete the empty folder
  if (rmdir(path) != 0) {
    // perror("Error deleting folder");
    etaHEN_log("Error deleting folder %s", path);
  }

  return true;
}

struct sockaddr_in networkAdress(uint16_t port) {
  struct sockaddr_in address;
  address.sin_len = sizeof(address);
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  memset(address.sin_zero, 0, sizeof(address.sin_zero));
  return address;
}

int networkListen(const char *soc_path) {
  struct sockaddr_un server;
  unlink(soc_path);
  etaHEN_log("[Daemon] Deleted Socket...");
  int s = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s < 0) {
    etaHEN_log("[Daemon] Socket failed! %s", strerror(errno));
    return INVAIL;
  }

  memset(&server, 0, sizeof(server));
  server.sun_family = AF_UNIX;
  strcpy(server.sun_path, soc_path);

  int r = bind(s, (struct sockaddr *)&server, SUN_LEN(&server));
  if (r < 0) {
    etaHEN_log("[Daemon] Bind failed! %s", strerror(errno));
    return INVAIL;
  }

 // etaHEN_log("Socket has name %s", server.sun_path);

  r = listen(s, 100);
  if (r < 0) {
    etaHEN_log("[Daemon] listen failed! %s", strerror(errno));
    return INVAIL;
  }

  return s;
}

int networkAccept(int socket) {
  return accept(socket, 0, 0);
}

int networkReceiveData(int socket, void *buffer, int32_t size) {
  int nu = recv(socket, buffer, size, 0);
  etaHEN_log("got %i bytes", nu);
  return nu;
}

int networkSendData(int socket, void *buffer, int32_t size) {
  return send(socket, buffer, size, MSG_NOSIGNAL);
}

int networkSendDebugData(void *buffer, int32_t size) {
  return networkSendData(DaemonSocket, buffer, size);
}

int networkCloseConnection(int socket) { return close(socket); }

int networkCloseDebugConnection() {
  return networkCloseConnection(DaemonSocket);
}

void reply(int sender_socket, bool error, std::string out_var = "Nothing") {

  std::string inputStr = "{\"res\":" + std::to_string(error ? -1 : 0) +
                         ", \"var\":\"" + out_var + "\"}";

  IPCMessage outputMessage;
  outputMessage.cmd = BREW_UTIL_RETURN_VALUE;
  outputMessage.error = error ? -1 : 0;
  etaHEN_log("error: %d", outputMessage.error);
  if (!inputStr.empty()) {
    strncpy(outputMessage.msg, inputStr.c_str(), sizeof(outputMessage.msg) - 1);
    // Null-terminate the destination array
    outputMessage.msg[sizeof(outputMessage.msg) - 1] = '\0';
  }

  networkSendData(sender_socket, reinterpret_cast<void *>(&outputMessage),
                  sizeof(outputMessage));
}

std::vector<uint8_t> readFile(std::string filename) {
  // open the file:
  std::ifstream file(filename, std::ios::binary);
  if (!file.is_open()) {
    etaHEN_log("Failed to open %s", filename.c_str());
    return std::vector<uint8_t>();
  }

  // Stop eating new lines in binary mode!!!
  file.unsetf(std::ios::skipws);

  // get its size:
  std::streampos fileSize;

  file.seekg(0, std::ios::end);
  fileSize = file.tellg();
  file.seekg(0, std::ios::beg);

  // reserve capacity
  std::vector<uint8_t> vec;

  vec.reserve(fileSize);

  // read the data:
  vec.insert(vec.begin(), std::istream_iterator<uint8_t>(file),
             std::istream_iterator<uint8_t>());

  return vec;
}

std::string GetPS5Version(const std::string &jsonpath) {
  try {
    std::ifstream input_file(jsonpath);
    if (!input_file.is_open()) {
      etaHEN_log("Failed to open file for reading: %s", jsonpath.c_str());
      return "Error Opening Json";
    }

    nlohmann::json j;
    input_file >> j;
    input_file.close();

    if (j.contains("contentVersion"))
      return std::string(j["contentVersion"]);

  } catch (const std::exception &e) {
    // Handle exceptions here, you can log the error or perform other error
    // handling tasks
    etaHEN_log("An exception occurred: %s", e.what());
    return "Error getting version";
  }

  return "Error getting version";
}

// Callback function to write received data
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
  FILE *fp = (FILE *)userp;
  return fwrite(contents, size, nmemb, fp);
}

void handleIPC(struct clientArgs *client, std::string &inputStr,
               DaemonCommands command) {

  constexpr uint32_t MAX_TOKENS = 256;
  json_t pool[MAX_TOKENS]{};
  int sender_app = client->socket;

  std::string path_buf, path_buf2, json_path;

  char temp[0x255];
  std::string out_var = "Nothing"; // default send var

  etaHEN_log("Received IPC command 0x%X", command);
  // etaHEN_log("Received IPC data: %s", inputStr.c_str());

  json_t const *my_json =
      inputStr.empty()
          ? NULL
          : json_create((char *)inputStr.c_str(), pool, MAX_TOKENS);
  if (!my_json) {
    etaHEN_log("Error parsing JSON");
    notify(true, "Error parsing JSON");
    reply(sender_app, true);
    return;
  }

  switch (command) {
  case BREW_UTIL_SHELLUI_ON_STANDBY: {
    etaHEN_log("ShellUI on standby");
    real_rest_mode_detected = no_network_rest_mode_action = true;
    reply(sender_app, false);
    break;
  }
  case BREW_UTIL_TOGGLE_FTP: {
    bool turn_on = (bool)json_getInteger(json_getProperty(my_json, "toggle"));
    etaHEN_log("FTP toggle: %d", turn_on);
    if (turn_on) {
      if (StartFTP()) {
        notify(true, "FTP Server Started\nIP: %s Port: 1337", ip_address);
        reply(sender_app, false);
        break;
      } else
        reply(sender_app, true);
    } else {
      ShutdownFTP();
      notify(true, "FTP Server Stopped");
      reply(sender_app, false);
    }
    break;
  }
  case BREW_UTIL_TOGGLE_KLOG: {
    bool turn_on = (bool)json_getInteger(json_getProperty(my_json, "toggle"));
    etaHEN_log("klog toggle: %d", turn_on);
    if (turn_on) {
      if (start_klog()) {
        notify(true, "Klog Server Started\nIP: %s Port: 9081", ip_address);
        reply(sender_app, false);
      } else
        reply(sender_app, true);
    } else {
      shutdown_klog();
      notify(true, "Klog Server Stopped");
      reply(sender_app, false);
    }
    break;
  }
  case BREW_UTIL_TOGGLE_DPI: {
    bool turn_on = (bool)json_getInteger(json_getProperty(my_json, "toggle"));
    bool is_v2 = (bool)json_getInteger(json_getProperty(my_json, "is_v2"));
    etaHEN_log("DPI toggle: %d | is_v2 %s", turn_on, is_v2 ? "true" : "false");
    if (turn_on) {
      if (startDirectPKGInstaller(is_v2)) {
        notify(true,
               is_v2 ? "Direct PKG Installer V2 Server Started\nWebUI: "
                       "http://%s:12800 "
                     : "Direct PKG Installer Server Started\nIP: %s Port: 9090",
               ip_address);
        reply(sender_app, false);
      } else
        reply(sender_app, true);
    } else {
      shutdownDirectPKGInstaller(is_v2);
      notify(true, is_v2 ? "Direct PKG Installer V2 Server Stopped"
                         : "Direct PKG Installer Server Stopped");
      reply(sender_app, false);
    }
    break;
  }
  case BREW_UTIL_DAEMON_PID: {
    snprintf(temp, sizeof(temp), "%d", getpid());
    reply(sender_app, false, temp);
    break;
  }
  case BREW_UTIL_GET_GAME_VER: {
    auto tid = std::string(json_getPropertyValue(my_json, "tid"));
    if (tid.empty()) {
      notify(true, "Failed to get tid");
      reply(sender_app, true);
      break;
    }

    std::string tmp, game_version;
    bool is_PS5 = tid.rfind("PPSA", 0) == 0; // Check if tid starts with "PPSA"
    if (is_PS5) {
      // Attempt to load JSON files for PS5 games
      tmp = "/system_data/priv/appmeta/" + tid + "/param.json";
      if (!if_exists(tmp.c_str())) {
        etaHEN_log("%s: json %s does not exist", tid.c_str(), tmp.c_str());
        tmp = "/system_data/priv/appmeta/external/" + tid + "/param.json";

        if (!if_exists(tmp.c_str())) {
          etaHEN_log("%s: json %s does not exist", tid.c_str(), tmp.c_str());
          tmp = "/system_ex/app/" + tid + "/sce_sys/param.json";
          if (!if_exists(tmp.c_str())) {
            etaHEN_log("%s: json %s does not exist", tid.c_str(), tmp.c_str());
            notify(true, "Failed to get game version");
            reply(sender_app, true);
            break;
          }
        }
      }

      game_version = GetPS5Version(tmp);
      if (game_version.empty()) {
        notify(true, "Failed to get game version");
        etaHEN_log("Failed to get game version for PS5 Game");
        reply(sender_app, true);
        break;
      }
    } else {
      // Attempt to load SFO files for PS4 games
      tmp = "/system_data/priv/appmeta/" + tid + "/param.sfo";
      if (!if_exists(tmp.c_str())) {
        etaHEN_log("%s: sfo %s does not exist", tid.c_str(), tmp.c_str());
        tmp = "/system_data/priv/appmeta/external/" + tid + "/param.sfo";
        if (!if_exists(tmp.c_str())) {
          etaHEN_log("%s: sfo %s does not exist", tid.c_str(), tmp.c_str());
          notify(true, "Failed to get game version");
          reply(sender_app, true);
          break;
        }
      }

      std::vector<uint8_t> sfo_data = readFile(tmp);
      if (sfo_data.empty()) {
        notify(true, "Failed to read SFO file");
        reply(sender_app, true);
        break;
      }

      SfoReader sfo(sfo_data);
      // VERSION key holds the original version, it doesn't change if updated
      try {
          std::string version_str = sfo.GetValueFor<std::string>("VERSION");
          std::string app_ver_str = sfo.GetValueFor<std::string>("APP_VER");

          float version_val = std::stof(version_str);
          float app_ver_val = std::stof(app_ver_str);

          game_version = (version_val > app_ver_val) ? version_str : app_ver_str;
      }
      catch (const std::exception& e) {
          // Fallback to APP_VER if there's an issue
          game_version = sfo.GetValueFor<std::string>("APP_VER");
      }
    }

    etaHEN_log("Version: %s", game_version.c_str());
    reply(sender_app, false, game_version);

    break;
  }
  case BREW_UTIL_LAUNCH_PLUGIN: {
    std::string plugin_path =
        std::string(json_getPropertyValue(my_json, "plugin_path"));
    std::string title_id =
        std::string(json_getPropertyValue(my_json, "title_id"));
    etaHEN_log("Launching %s (TID: %s)", plugin_path.c_str(),
               title_id.c_str());
    if (!load_plugin(plugin_path.c_str())) {
      notify(true, "Failed to Load in\nPath: %s\nTID: %s",
             plugin_path.c_str(), title_id.c_str());
      reply(sender_app, true);
      break;
    }
    notify(true, "Plugin or ELF launched successfully\nPath: %s\nTID: %s",
           plugin_path.c_str(), title_id.c_str());
    reply(sender_app, false);
    break;
  }

  case BREW_UTIL_GET_GAME_CHEAT: {
    std::string title_id = std::string(json_getPropertyValue(my_json, "tid"));
    std::string version =
        std::string(json_getPropertyValue(my_json, "version"));
    GameCheat *cheat = CheatManager::GetGameCheat(title_id, version);

    if (cheat) {
      //
      // Build json response, we need escape the quotes because the IPC response
      // is also between quotes, which break the JSON response
      //
      nlohmann::json res_json;

      // Set the name
      res_json["name"] = cheat->name;

      // Build the cheats array
      for (size_t i = 0; i < cheat->cheats.size(); ++i) {
        nlohmann::json cheat_entry;
        cheat_entry["name"] = cheat->cheats[i].name;
        cheat_entry["id"] = static_cast<int>(i);
        cheat_entry["enabled"] = cheat->cheats[i].enabled;
        cheat_entry["description"] = cheat->cheats[i].description;
        res_json["cheats"].push_back(cheat_entry);
      }

      // Build the authors array
      for (size_t i = 0; i < cheat->authors.size(); ++i) {
        res_json["authors"].push_back(cheat->authors[i]);
      }

      std::string res = res_json.dump();
      #if SHELL_DEBUG == 1
      etaHEN_log("Response json => %s (%d bytes)", res.c_str(), res.size());
      #endif

      //
      // Create a shared file contained the parsed cheat
      //

      std::string shm_path = "/user/data/etaHEN/" + title_id + "_cheats";
      unlink(shm_path.c_str());

      int fd = open(shm_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
      if (fd >= 0) {
        // Write the buffer to the file
        if (write(fd, res.c_str(), res.length()) == -1) {
          perror("write failed");
        }
        // Close the file descriptor
        close(fd);
      }

      reply(sender_app, false, shm_path);

    } else {
      notify(true, "No cheats available for %s version %s!", title_id.c_str(),
             version.c_str());
      reply(sender_app, true);
    }

    break;
  }

  case BREW_UTIL_TOGGLE_CHEAT: {
    std::string title_id = std::string(json_getPropertyValue(my_json, "tid"));
    json_t const *cheat_id_property = json_getProperty(my_json, "cheat_id");
    json_t const *target_pid_property = json_getProperty(my_json, "pid");
    int pid = json_getInteger(target_pid_property);
    int cheat_id = json_getInteger(cheat_id_property);
    std::string cheat_name;

    etaHEN_log("Received toggle command for cheat %d on %s PID %d ID %d",
               cheat_id, title_id.c_str(), pid, cheat_id);

    if (CheatManager::ToggleCheat(pid, title_id, cheat_id, cheat_name)) {
      etaHEN_log("Cheat successfully activated!");
      reply(sender_app, false, cheat_name);
    } else {
      reply(sender_app, true);
    }
    break;
  }
  case BREW_UTIL_LAUNCH_ELFLDR: {
#if 1
    if (elfldr_spawn("/", STDOUT_FILENO, elfldr_start, "elfldr.elf") >= 0) {
      reply(sender_app, false);
      break;
    }
#endif
    reply(sender_app, true);
    break;
  }
  case BREW_UTIL_DOWNLOAD_CHEATS: {
    json_t const *target_repo_property = json_getProperty(my_json, "repo");
    int repo = json_getInteger(target_repo_property);

    if(!check_for_new_commit(repo)){
      etaHEN_log("Failed to check for new commit or is up to date");
      reply(sender_app, false);
      break;
    }
    notify(true, "Downloading the latest %s Cheats repo....", repo ? "GoldHEN PS4" : "etaHEN PS5");
    if (!download_file(repo ? "https://api.github.com/repos/GoldHEN/GoldHEN_Cheat_Repository/zipball" : "https://api.github.com/repos/etaHEN/PS5_Cheats/zipball",
                       "/data/etaHEN/cheats.zip")) {
      etaHEN_log("Failed to download cheats");
      reply(sender_app, true);
      break;
    }
    etaHEN_log("Extracting Zip to the cheats folder");
    if (!extract_zip("/data/etaHEN/cheats.zip", "/data/etaHEN/cheats")) {
      etaHEN_log("Failed to extract zip");
      reply(sender_app, true);
      break;
    }

    unlink("/data/etaHEN/cheats.zip");
    MakeInitialCheatCache(NULL);
    notify(true, "Successfully updated & refreshed the etaHEN Cheats with the latest cheats repo");
    reply(sender_app, false);
    break;
  }
  case BREW_UTIL_DOWNLOAD_KSTUFF: {
      notify(true, "Attempting to Download kstuff ...");
      if (!download_file("https://github.com/EchoStretch/kstuff/releases/latest/download/kstuff.elf",
          "/data/etaHEN/kstuff.elf")) {
		  unlink("/data/etaHEN/kstuff.elf");
          etaHEN_log("Failed to download kstuff");
          reply(sender_app, true);
          break;
      }

      notify(true, "Successfully downloaded latest kstuff");
      reply(sender_app, false);
      break;
  }
  case BREW_UTIL_RELOAD_CHEATS: {
    notify(true, "Reloading cheats cache");
    ReloadCheatsCache(NULL);
    reply(sender_app, false);
    break;
  }
  case BREW_UTIL_TOGGLE_LEGACY_CMD_SERVER: {
    bool turn_on = (bool)json_getInteger(json_getProperty(my_json, "toggle"));
    etaHEN_log("Legacy Command Server toggle: %d", turn_on);
    if (turn_on) {
      notify(true, "Legacy Command Server Enabled");
      global_conf.legacy_cmd_server = true;
      global_conf.legacy_cmd_server_exit = true;
    } else {
	  // dont exit server because its used to detect rest mode too 
      // just stop handling commands
      global_conf.legacy_cmd_server = false;
      notify(true, "Legacy Command Server Disabled");
    }
    reply(sender_app, false);
	break;
  }
  case BREW_UTIL_GET_GAMES_LIST:{
    bool cheats_activated_shortcut = json_getInteger(json_getProperty(my_json, "shortcut"));
    std::string games_list;
    generate_games_xml(games_list, cheats_activated_shortcut);

    std::string shm_path = "/user/data/etaHEN/games_list.xml";
    //make file 
    int fd = open(shm_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd >= 0) {
        // Write the buffer to the file
      if (write(fd, games_list.c_str(), games_list.length()) == -1) {
          perror("write failed");
          close(fd);
          reply(sender_app, true);
          break;
      }
        // Close the file descriptor
      close(fd);
      reply(sender_app, false, shm_path);
      break;
    } else {
        notify(true, "Failed to create shared file for games list!");
       // generate_default_games_xml(games_list, cheats_activated_shortcut);
        reply(sender_app, true);
        break;
    }
    
    break;
  }
  case BREW_UTIL_LAUNCH_GAME_BY_BUTTON_ID:{
    std::string button_id = std::string(json_getPropertyValue(my_json, "button_id"));
    etaHEN_log("Launching game with button id: %s", button_id.c_str());
    int res = Launch_Game_By_ID(button_id.c_str());
    if (res < 0) {
      reply(sender_app, true);
      break;
    }
    reply(sender_app, false);
    break;
  }
  case BREW_KILL_DAEMON:{
    is_handler_enabled = false;
    exit(1337);
    kill(getpid(), SIGKILL);
    reply(sender_app, false);
    break;
  }
  case BREW_RELOAD_SETTINGS: {
    LoadSettings();
    //notify(true, "Reloaded Settings");
    reply(sender_app, false);
    break;
  }
  default:
    notify(true, "Unknown command 0x%X", command);
    reply(sender_app, true);
    break;
  }
}

void *ipc_client(void *args) {
  struct clientArgs *client = (struct clientArgs *)args;
  etaHEN_log("[Daemon IPC] Thread created for Socket %i", client->socket);

  uint32_t readSize = 0;
  IPCMessage ipcMessage; // Create an IPCMessage struct to store received data

  while ((readSize = networkReceiveData(client->socket,
                                        reinterpret_cast<void *>(&ipcMessage),
                                        sizeof(ipcMessage))) > 0) {
    if (ipcMessage.magic == 0xDEADBABE) {
      // Handle IPCMessage
      std::string message = ipcMessage.msg; // Retrieve the std::string message
      handleIPC(client, message, ipcMessage.cmd);
    } else {
      etaHEN_log("[Daemon IPC][client %i] Invalid magic number",
                 client->cl_nmb);
      ipcMessage.error = -1;
      networkSendData(client->socket, reinterpret_cast<void *>(&ipcMessage),
                      sizeof(ipcMessage));
    }
  }

  etaHEN_log(
      "[Daemon IPC][client %i] IPC Connection disconnected, Shutting down ...",
      client->cl_nmb);

  networkCloseConnection(client->socket);
  delete client;
  pthread_exit(NULL);

  return NULL;
}

void *IPC_loop(void *args) {
  // Listen on port
  int serverSocket = networkListen(UTIL_IPC_SOC);
  if (serverSocket < 0) {
    etaHEN_log("[Daemon IPC] networkListen error %s", strerror(errno));
    return nullptr;
  }

  // Keep accepting client connections
  int cli_new = 0;
  while (true) {
    // Accept a client connection
    int clientSocket = networkAccept(serverSocket);
    if (clientSocket < 0) {
      etaHEN_log("[Daemon IPC] networkAccept error %s", strerror(errno));
      break; // Breaking out of the loop on error to cleanup
    }

    etaHEN_log("[Daemon IPC] Connection Accepted");
    etaHEN_log("[Daemon IPC] cl_nmb %i", cli_new);

    // Build data to send to thread
    auto clientParams = new clientArgs();
    clientParams->ip = "localhost";
    clientParams->socket = clientSocket;
    clientParams->cl_nmb = cli_new;

    etaHEN_log("[Daemon IPC] clientParams->cl_nmb %i", clientParams->cl_nmb);
    pthread_t ipc_thread;
    pthread_create(&ipc_thread, NULL, ipc_client, clientParams);
    pthread_detach(ipc_thread); // Detach the thread to allow it to run independently
    cli_new++;
  }

  // Cleanup
  networkCloseConnection(serverSocket);
  return nullptr;
}