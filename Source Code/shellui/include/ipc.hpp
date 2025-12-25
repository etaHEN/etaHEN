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
#include <strings.h>
#ifndef IPC_HEADER_H
#define IPC_HEADER_H

#include "HookedFuncs.hpp"
#include <array>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <json.hpp>
#include <memory>
#include <msg.hpp>
#include <mutex>
#include <stdarg.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>
#include <ps5/klog.h>
#include <iostream>
#include <fstream>

enum Cheat_Actions {
  DOWNLOAD_CHEATS = 0,
  RELOAD_CHEATS,
};

extern bool is_testkit, cheats_shortcut_activate;
pid_t find_pid(const char *name, bool needle, bool for_bigapp,
               bool need_eboot = false);
static void shellui_log(const char *fmt, ...) {
  char buffer[DAEMON_BUFF_MAX];
  va_list args;
  va_start(args, fmt);
  int len = vsnprintf(buffer, DAEMON_BUFF_MAX, fmt, args);
  va_end(args);

  if (len >= 0 && len < DAEMON_BUFF_MAX - 2) {
    // If vsnprintf succeeded and there's space for \n and null terminator
    buffer[len] = '\n';
    buffer[len + 1] = '\0';
  } else {
    // If the buffer was truncated, ensure it ends with \n and null terminator
    buffer[DAEMON_BUFF_MAX - 2] = '\n';
    buffer[DAEMON_BUFF_MAX - 1] = '\0';
  }
  if (!is_testkit)
	  klog_printf(buffer);
  else
    printf("%s", buffer);
}

static int MainDaemonSocket = -1;
static int UtilDaemonSocket = -1;
class IPC_Client {
private:
public:
  bool util_daemon = false;

  // Socket Management
  int OpenConnection(const char *path) {
    sockaddr_un server;
    int soc = socket(AF_UNIX, SOCK_STREAM, 0);
    if (soc == -1) {
      shellui_log("Failed to create socket");
      return -1;
    }
    server.sun_family = AF_UNIX;
    strncpy(server.sun_path, path, sizeof(server.sun_path) - 1);
    if (connect(soc, (struct sockaddr *)&server, SUN_LEN(&server)) == -1) {
      close(soc);
      shellui_log("Failed to connect to socket");
      return -1;
    }
    return soc;
  }

  // IPC Functions
  bool IPCOpenConnection() {
    util_daemon ? UtilDaemonSocket = OpenConnection(UTIL_IPC_SOC)
                : MainDaemonSocket = OpenConnection(CRIT_IPC_SOC);
    return util_daemon ? UtilDaemonSocket >= 0 : MainDaemonSocket >= 0;
  }

  bool IPCOpenIfNotConnected() {
    if (util_daemon ? UtilDaemonSocket >= 0 : MainDaemonSocket >= 0) {
      return true;
    }
    return IPCOpenConnection();
  }
  int IPCReceiveData(IPCMessage &msg, std::string &ipc_msg) {

    // erase the old message
    bzero(msg.msg, sizeof(msg.msg));

    int timeout_ms = 25 * 1000;
    // Set receive timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int socket_fd = util_daemon ? UtilDaemonSocket : MainDaemonSocket;

    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return -1; // Error setting timeout
    }

    shellui_log("Waiting for daemon response...");
    int ret = recv(socket_fd, reinterpret_cast<void*>(&msg), sizeof(msg), MSG_NOSIGNAL);
    if (ret < 0) {
      shellui_log("recv failed with: 0X%X", ret);
      return ret;
    }
    shellui_log("Daemon returned: %i", msg.error);

    if (msg.error != 0) {
      shellui_log("Daemon returned an error: %i (strerror: %s)", msg.error, strerror(errno));
      return msg.error;
    }

    if (strlen(msg.msg) <= 2) {
      shellui_log("Daemon message is empty");
      return -1;
    }

    nlohmann::json j;
    // parse the json from the payload buffer
    try {
      j = nlohmann::json::parse(msg.msg);
    } catch (
        const std::exception &e) { // so if it can parse it doesnt crash shellui
      shellui_log("Failed to parse json: %s", e.what());
      return -1;
    }

    if (!j.contains("var")) {
      shellui_log("Daemon message does not contain the return obj");
      return -1;
    }

    ipc_msg = j["var"];
    shellui_log("Daemon IPC return obj: %s", ipc_msg.c_str());

    return msg.error;
  }

  int IPCSendData(const IPCMessage &msg) {
    int ret =
        send(util_daemon ? UtilDaemonSocket : MainDaemonSocket,
             reinterpret_cast<const void *>(&msg), sizeof(msg), MSG_NOSIGNAL);
    if (ret < 0) {
      shellui_log("IPCSendData failed with: %s", strerror(errno));
    }
    shellui_log("IPCSendData sent %i bytes", ret);
    return ret;
  }

  int IPCCloseConnection() {
    if (util_daemon ? UtilDaemonSocket < 0 : MainDaemonSocket < 0) {
      return -1;
    }

    close(util_daemon ? UtilDaemonSocket : MainDaemonSocket);
    util_daemon ? UtilDaemonSocket = -1 : MainDaemonSocket = -1;
    return 0;
  }

  bool IPCSendCommand(DaemonCommands cmd, std::string &ipc_msg1,
                      std::string ipc_msg2 = "") {

    int ret = -1;
    std::string json;
    nlohmann::json j;
    
    #if SHELL_DEBUG==1 
    shellui_log("Sending command to daemon: 0x%X", cmd);
    #endif

    IPCMessage msg;
    msg.cmd = cmd;
    if (cmd == BREW_REMOUNT_FOLDER) {
      j["mount_src"] = ipc_msg1;
      j["mount_dest"] = ipc_msg2;
      json = j.dump();
    }
    else if (ipc_msg2.empty()) {
      if (cmd == BREW_DAEMON_PID || cmd == BREW_UTIL_DAEMON_PID) {
        json = "{\"pid\": 0 }";
      } else {
        json = "{\"msg_1\": 0}";
      }
    } else {
      json = ipc_msg2;
    }

    // shellui_log("Json: %s", json.c_str());

    if (!IPCOpenIfNotConnected()) {
      shellui_log("Failed to open connection to daemon");
      return false;
    }

    IPC_Ret error = IPC_Ret::INVALID;
    snprintf(msg.msg, sizeof(msg.msg), "%s", json.c_str());

    if ((ret = IPCSendData(msg)) < 0) {
      shellui_log("Failed to send message to daemon");
      notify("Failed to send message to daemon");
      IPCCloseConnection();
      return false;
    }

    if(cmd == BREW_KILL_DAEMON) {
      shellui_log("Daemon kill cmd sent");
      return true;
    }

    // Get message back from daemon
    error = (IPC_Ret)IPCReceiveData(msg, ipc_msg1);
    if (error == IPC_Ret::NO_ERROR) {
      shellui_log("[ItemzDaemon] Daemon returned NO ERROR");
      return true;
    } else {
      shellui_log("[ItemzDaemon] Daemon returned an ERROR");
      // notify("Daemon returned an ERROR");
      return false;
    }

    return false;
  }
  // Deleted copy constructor and assignment operator to ensure only one
  // instance
  IPC_Client &operator=(const IPC_Client &) = delete;

  // Static method to access the instance
  static IPC_Client &getInstance(bool is_util_daemon) {
    static IPC_Client
        instance; // Lazy-loaded instance, guaranteed to be destroyed
    instance.util_daemon = is_util_daemon;
    return instance;
  }

  int GetDaemonPid() {
    std::string ipc_msg;
    if (!IPCSendCommand(util_daemon ? BREW_UTIL_DAEMON_PID : BREW_DAEMON_PID,
                        ipc_msg)) {
      shellui_log("Failed to get daemon pid");
      return -1;
    } else {
      shellui_log("Daemon pid: %s", ipc_msg.c_str());
      return atoi(ipc_msg.c_str());
    }

    return -1;
  }

  IPC_Ret ToggleSetting(DaemonCommands cmd, bool turn_on) {
    std::string ipc_msg;
    std::string json = turn_on ? "{\"toggle\": 1}" : "{\"toggle\": 0}";
    if (!IPCSendCommand(cmd, ipc_msg, json)) {
      shellui_log("Failed to toggle setting 0x%X (%d)", cmd, cmd);
      return IPC_Ret::OPERATION_FAILED;
    }

    shellui_log("Setting 0x%X (%d) toggled", cmd, cmd);
    return IPC_Ret::NO_ERROR;
  }

  IPC_Ret DownloadTheStore() {
    if (util_daemon) {
      shellui_log("This IPC command is ONLY in the main daemon");
      return IPC_Ret::INVALID;
    }
    std::string ipc_msg;
    if (!IPCSendCommand(BREW_INSTALL_THE_STORE, ipc_msg)) {
      shellui_log("Failed to BREW_INSTALL_THE_STORE");
      return IPC_Ret::OPERATION_FAILED;
    }

    return IPC_Ret::NO_ERROR;
  }

  IPC_Ret DownloadKstuff() {
      std::string ipc_msg;
      if (!IPCSendCommand(BREW_UTIL_DOWNLOAD_KSTUFF, ipc_msg)) {
          shellui_log("Failed to BREW_UTIL_DOWNLOAD_KSTUFF");
          return IPC_Ret::OPERATION_FAILED;
      }

      return IPC_Ret::NO_ERROR;
  }

  void KillDaemon() {
    std::string ipc_msg;
    IPCSendCommand(BREW_KILL_DAEMON, ipc_msg);
  }

  void ForceKillPID(int pid) {
    if(util_daemon) {
      shellui_log("This IPC command is NOT in the util daemon");
      return;
    }
    std::string ipc_msg;
    std::string json = "{\"pid\": " + std::to_string(pid) + "}";
    IPCSendCommand(BREW_FORCE_KILL_PID, ipc_msg, json);
  }

  //
  IPC_Ret CopyFile(std::string src, std::string dest) {
    if (util_daemon) {
      shellui_log("This IPC command is NOT in the util daemon");
      return IPC_Ret::INVALID;
    }
    std::string ipc_msg;
    std::string json = "{\"path\": \"" + src + "\", \"dest\": \"" + dest + "\"}";
    if (!IPCSendCommand(BREW_COPY_FILE, ipc_msg, json)) {
      shellui_log("Failed to copy file");
      return IPC_Ret::OPERATION_FAILED;
    }

    return IPC_Ret::NO_ERROR;
  }

  IPC_Ret LaunchPlugin(std::string plugin_path, std::string tid) {
    if (!util_daemon) {
      shellui_log("This IPC command is NOT in the main daemon");
      return IPC_Ret::INVALID;
    }
    std::string ipc_msg;
    std::string json = "{\"plugin_path\": \"" + plugin_path +
                       "\", \"title_id\": \"" + tid + "\"}";
    if (!IPCSendCommand(BREW_UTIL_LAUNCH_PLUGIN, ipc_msg, json)) {
      shellui_log("Failed to launch plugin");
      return IPC_Ret::OPERATION_FAILED;
    }

    return IPC_Ret::NO_ERROR;
  }

  bool GameVerFromTid(std::string tid, std::string &out_ver) {
    if (!util_daemon) {
      shellui_log("This IPC command is NOT in the main daemon");
      return false;
    }

    std::string json = "{\"tid\": \"" + tid + "\"}";
    if (!IPCSendCommand(BREW_UTIL_GET_GAME_VER, out_ver, json)) {
      shellui_log("Failed to get game name from tid");
      return false;
    }
    return true;
  }

  bool Remount(const char* src, const char* dest) {
    if (util_daemon) {
        shellui_log("This IPC command is NOT in the util daemon");
        return false;
    }
    // send jailbreak IPC command
    std::string in = src;
    if (!IPCSendCommand(BREW_REMOUNT_FOLDER, in, dest)) {
        shellui_log("Failed to remount %s to %s", src, dest);
        return false;
    }

    return true;
}

  bool GetGameCheats(const std::string &tid, const std::string &ver,
                     std::string &cheats) {
    if (!util_daemon) {
      shellui_log("This IPC command is NOT in the main daemon");
      return false;
    }

    std::string json =
        R"({"tid": ")" + tid + R"(", "version": ")" + ver + R"("}")";
    if (!IPCSendCommand(BREW_UTIL_GET_GAME_CHEAT, cheats, json)) {
      shellui_log("Failed to get cheats for %s", tid.c_str());
      return false;
    }

    return true;
  }

  bool ToggleGameCheat(int pid, const std::string &tid, int cheat_index,
                       std::string &cheat_enabled) {
    if (!util_daemon) {
      shellui_log("This IPC command is NOT in the main daemon");
      return false;
    }

    std::string ipc_msg;
    std::string json = R"({"tid": ")" + tid + R"(", "cheat_id" : )" +
                       std::to_string(cheat_index) + R"(, "pid" : )" +
                       std::to_string(pid) + "}";

    if (!IPCSendCommand(BREW_UTIL_TOGGLE_CHEAT, cheat_enabled, json)) {
      shellui_log("Failed to enable cheats for %s", tid.c_str());
      return false;
    }

    return true;
  }

  void SendRestModeAction() {
    if (!util_daemon) {
      shellui_log("This IPC command is NOT in the main daemon");
      return;
    }
    std::string ipc_msg;
    std::string json;
    if (!IPCSendCommand(BREW_UTIL_SHELLUI_ON_STANDBY, ipc_msg, json)) {
      shellui_log("Failed to launch plugin");
    }
  }

  bool IsTestKit() {
    if (util_daemon) {
      shellui_log("This IPC command is NOT in the util daemon");
      return false;
    }
    std::string ipc_msg;
    if (!IPCSendCommand(BREW_TESTKIT_CHECK, ipc_msg)) {
      return false;
    }
    return true;
  }

  void Reload_Daemon_Settings() {
    std::string ipc_msg;
    if (!IPCSendCommand(BREW_RELOAD_SETTINGS, ipc_msg)) {
      shellui_log("Failed to reload daemon settings");
    } else {
      shellui_log("Daemon settings reloaded successfully");
    }
  }

  bool Launch_Elfldr() {
    if (!util_daemon) {
      shellui_log("This IPC command is NOT in the main daemon");
      return false;
    }
    std::string ipc_msg;
    if (!IPCSendCommand(BREW_UTIL_LAUNCH_ELFLDR, ipc_msg)) {
      return false;
    }
    return true;
  }

  bool Toggle_ps5debug() {
    if (util_daemon) {
      shellui_log("This IPC command is NOT in the util daemon");
      return false;
    }
    std::string ipc_msg;
    if (!IPCSendCommand(BREW_TOGGLE_PS5DEBUG, ipc_msg)) {
      return false;
    }
    return true;
  }

  bool Cheats_Action(Cheat_Actions act, int repo) {
    DaemonCommands cmd;
    if (!util_daemon) {
      shellui_log("This IPC command is NOT in the main daemon");
      return false;
    }
    switch (act) {
    case DOWNLOAD_CHEATS:
      cmd = BREW_UTIL_DOWNLOAD_CHEATS;
      break;
    case RELOAD_CHEATS:
      cmd = BREW_UTIL_RELOAD_CHEATS;
      break;
    default:
      shellui_log("Invalid action");
      return false;
    
    }
    std::string ipc_msg;
    std::string json = "{\"repo\": " + std::to_string(repo) + "}";
    if (!IPCSendCommand(cmd, ipc_msg, json)) {
      return false;
    }
    return true;
  }

  bool Set_Fan_Threshold(int temp, bool enabled) {
    if (util_daemon) {
        shellui_log("This IPC command is NOT in the util daemon");
        return false;
    }
    std::string ipc_msg;
    //and enabled
    std::string json = "{\"speed\": " + std::to_string(temp) + ", \"enabled\": " + std::to_string(enabled) + "}";
    if (!IPCSendCommand(BREW_ADJUST_FAN_SPEED, ipc_msg, json)) {
        shellui_log("Failed to adjust fan speed");
        return false;
    }
    return true;
  }

  bool ToggleDPI(bool turn_on, bool is_v2) {
    if (!util_daemon) {
        shellui_log("This IPC command is NOT in the main daemon");
        return false;
    }

    std::string ipc_msg;
    std::string json = "{\"toggle\": " + std::to_string(turn_on) + 
                       ", \"is_v2\": " + std::to_string(is_v2) + "}";

    if (!IPCSendCommand(BREW_UTIL_TOGGLE_DPI, ipc_msg, json)) {
        shellui_log("Failed to toggle DPI");
        return false;
    }

    return true;
}
void Launch_Dumper() {
    if (util_daemon) {
        shellui_log("This IPC command is in the main daemon");
        return;
    }
    std::string ipc_msg;
    if (!IPCSendCommand(BREW_LAUNCH_DUMPER, ipc_msg)) {
        shellui_log("Failed to launch dumper");
    }
  }

  static void generate_default_games_xml(std::string &xml_buffer,  bool game_shortcut_activated) {
  std::string list_id = game_shortcut_activated ? "id_debug_settings" : "id_ps5_backups";

  xml_buffer =  "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
      "<system_settings version=\"1.0\" plugin=\"debug_settings_plugin\">\n"
      "\n";

  xml_buffer += "<setting_list id=\"" + list_id + "\" title=\"(Beta) PS5 webMAN Games (ERROR)\">\n";
  xml_buffer += "</setting_list>\n</system_settings> ";
}

bool GetGamesList(bool cheats_activated_shortcut, std::string &games_list) {
    if (!util_daemon) {
        shellui_log("This IPC command is in the util daemon");
        generate_default_games_xml(games_list, cheats_activated_shortcut);
        return false;
    }

    std::string json = "{\"shortcut\": " + std::to_string(cheats_activated_shortcut) + "}";
    if (!IPCSendCommand(BREW_UTIL_GET_GAMES_LIST, games_list, json)) {
        shellui_log("Failed to get games list");
        generate_default_games_xml(games_list, cheats_activated_shortcut);
        return false;
    }


        std::ifstream file("/user/data/etaHEN/games_list.xml");
        if (file) {
            std::string content((std::istreambuf_iterator<char>(file)),
                                 std::istreambuf_iterator<char>());
            games_list = content;
            file.close();
            return true;
        } else {
            shellui_log("Failed to open games list file: %s", games_list.c_str());
            return false;
        }
    

    shellui_log("Games list: %s", games_list.c_str());
    return true;
  }

  bool Launch_Game_By_ID(const std::string& button_id) {
      if (!util_daemon) {
          shellui_log("This IPC command is in the util daemon");
          return false;
      }
      std::string ipc_msg;
      std::string json = "{\"button_id\": \"" + button_id + "\"}";
      if (!IPCSendCommand(BREW_UTIL_LAUNCH_GAME_BY_BUTTON_ID, ipc_msg, json)) {
          shellui_log("Failed to launch game by button id: %s", button_id.c_str());
          return false;
      }
      return true;
  }
}; // namespace IPC

#endif // IPC_HEADER_H
