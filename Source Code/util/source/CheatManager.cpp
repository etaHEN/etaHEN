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

#include "../include/CheatManager.hpp"

CheatCache cache;
static GameCheat *currentGameCheat = nullptr;
bool monitorGameRunning = false;
pthread_t pthreadMonitor;
extern "C" void notify(bool show_watermark, const char *text, ...);


//
// This function is used to fix the mc4 decrypted xml file
//
void replaceAllOccurrences(std::string &source,
                           const std::vector<std::string> &targets,
                           const std::vector<std::string> &replacements) {
  for (size_t i = 0; i < targets.size(); ++i) {
    size_t pos = 0;
    while ((pos = source.find(targets[i], pos)) != std::string::npos) {
      source.replace(pos, targets[i].length(), replacements[i]);
      pos += replacements[i].length(); // Move past the replacement
    }
  }
}

void *CheatManager::MonitorOpenGame(CheatMetadata *cheatMeta) {

  while (monitorGameRunning) {
    if (sceSystemServiceGetAppIdOfRunningBigApp() < 0) {
      break;
    }

    sleep(1);
  }

  auto cleanParsed = [&](std::unordered_map<std::string, CheatParsed> &x) {
    for (auto &pair : x) {
      if (pair.second.parsed) {
        pair.second.parsed = nullptr;
      }
    }
  };

  if (currentGameCheat != nullptr) {
    delete currentGameCheat;
    currentGameCheat = nullptr;
  }
  //
  // Clean the parsed and the current cheat pointers
  //
  cleanParsed(cheatMeta->json);
  cleanParsed(cheatMeta->mc4);
  cleanParsed(cheatMeta->shn);

  monitorGameRunning = false;

  return nullptr;
}
bool ParseTXTEntry(char *line, char *title_id, char *version, char *game_name,
                   char *filename) {
  //
  // Example line => CUSA05786_01.04_kingdom1.elf.json=KINGDOM HEARTS -
  // HD 1.5+2.5 ReMIX -
  //

  // Initialize title_id and version to empty strings for safe logging
  title_id[0] = '\0';
  version[0] = '\0';

  if (strlen(line) < 20) {
    //
    // 20 bytes is the mininum that a entry can have
    //
    etaHEN_log("ParseTXTEntry: %s %s Invalid line length (%zu), skipping...",
              title_id, version, strlen(line));
    return false;
  }

  int n = sscanf(line, "%[^=]=%[^\n]", filename, game_name);

  if (n != 2) {
    //
    // If no expected matches
    //
    etaHEN_log("ParseTXTEntry: sscanf Invalid line format: '%s', skipping...",
               line);
    return false;
  }

  // Look for any of the separators: '_', '-', or space
  char *version_start = NULL;
  char *underscore_sep = strchr(filename, '_');
  char *dash_sep = strchr(filename, '-');
  char *space_sep = strchr(filename, ' ');

  // Find which separator comes first (if any)
  if (underscore_sep != NULL) {
    version_start = underscore_sep;
  }

  if (dash_sep != NULL && (version_start == NULL || dash_sep < version_start)) {
    version_start = dash_sep;
  }

  if (space_sep != NULL &&
      (version_start == NULL || space_sep < version_start)) {
    version_start = space_sep;
  }

  // If no separator found, return false
  if (version_start == NULL) {
    etaHEN_log(
        "ParseTXTEntry: No separator found in filename '%s', skipping...",
        filename);
    return false;
  }

  // Copy the title ID
  size_t title_id_len = version_start - filename;
  if (title_id_len > 0) {
    strncpy(title_id, filename, title_id_len);
    title_id[title_id_len] = '\0';
  } else {
    etaHEN_log("ParseTXTEntry: Invalid title ID length in '%s', skipping...",
               filename);
    return false;
  }

  version_start++; // Skip the separator

  // Find the first period after the version start
  char *version_end = strchr(version_start, '.');
  if (version_end == NULL) {
    etaHEN_log("TitleID %s: No version end found in '%s', skipping...",
               title_id, filename);
    return false;
  }

  // Find the next period if it exists (for PS5 format)
  char *ps5_version_fmt = strchr(version_end + 1, '.');

  // Check if this is a PS5 format (has a digit 3 chars after second period)
  bool is_ps5_format = false;
  if (ps5_version_fmt != NULL &&
      ps5_version_fmt + 3 < filename + strlen(filename) &&
      (ps5_version_fmt[3] >= '0' && ps5_version_fmt[3] <= '9')) {
    is_ps5_format = true;
   // etaHEN_log("TitleID %s: Detected PS5 version format", title_id);
  } else {
    ps5_version_fmt = NULL;
  }

  // Find the next underscore after version
  char *underscore_start = NULL;
  if (is_ps5_format) {
    underscore_start = strchr(ps5_version_fmt, '_');
  } else {
    underscore_start = strchr(version_end, '_');
  }

  // Calculate version length
  size_t version_len;
  if (underscore_start != NULL) {
    version_len = underscore_start - version_start;
  } else {
    // Find the last period which should mark the start of any file extension
    char *last_dot = strrchr(version_end, '.');
    if (last_dot != NULL) {
      version_len = last_dot - version_start;
    } else {
      version_len = strlen(version_start);
    }
  }

  // Copy the version string
  if (version_len < MAX_CHEAT_VERSION_LEN) {
    strncpy(version, version_start, version_len);
    version[version_len] = '\0';
  } else {
    etaHEN_log("TitleID %s: Version string too long, truncating", title_id);
    strncpy(version, version_start, MAX_CHEAT_VERSION_LEN - 1);
    version[MAX_CHEAT_VERSION_LEN - 1] = '\0';
  }

 // etaHEN_log("TitleID %s Version %s: Successfully parsed entry for '%s'",
  //           title_id, version, game_name);
  return true;
}

void ParseFile(CheatExtType extensionType) {
  CheatMetadata jsonMetadata;
  char cheat_file_path[MAX_CHEAT_FILEPATH_LEN];
  char filename[MAX_CHEAT_NAME];
  char title_id[MAX_CHEAT_TITLE_ID_LEN];
  char version[MAX_CHEAT_VERSION_LEN];
  char game_name[MAX_CHEAT_GAMENAME_LEN];
  std::string file_extension, path;

  if (extensionType == JSON_CHEAT) {
    file_extension = "json";
    path = JSON_CHEATS_LIST;
  } else if (extensionType == MC4_CHEAT) {
    file_extension = "mc4";
    path = MC4_CHEATS_LIST;
  } else if (extensionType == SHN_CHEAT) {
    file_extension = "shn";
    path = SHN_CHEATS_LIST;
  } else {
    etaHEN_log("Invalid cheat filetype!");
    return;
  }

  std::ifstream stream(path);
  if (stream.is_open()) {
    int line_num = 0;
    for (std::string line; std::getline(stream, line);) {
      line_num++;
      bzero(cheat_file_path, MAX_CHEAT_FILEPATH_LEN);
      bzero(title_id, MAX_CHEAT_TITLE_ID_LEN);
      bzero(version, MAX_CHEAT_VERSION_LEN);
      bzero(game_name, MAX_CHEAT_GAMENAME_LEN);
      bzero(filename, MAX_CHEAT_NAME);

      // etaHEN_log("Parsing line %d", line_num);

      if (!ParseTXTEntry((char *)line.c_str(), title_id, version, game_name,
                         filename)) {
        etaHEN_log("Invalid json line %d, skipping...", line_num);
        continue;
      }

      if (!strlen(title_id) || !strlen(version) || !strlen(game_name) ||
          !strlen(filename)) {
        etaHEN_log("Invalid json line %d, skipping, wrong entry values!...",
                   line_num);
        continue;
      }

      snprintf(cheat_file_path, MAX_CHEAT_FILEPATH_LEN, "%s/%s/%s",
               CHEATS_DIRECTORY, file_extension.c_str(), filename);

      // etaHEN_log("Cheat file path: %s", cheat_file_path);
      // etaHEN_log("Title ID: %s %s", title_id, version);

      std::string tid = std::string(title_id);
      std::string game_name_str = std::string(game_name);
      std::string version_str = std::string(version);
      std::string cheat_file_path_str = std::string(cheat_file_path);

      //
      // Remove the .xml from mc4 cheat files
      //
      if (cheat_file_path_str.rfind(".mc4.xml") != std::string::npos) {
        cheat_file_path_str.resize(cheat_file_path_str.size() - 4);
      }

      auto it = cache.find(tid);
      CheatParsed parsedCheat;
      parsedCheat.parsed = nullptr;

      parsedCheat.filepaths.push_back(cheat_file_path_str);

      if (it != cache.end()) {
        CheatMetadata *meta = &it->second;
        std::unordered_map<std::string, CheatParsed>::iterator version_it;
        std::unordered_map<std::string, CheatParsed> *extension;

        switch (extensionType) {
        case JSON_CHEAT:
          version_it = meta->json.find(version_str);
          extension = &meta->json;
          break;
        case MC4_CHEAT:
          version_it = meta->mc4.find(version_str);
          extension = &meta->mc4;
          break;
        case SHN_CHEAT:
          version_it = meta->shn.find(version_str);
          extension = &meta->shn;
          break;
        default:
          etaHEN_log("Invalid cheat extension type!");
          return;
        }

        if (version_it == extension->end()) {
          //
          // Insert new cheat for a different version;
          //
          // etaHEN_log("New cheat version for %s\n",
          // cheat_file_path_str.c_str());
          extension->insert(std::make_pair(version_str, parsedCheat));
        } else {
          // etaHEN_log("New etahen cheatfile for %s version %s\n",
          // cheat_file_path_str.c_str(), version);
          version_it->second.filepaths.push_back(cheat_file_path_str);
        }

        continue;
      }
      //
      // New cache entry
      //
      CheatMetadata meta;
      meta.title_id = tid;
      meta.game_name = game_name_str;

      switch (extensionType) {
      case JSON_CHEAT:
        meta.json.insert(std::make_pair(version_str, parsedCheat));
        break;
      case MC4_CHEAT:
        meta.mc4.insert(std::make_pair(version_str, parsedCheat));
        break;
      case SHN_CHEAT:
        meta.shn.insert(std::make_pair(version_str, parsedCheat));
        break;
      default:
        etaHEN_log("Invalid cheat extension type!");
        return;
      }

      cache.insert(std::make_pair(tid, meta));
    }
  }

  // etaHEN_log("Finished processing %s", path.c_str());
}

//
// Parse the json.txt, m4.txt and shn.txt file to build the lookup table
//
void *MakeInitialCheatCache(void *) {
  cache.clear();
  ParseFile(JSON_CHEAT);
  ParseFile(MC4_CHEAT);
  ParseFile(SHN_CHEAT);

  return NULL;
}

//
// Search the cheat file file inside the cheat directory
//
GameCheat *CheatManager::GetGameCheat(const std::string &name,
                                      const std::string &version) {
  if (cache.empty())
    MakeInitialCheatCache(NULL);

  auto it = cache.find(name);

  if (it == cache.end()) {
    etaHEN_log("No cheat exists for %s", name.c_str());
    return nullptr;
  }

  CheatMetadata *meta = &it->second;
  GameCheat *cheat = nullptr;
  // GameCheat* tmp = nullptr;

  if (meta->json.size()) {
    cheat = LoadCheat(meta, version, JSON_CHEAT, cheat);
    // if (tmp) cheat = tmp;
  }

  if (meta->mc4.size()) {
    cheat = LoadCheat(meta, version, MC4_CHEAT, cheat);
    // if (tmp) cheat = tmp;
  }

  if (meta->shn.size()) {
    cheat = LoadCheat(meta, version, SHN_CHEAT, cheat);
    // if (tmp) cheat = tmp;
  }

  if (cheat) {
    if (currentGameCheat != nullptr && currentGameCheat != cheat) {
      //
      // The game has changed, update the gameCheat attributes
      //
      for (auto &cheat : currentGameCheat->cheats) {
        cheat.enabled = false; // Set enabled to false for each cheat
      }
    }

    if (!currentGameCheat) {
      //
      // Launch the monitor thread
      //
      if (monitorGameRunning) {
        monitorGameRunning = false;
        void *ret;
        pthread_join(pthreadMonitor, &ret);
      }

      //etaHEN_log("Starting monitor thread...");
      monitorGameRunning = true;
      pthread_create(&pthreadMonitor, NULL, (void *(*)(void *))MonitorOpenGame,
                     meta);
      pthread_detach(pthreadMonitor);
    }

    etaHEN_log("Loaded cheat for %s", cheat->name.c_str());
  }

  currentGameCheat = cheat;

  return cheat;
}

//
// Search on the local folder the current game
//
GameCheat *CheatManager::LoadCheat(CheatMetadata *meta,
                                   const std::string &version,
                                   CheatExtType type, GameCheat *cheat) {
  GameCheat *gameCheats = nullptr;

  if (cheat) {
    gameCheats = cheat;
  }
  //
  // Starting loading cheats
  //
  std::unordered_map<std::string, CheatParsed>::iterator it;
  std::unordered_map<std::string, CheatParsed> *extIterator;

  switch (type) {
  case JSON_CHEAT:
    it = meta->json.find(version);
    extIterator = &meta->json;
    break;
  case MC4_CHEAT:
    it = meta->mc4.find(version);
    extIterator = &meta->mc4;
    break;
  case SHN_CHEAT:
    it = meta->shn.find(version);
    extIterator = &meta->shn;
    break;
  }

  if (it != extIterator->end()) {
    if (it->second.parsed) {
      gameCheats = it->second.parsed;
    } else {
      // Load json cheats
      // Version -> VersionPath
      CheatParsed *cheatParsed = &it->second;
      if (cheatParsed->filepaths.size() == 1) {
        //
        // Best case scenario
        //
        switch (type) {
        case JSON_CHEAT:
          gameCheats = CheatManagerFormats::ParseJSONCheat(
              cheatParsed->filepaths[0], gameCheats);
          break;
        case MC4_CHEAT:
          gameCheats = CheatManagerFormats::ParseMC4Cheat(
              cheatParsed->filepaths[0], gameCheats);
          break;
        case SHN_CHEAT:
          gameCheats = CheatManagerFormats::ParseSHNCheat(
              cheatParsed->filepaths[0], gameCheats);
          break;
        }

      } else {
        GameCheat *(*Parse)(const std::string &, GameCheat *);
        switch (type) {
        case JSON_CHEAT:
          Parse = CheatManagerFormats::ParseJSONCheat;
          break;
        case MC4_CHEAT:
          Parse = CheatManagerFormats::ParseMC4Cheat;
          break;
        case SHN_CHEAT:
          Parse = CheatManagerFormats::ParseSHNCheat;
          break;
        }

        //
        // Parse all json and concat it IF is from the SAME process
        //
        for (const auto &filepath : cheatParsed->filepaths) {
          gameCheats = Parse(filepath, gameCheats);
        }
      }

      cheatParsed->parsed = gameCheats;
    }
  }

  return gameCheats;
}

typedef struct
{
    uint64_t pad0;
    char version_str[0x1C];
    uint32_t version;
    uint64_t pad1;
} OrbisKernelSwVersion;

extern "C" {
    int sceKernelGetProsperoSystemSwVersion(OrbisKernelSwVersion *version);
}

//
// Enable/Disable cheat based on the current cheat state
//
bool CheatManager::ToggleCheat(int pid, const std::string &title_id,
                               int cheat_index, std::string &cheat_name) {
  if (currentGameCheat == nullptr) {
    return false;
  }

  OrbisKernelSwVersion sys_ver;
  sceKernelGetProsperoSystemSwVersion(&sys_ver);
  int fw = (sys_ver.version >> 16);

  if (cheat_index < 0 || cheat_index > currentGameCheat->cheats.size()) {
    etaHEN_log("Cheat index %d is 0 or greater than the size", cheat_index);
    return false;
  }
  bool status = true;

  CheatInfo &cheat = currentGameCheat->cheats[cheat_index];
  etaHEN_log("Toggling cheat %s", cheat.name.c_str());
  module_info_t *target_mod = get_module_handle(pid, cheat.module_name.c_str());
  etaHEN_log("Target module name: %s", cheat.module_name.c_str());
  if (!target_mod) {
    etaHEN_log("CheatManager::ToggleCheat: Unable to find %s of cheat %s",
               cheat.module_name.c_str(), title_id.c_str());
    return false;
  }

  bool enabled = false;
  cheat_name = cheat.name;
  uint64_t baseAddress = target_mod->sections[0].vaddr;
  //
  // Check if is a PS2 game
  //
  module_info_t *ps2Lib = get_module_handle(pid, "libScePs2EmuMenuDialog.sprx");
  bool isPS2 = false;

  if (ps2Lib) {
    isPS2 = true;
    free(ps2Lib);
  }

  int pt_ret = 0;
  if (fw >= 0x840) {
      if (pt_attach_proc(pid) < 0) {
          etaHEN_log("Unable to ptrace into %d, aborting cheat...", pid);
          return false;
      }
  }

  //
  // Used for Fixing master code references
  //
  if (currentGameCheat->masterCodeId < 0 &&
      // TODO: this check gotta be done in a clever way, maybe associating each
      // MC depentando to a MC ID
      (cheat.name.rfind("Master Code") != std::string::npos ||
       cheat.name.rfind("Mastercode") != std::string::npos)) {
    currentGameCheat->masterCodeId = cheat_index;
  }
  //
  // Fix issues with cheats dependent on the master code (MC). If the master
  // code is enabled, we may encounter invalid memory that we previously
  // handled. Some MC-dependent cheats use a relative offset from a "section"
  // that may not be available. To resolve this, we need to identify at runtime
  // where the MC-dependent cheat is referencing within the MC code, and then
  // update the offset field accordingly.
  //
  else if (currentGameCheat->masterCodeId >= 0 &&
           cheat.name.rfind("MC") != std::string::npos &&
           cheat.mods.size() == 1 && cheat.mods[0].section != 0) {
    //
    // Require Master code to be enabled
    //
    // if (currentGameCheat->masterCodeId < 0)
    // {
    //     etaHEN_log("No master code enabled for cheat!");
    //     return false;
    // }
    //
    // Check and fix the offsets
    //
    etaHEN_log("Fixing Master Code dependent cheat");
    CheatInfo &masterCode =
        currentGameCheat->cheats[currentGameCheat->masterCodeId];
    CheatMemory &mcPatch = masterCode.mods[0];
    CheatMemory &mcDepentent = cheat.mods[0];
    //
    // Search inside the mcPatch where the current cheat modification starts
    //

    uint64_t mcAddress = mcPatch.absolute ? mcPatch.Offset : baseAddress + mcPatch.Offset;  // 09/10/2025 xZenithy

    std::vector<uint8_t> vPatchedCode(mcPatch.On.size());
    //
    // Copy cheat master code
    //
    if (fw >= 0x840) {
        etaHEN_log("Master code address: %#02lx", mcAddress);
        kernel_mprotect(pid, mcAddress, mcPatch.On.size(), PROT_READ | PROT_WRITE | PROT_EXEC);
        etaHEN_log("Copying master code...");
        pt_ret = pt_copyout(pid, mcAddress, vPatchedCode.data(), mcPatch.On.size());
        etaHEN_log("Master code copied... errno %d %d", pt_ret, pt_errno(pid));
    }
    else {
        mdbg_copyout(pid, mcAddress, vPatchedCode.data(), mcPatch.On.size());
    }
    //
    // Search the cheat inside the Master Code, the "Off" field holds the
    // original MC code
    //
    auto it = std::search(vPatchedCode.begin(), vPatchedCode.end(),
                          mcDepentent.Off.begin(), mcDepentent.Off.end());

    if (it != vPatchedCode.end()) {
      int index = std::distance(vPatchedCode.begin(), it);
      //
      // Update offsets
      //
      mcDepentent.Offset = mcPatch.Offset + index;
    } else {
      //
      // Unable to find it, this means that the Off toggle from the MC dependent
      // cheat dont set to same value all that remains is a shot in the dark
      // where we should update the offset by extract the less significant byte
      // from it
      //
      mcDepentent.Offset =
          ((mcPatch.Offset >> 8) << 8) | (mcDepentent.Offset & 0xff);
    }
  }

  for (auto &mod : cheat.mods) {
    ssize_t patch_size = mod.On.size();
    //
    // If the address is higher
    //
    uint64_t addr = (isPS2 || mod.absolute) ? mod.Offset : baseAddress + mod.Offset;  // Absolute address controled by bolean variables // 09/10/2025 xZenithy

    etaHEN_log("Offset: %#02lx", mod.Offset);
    etaHEN_log("Addr: %#02lx", addr);
    // etaHEN_log("Base address: %#02lx %s\n", baseAddress,
    // target_mod->filename);
    bool fixCodeCave = false;
    // bool try_fix_asrl = false;
    if (cheat.enabled) {
	  etaHEN_log("Disabling cheat...");
      if (fw >= 0x840) {
          kernel_mprotect(pid, addr, patch_size, PROT_READ | PROT_WRITE | PROT_EXEC);
          etaHEN_log("Restoring original data...");
          pt_ret = pt_copyin(pid, mod.Off.data(), addr, mod.Off.size());
      }
      else {
          mdbg_copyin(pid, mod.Off.data(), addr, mod.Off.size());
      }
      etaHEN_log("Cheat %s disabled, errno %d %d", cheat.name.c_str(), pt_ret, pt_errno(pid));
      enabled = false;
    } else {
      uint8_t *patch_data = mod.On.data();
      uint8_t *dump_on = new uint8_t[patch_size];
      bzero(dump_on, patch_size);

    // fix_aslr:
    //     if (try_fix_asrl)
    //     {
    //         etaHEN_log("Trying to fix non-ASLR address");
    //         addr = baseAddress + (mod.Offset - NO_ASLR_ADDR_PS4);
    //         etaHEN_log("New address %#02lx\n", addr);
    //     }
    relocAndPatch:
      if (fixCodeCave) {
        //
        // Fix offset on code caves that don't exist due the process layout
        //
        if (fw < 0x840) {
              if (pt_attach_proc(pid) < 0) {
                  etaHEN_log("Unable to ptrace into %d, aborting cheat...", pid);
                  return false;
              }
        }
        // addr = baseAddress + mod.Offset;
        uint64_t mem = pt_mmap(pid, ROUND_PG_DOWN(addr),
                               ROUND_PG(mod.On.size()), PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYNMOUS, -1, 0);
        etaHEN_log("Code Cave Cheat Mem => %02llx", mem);
        if (mem == -1) {
          etaHEN_log("Unable to fix codecave memory! game must be restarted "
                     "for enabling this cheat!");
          status = false;
          break;
        }
        etaHEN_log("Making it executable...");
        kernel_mprotect(pid, mem, ROUND_PG(mod.On.size()),
                        PROT_READ | PROT_EXEC | PROT_WRITE);

        if (fw < 0x840) {
            pt_detach_proc(pid, 0);
        }
        etaHEN_log("Ready to continue...");
      }

	  etaHEN_log("Enabling cheat %s...", cheat.name.c_str());
      if (fw >= 0x840) {
          kernel_mprotect(pid, addr, patch_size, PROT_READ | PROT_WRITE | PROT_EXEC);
          etaHEN_log("Applying patch...");
          pt_ret = pt_copyin(pid, patch_data, addr, patch_size);
          etaHEN_log("Patch applied, verifying... errrno %d %d", pt_ret, pt_errno(pid));
          kernel_mprotect(pid, addr, patch_size, PROT_READ | PROT_WRITE | PROT_EXEC);
          etaHEN_log("Reading back patched data...");
          pt_ret = pt_copyout(pid, addr, dump_on, patch_size);
          etaHEN_log("Data read back, comparing... errrno %d %d", pt_ret, pt_errno(pid));
      }
      else {
          mdbg_copyin(pid, patch_data, addr, patch_size);
          mdbg_copyout(pid, addr, dump_on, patch_size);
      }
      enabled = true;
      //
      // Checking if patch was applied successfully
      //
      for (int j = 0; j < patch_size; ++j) {
        if (dump_on[j] != patch_data[j]) {
          // if (!try_fix_asrl)
          // {
          //     try_fix_asrl = true;
          //     goto fix_aslr;
          // }

          if (!mod.codeCaveReloc) {
            mod.codeCaveReloc = true;
            fixCodeCave = true;
            goto relocAndPatch;
          } else {
            etaHEN_log("Failed to activate cheat find %s of cheat %s",
                       cheat.module_name.c_str(), title_id.c_str());
            status = false;
            enabled = false;
            break;
          }
        }
      }

      delete[] dump_on;
    }
  }

  cheat.enabled = enabled;
 // pt_continue(pid);
  if (fw >= 0x840) {
      pt_ret = pt_detach_proc(pid, 0);
      etaHEN_log("Detached from process %d, errno %d %d", pid, pt_ret,
          pt_errno(pid));
  }
  return status;
}

GameCheat *
CheatManager::CheatManagerFormats::ParseJSONCheat(const std::string &filename,
                                                  GameCheat *parsed) {

  struct stat st;
  GameCheat *cheat = parsed;
  if (stat(filename.c_str(), &st) != 0) {
    etaHEN_log("CheatManager: %s does not exist!", filename.c_str());
    return cheat;
  }

  int cheat_fd = open(filename.c_str(), O_RDONLY);

  if (!cheat_fd) {
    etaHEN_log("CheatManager: Unable to open %s!", filename.c_str());
    return cheat;
  }

  char *cheat_data = (char *)calloc(st.st_size + 1, sizeof(char));

  if (read(cheat_fd, cheat_data, st.st_size) < 0) {
    free(cheat_data);
    etaHEN_log("CheatManager: Unable to read file %s", filename.c_str());
    return cheat;
  }

  close(cheat_fd);
  //
  // Parse json
  //
  nlohmann::json cheat_json;

  try {
    cheat_json = nlohmann::json::parse(cheat_data);
  } catch (const std::exception &e) {
    etaHEN_log("CheatManager: Failed to parse json: %s", e.what());
    return cheat;
  }

  std::string process_target;
  std::string name;

  if (cheat_json.contains("process") && cheat_json.contains("name")) {
    process_target = cheat_json["process"];
    name = cheat_json["name"];
  } else {
    goto error;
  }

  //
  // Cheat metadata
  //
  if (!cheat) {
    cheat = new GameCheat;
    cheat->name = name;
    cheat->masterCodeId = -1;
  }

  if (cheat_json.contains("mods")) {
    auto mods = cheat_json["mods"];

    for (auto &mod : mods) {
      if (mod.is_object()) {
        CheatInfo mod_info;

        if (mod.contains("name")) {
          mod_info.name = mod["name"].get<std::string>();
        } else {
          continue;
        }

        if (mod.contains("description")) {
          mod_info.description = mod["description"].get<std::string>();
        }

        mod_info.enabled = false;
        mod_info.module_name = process_target;

        //
        // Parse memory patches
        //
        if (mod.contains("memory")) {
          auto memory_json = mod["memory"];

          for (auto &memory : memory_json) {
            if (memory.is_object()) {

              std::string offset;
              std::string on;
              std::string off;
              std::string section;

              if (memory.contains("offset")) {
                offset = memory["offset"];
              }
              if (memory.contains("on")) {
                on = memory["on"];
              }
              if (memory.contains("off")) {
                off = memory["off"];
              }
              if (memory.contains("section")) {
                section = memory["section"];
              }

              if (on.size() && off.size() && offset.size()) {
                CheatMemory mem;
                mem.section = 0;
                mem.codeCaveReloc = false;

                mem.Offset = strtol(offset.c_str(), nullptr, 16);
                mem.On = Converters::unhexlify(on);
                mem.Off = Converters::unhexlify(off);

                if (section.size()) {
                  int section_num = atoi(section.c_str());
                  if (section_num < MODULE_INFO_MAX_SECTIONS)
                    mem.section = section_num;
                }
                mod_info.mods.push_back(mem);
              }
            }
          }
        }
        cheat->cheats.push_back(mod_info);
      }
    }
  }

  //
  // Parse authors
  //
  if (cheat_json.contains("credits")) {
    auto authors = cheat_json["credits"];

    for (auto &author : authors) {
      if (author.is_string()) {
        cheat->authors.push_back(author.get<std::string>());
      }
    }
  }

  goto success;

error:
  etaHEN_log("CheatManager: Invalid cheat file %s", filename.c_str());

success:
  free(cheat_data);
  return cheat;
}

GameCheat *
CheatManager::CheatManagerFormats::ParseMC4Cheat(const std::string &filename,
                                                 GameCheat *parsed) {
  GameCheat *cheat = nullptr;
  struct stat st;
  etaHEN_log("Loading MC4 script %s!", filename.c_str());

  if (stat(filename.c_str(), &st) != 0) {
    etaHEN_log("CheatManager::ParseMC4Cheat: %s does not exist!",
               filename.c_str());
    return cheat;
  }

  int cheat_fd = open(filename.c_str(), O_RDONLY);

  if (!cheat_fd) {
    etaHEN_log("CheatManager::ParseMC4Cheat: Unable to open %s!",
               filename.c_str());
    return cheat;
  }

  char *cheat_data = (char *)calloc(st.st_size + 1, sizeof(char));

  if (read(cheat_fd, cheat_data, st.st_size) < 0) {
    free(cheat_data);
    etaHEN_log("CheatManager::ParseMC4Cheat: Unable to read file %s",
               filename.c_str());
    return cheat;
  }

  close(cheat_fd);

  //
  // Decrypt MC4 data
  //
  size_t decrypted_size = st.st_size;
  uint8_t *decrypted_xml = decrypt_data((uint8_t *)cheat_data, &decrypted_size);
  etaHEN_log("Decrypted at %p size: %d bytes\n", decrypted_xml, decrypted_size);

  if (decrypted_xml) {
    std::string cheat_xml = std::string((char *)decrypted_xml);
    std::vector<std::string> targets = {"&lt;", "&gt;", "\\&quot;"};
    std::vector<std::string> replacement = {"<", ">", "\""};
    replaceAllOccurrences(cheat_xml, targets, replacement);

    //
    // Parse XML
    //
    parsed = CheatManagerFormats::ParseXMLCheat(cheat_xml, parsed);
    if (!parsed) {
      etaHEN_log("Unable to parse cheat file %s!", filename.c_str());
    } else {
      cheat = parsed;
    }
    free(decrypted_xml);
  }

  else {
    etaHEN_log("Unable to decrypt MC4 cheat file %s!", filename.c_str());
  }

  free(cheat_data);
  return cheat;
}

//
// Parse SHN, which is the same as the MC4 but unencrypted
//
GameCheat *
CheatManager::CheatManagerFormats::ParseSHNCheat(const std::string &filename,
                                                 GameCheat *parsed) {
  GameCheat *cheat = parsed;
  struct stat st;
  etaHEN_log("Loading SHN cheat file %s!", filename.c_str());

  if (stat(filename.c_str(), &st) != 0) {
    etaHEN_log("CheatManager::ParseSHNCheat: %s does not exist!",
               filename.c_str());
    return cheat;
  }

  int cheat_fd = open(filename.c_str(), O_RDONLY);

  if (!cheat_fd) {
    etaHEN_log("CheatManager::ParseSHNCheat: Unable to open %s!",
               filename.c_str());
    return cheat;
  }

  char *cheat_data = (char *)calloc(st.st_size + 1, sizeof(char));

  if (read(cheat_fd, cheat_data, st.st_size) < 0) {
    free(cheat_data);
    etaHEN_log("CheatManager::ParseSHNCheat: Unable to read file %s",
               filename.c_str());
    return cheat;
  }

  close(cheat_fd);

  std::string cheat_xml = std::string((char *)cheat_data);
  cheat = CheatManagerFormats::ParseXMLCheat(cheat_xml, cheat);

  if (!parsed) {
    etaHEN_log("CheatManager::ParseSHNCheat failed to parse SHN file %s!",
               filename.c_str());
  }

  free(cheat_data);

  return cheat;
}

//
// Parse XML cheat file, can be used on both mc4 and shn cheats
//
GameCheat *
CheatManager::CheatManagerFormats::ParseXMLCheat(const std::string &xml,
                                                 GameCheat *parsed) {
  GameCheat *cheat = parsed;
  pugi::xml_document doc;
  pugi::xml_parse_result result = doc.load_buffer(xml.c_str(), xml.size());

  if (result) {
    pugi::xml_node trainer = doc.child("Trainer");
    std::string process_target = trainer.attribute("Process").as_string();
    std::string name = trainer.attribute("Game").as_string();
    std::string author = trainer.attribute("Moder").as_string();

    if (!cheat) {
      cheat = new GameCheat;
      cheat->name = name;
      cheat->masterCodeId = -1;
    }

    cheat->authors.push_back(author);
    //
    // Parse mods
    //
    for (pugi::xml_node cheatNode = trainer.child("Cheat"); cheatNode;
         cheatNode = cheatNode.next_sibling("Cheat")) {
      CheatInfo mod_info;
      std::string cheatTitle = cheatNode.attribute("Text").as_string();
      // etaHEN_log("Cheat => %s\n", cheatTitle.c_str());
      mod_info.name = cheatTitle;
      mod_info.description = cheatNode.attribute("Description").as_string();
      mod_info.module_name = process_target;
      mod_info.enabled = false;
      for (pugi::xml_node cheatLine = cheatNode.child("Cheatline"); cheatLine;
           cheatLine = cheatLine.next_sibling("Cheatline")) {
        std::string offset = cheatLine.child("Offset").text().as_string();
        std::string section = cheatLine.child("Section").text().as_string();
        std::string on = cheatLine.child("ValueOn").text().as_string();
        std::string off = cheatLine.child("ValueOff").text().as_string();
        std::string absolute = cheatLine.child("Absolute").text().as_string();  // 09/10/2025 xZenithy
        // etaHEN_log("Offset: %s\nSection: %s\nOn: %s\nOff: %s\n",
        //     offset.c_str(),
        //     section.c_str(),
        //     on.c_str(),
        //     off.c_str()
        // );

        CheatMemory mem;
        mem.codeCaveReloc = false;
        mem.section = 0;
        if (on.size() && off.size() && offset.size()) {
          //
          // Remove the hyphen from the bytearray string
          //
          on.erase(std::remove(on.begin(), on.end(), '-'), on.end());
          off.erase(std::remove(off.begin(), off.end(), '-'), off.end());
          //
          // Convert
          //
          mem.Offset = strtol(offset.c_str(), NULL, 16);
          mem.On = Converters::unhexlify(on);
          mem.Off = Converters::unhexlify(off);
          mem.absolute = !absolute.empty();  // false if missing, true absolute address // 09/10/2025 xZenithy
        }

        if (section.size()) {
          int section_num = atoi(section.c_str());
          if (section_num < MODULE_INFO_MAX_SECTIONS)
            mem.section = section_num;
        }

        mod_info.mods.push_back(mem);
      }

      cheat->cheats.push_back(mod_info);
    }
  }

  return cheat;
}

///////// Converters helpers //////////
int CheatManager::Converters::ascii2val(char c) {
  int iRetVal;

  if ((c >= '0') && (c <= '9')) {
    iRetVal = (c - '0');
  } else if ((c >= 'a') && (c <= 'f')) {
    iRetVal = (c - 'a' + 10);
  } else if ((c >= 'A') && (c <= 'F')) {
    iRetVal = (c - 'A' + 10);
  } else {
    iRetVal = 0;
  }

  return iRetVal;
}

ByteArray CheatManager::Converters::unhexlify(std::string &InBuffer) {
  if (InBuffer.size() == 1 || InBuffer.size() % 2) {
    InBuffer.insert(InBuffer.begin(), '0');
  }

  ByteArray OutBuffer(InBuffer.size() / 2);

  for (size_t i = 0, j = 0; i < InBuffer.size(); i += 2, ++j) {
    uint8_t *dest = &OutBuffer[j];
    *dest++ = (((ascii2val(InBuffer[i]) << 4) | (ascii2val(InBuffer[i + 1]))));
  }

  return OutBuffer;
}

// Function to check if a file entry already exists in cache
bool entry_exists_in_cache(const std::string &cache_path,
                           const std::string &filename) {
  std::ifstream cache_file(cache_path);
  if (!cache_file.is_open()) {
    return false;
  }

  std::string line;
  while (std::getline(cache_file, line)) {
    // Remove any carriage returns if present
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }

    size_t pos = line.find('=');
    if (pos != std::string::npos) {
      std::string cached_filename = line.substr(0, pos);
      if (cached_filename == filename) {
        return true;
      }
    }
  }
  return false;
}

// Extract game name from JSON file using the C TinyJSON library
std::string extract_game_name_from_json(const std::string &file_path) {
  std::string game_name = "Unknown Game";

  // Read the file using standard C file operations
  FILE *file = fopen(file_path.c_str(), "r");
  if (!file) {
    etaHEN_log("Failed to open JSON file: %s", file_path.c_str());
    return game_name;
  }

  // Get file size
  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  // Read the entire file
  char *buffer = (char *)malloc(file_size + 1);
  if (!buffer) {
    fclose(file);
    etaHEN_log("Failed to allocate memory for JSON file");
    return game_name;
  }

  size_t bytes_read = fread(buffer, 1, file_size, file);
  buffer[bytes_read] = '\0';
  fclose(file);

// Parse the JSON using TinyJSON API - allocate memory for parse tree
// Adjust the size as needed based on your JSON complexity
#define MAX_JSON_TOKENS 0x1000
  json_t json_mem[MAX_JSON_TOKENS];

  // Parse the JSON
  const json_t *json = json_create(buffer, json_mem, MAX_JSON_TOKENS);
  if (!json) {
    etaHEN_log("JSON parse error for file: %s", file_path.c_str());
    free(buffer);
    return game_name;
  }

  // Find the "name" field
  const json_t *name_field = json_getProperty(json, "name");
  if (name_field) {
    jsonType_t type = json_getType(name_field);
    etaHEN_log("Type: %d", json_getType(name_field));
    if (type == JSON_TEXT) {
      etaHEN_log("It is JSON_TEXT");
      game_name = json_getValue(name_field);
      etaHEN_log("Name: %s\n", game_name.c_str());
    } else {
      etaHEN_log("It is not JSON_TEXT");
    }
  } else {
    etaHEN_log("Name field not found");
  }

  // Clean up
  free(buffer);

  return game_name;
}

// Extract game name from SHN file
std::string extract_game_name_from_shn(const std::string &file_path) {
  pugi::xml_document doc;
  pugi::xml_parse_result result = doc.load_file(file_path.c_str());

  if (!result) {
    etaHEN_log("XML parse error: %s", result.description());
    return "Unknown Game";
  }

  pugi::xml_node trainer = doc.child("Trainer");
  if (trainer) {
    return trainer.attribute("Game").value();
  }

  return "Unknown Game";
}

// Update cache for a specific directory and file type
// Update cache for a specific directory and file type
void update_cache_for_dir(
    const std::string &dir_path, const std::string &cache_path,
    const std::string &file_ext,
    std::function<std::string(const std::string &)> name_extractor) {
  // First, check if the cache file exists and create it if it doesn't
  bool file_exists = (access(cache_path.c_str(), F_OK) == 0);

  static std::string last_ext = "";
  static time_t last_notify_time = 0;
  time_t current_time = time(NULL);

  // Open cache file in append mode
  std::ofstream cache_file(cache_path, std::ios::app);
  if (!cache_file.is_open()) {
    etaHEN_log("Failed to open cache file: %s", cache_path.c_str());
    return;
  }

  // Make sure the file ends with a newline if it already exists
  if (file_exists) {
    // Check if the file ends with a newline
    std::ifstream check_file(cache_path);
    if (check_file.is_open()) {
      check_file.seekg(-1, std::ios_base::end);
      char last_char;
      check_file.get(last_char);
      check_file.close();

      // If the last character isn't a newline, add one
      if (last_char != '\n') {
        cache_file << std::endl;
      }
    }
  }

  DIR *dir = opendir(dir_path.c_str());
  if (!dir) {
    etaHEN_log("Failed to open directory: %s", dir_path.c_str());
    return;
  }

  int total_files = 0;
  int new_entries = 0;

  // Count total files first for progress reporting
  struct dirent *entry;
  while ((entry = readdir(dir)) != nullptr) {
    std::string filename = entry->d_name;
    if (filename.size() > file_ext.size() &&
        filename.substr(filename.size() - file_ext.size()) == file_ext) {
      total_files++;
    }
  }

  // Reset directory position
  rewinddir(dir);

  int processed = 0;

  // Process each file
  while ((entry = readdir(dir)) != nullptr) {
    std::string filename = entry->d_name;

    // Skip if not the right file extension
    if (filename.size() <= file_ext.size() ||
        filename.substr(filename.size() - file_ext.size()) != file_ext) {
      continue;
    }

    // Only notify if 6 seconds have passed or if we're processing a new
    // extension
    if (last_ext != file_ext) {
      notify(true, "Processing %s files: (%d total files)", file_ext.c_str(),
             total_files);
      last_ext = file_ext;
    } else if (current_time - last_notify_time >= 6) {
      etaHEN_log("Processing %s files: (%d/%d)", file_ext.c_str(), processed,
                 total_files);
      last_notify_time = current_time;
    }
    processed++;

    // Check if entry already exists
    if (entry_exists_in_cache(cache_path, filename)) {
      continue; // Skip existing entries
    }

    // Extract game name
    std::string full_path = dir_path + "/" + filename;
    std::string game_name = name_extractor(full_path);

    // Add to cache with proper line ending
    cache_file << filename << "=" << game_name << std::endl;
    new_entries++;
  }

  closedir(dir);
  cache_file.close();

  notify(true,
         "Completed processing %s files. Added %d new entries out of %d "
         "total files.",
         file_ext.c_str(), new_entries, total_files);
}

// Main caching function
void update_cheat_caches() {
  etaHEN_log("Starting cheat cache update...");

  // Create directories if they don't exist
  mkdir("/data/etaHEN/cheats", 0777);
  mkdir("/data/etaHEN/cheats/shn", 0777);
  mkdir("/data/etaHEN/cheats/mc4", 0777);
  mkdir("/data/etaHEN/cheats/json", 0777);

  // Update JSON cache
  update_cache_for_dir("/data/etaHEN/cheats/json",
                       "/data/etaHEN/cheats/json.txt", ".json",
                       extract_game_name_from_json);

  // Update SHN cache
  update_cache_for_dir("/data/etaHEN/cheats/shn", "/data/etaHEN/cheats/shn.txt",
                       ".shn", extract_game_name_from_shn);

  // For MC4, since we don't have a specific extraction method,
  // we'll use a simple lambda that returns a placeholder
  update_cache_for_dir("/data/etaHEN/cheats/mc4", "/data/etaHEN/cheats/mc4.txt",
                       ".mc4", [](const std::string &path) {
                         // Extract filename without path and extension
                         size_t lastSlash = path.find_last_of('/');
                         size_t lastDot = path.find_last_of('.');
                         std::string filenameWithoutExt = path.substr(
                             lastSlash + 1, lastDot - lastSlash - 1);
                         return filenameWithoutExt;
                       });

  etaHEN_log("Cheat cache update completed.");
}

void *ReloadCheatsCache(void *) {
  update_cheat_caches();
  return MakeInitialCheatCache(NULL);
}
