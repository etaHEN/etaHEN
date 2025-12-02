# etaHEN - AIO Homebrew enabler

![etaHEN](https://github.com/LightningMods/etaHEN/blob/main/etaHEN-Icon.jpg)

## 🚀 **Support the Project**

If you find this project useful and would like to support its continued development, consider buying me a coffee!
[![GitHub Sponsers](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://github.com/sponsors/LightningMods)

## Building from Source

The Source code is provided in the Source code folder under GPLv3 with all the necessary files to build it as required under GPLv3 
However I will not be providing instructions on how to build it since any dev should know how to use cmake 

## Official PS5 exploit website 
- https://tinyurl.com/PS5IPV6 (requires you to manually send the payload but has the best stability)
- https://ps5jb.pages.dev/ (auto loads the payload for you, id recommend the IPV6 exploit over UMTX)

## Recommended self-host exploits
- [Modified IPV6 exploit for etaHEN support](https://github.com/LightningMods/PS5-IPV6-Kernel-Exploit)

## Payload PowerShell Script usage for Windows (send_payload.ps1)

if you haven't already, you will need to either enable script execution globally via 

```
Set-ExecutionPolicy Bypass
```
in an admin PowerShell window or run the script with this command after replacing the script path

```
powershell.exe -ExecutionPolicy Bypass -File C:\Path\To\send_payload.ps1
```
**Script Usage**

```
.\send_payload.ps1 -Payload "C:\path\to\example.elf" -IP "192.168.xxx.xxx" -Port XXXX
```

**OR**

```
.\send_payload.ps1

cmdlet send_payload.ps1 at command pipeline position 1
Supply values for the following parameters:
(Type !? for Help.)
Payload: C:\path\to\example.elf
IP: 192.168.xxx.xxx
Port: XXXX
```
- Common Ports: SB elfldr 9021, exploit elfldr 9020

## Features
 - ★ etaHEN toolbox (debug settings replacement)
 - Custom etaHEN [Plugins](https://github.com/LightningMods/etaHEN-SDK/tree/main/Plugin_samples)
 - [Toolbox] Install the Homebrew Store on the console
 - [Toolbox] ★Rest Mode Options
 - [Toolbox] Remote Play Menu
 - [Toolbox] Plugin / Payload ELF Menu with auto start options
 - [Toolbox] External HDD Menu
 - [Toolbox] TestKit Menu  
 - [Toolbox] Kstuff menu
 - [Toolbox] Game Overlay Menu
 - [Toolbox] Cheats Menu (WIP)
 - [Toolbox] Controller Shortcuts
 - [Toolbox] PS5 webMAN Games menu
 - [Toolbox] Custom Game Options Menu
 - [Toolbox] Display Title IDs on Home menu
 - [Toolbox] Disable toolbox auto start
 - [Toolbox] Blu-Ray license activation 
 - [Toolbox] Disc auto eject for BD-J and LUA based exploits
 - [Toolbox] etaHEN credits and supporters
 - [Toolbox] Custom debug settings text and icon
 - [Toolbox] Auto open menu after etaHEN loads
 - [Toolbox] a number of different toolbox settings
 - React bundle (all FWs) & Self (only on 2.xx) FTP decryption Support
 - 2 seperate daemons for improved stability and reliability
 - The Util daemon will be auto restarted by the main etaHEN daemon
 - Custom System Software version (custom System info)
 - kstuff for fself and fpkg support 
 - etaHEN log in /data/etaHEN
 - (optional) System-wide controller shortcut to open itemzflow
 - Debug Settings
 - Game Dumper (Intrgrated with Itemzflow)
 - HEN config file for settings
 - Jailbreak IPC call (jailbreaks Homebrew apps)
 - Update blocker (unmounts update partition)
 - *Optional* Illusions cheats/patches [Plugin](https://github.com/LightningMods/etaHEN-SDK/tree/main/Plugin_samples/Illusion_cheats)
 - *Optional* FTP server on port 1337
 - *Optional* /data allowed inside apps sandboxes
 - Klog server on port 9081
 - elf loader on port 9021 (use Johns elfldr)
 - *Optional* PS5Debug
 - Itemzflow intergration
 - *Optional* Discord RPC server on port 8000, click [here](https://github.com/jeroendev-one/ps5-rpc-client) for setup instructions 
 - *Optional* Direct PKG installer V2 service with WebUI on http://PS5_IP:12800
 - *Optional* Direct PKG installer service on port 9090

## etaHEN SDK
make your own custom plugins via the [etaHEN SDK](https://github.com/lightningmods/etaHEN-SDK)
More info [Here](https://github.com/LightningMods/etaHEN-SDK/blob/main/README.md)

## Upcoming features
 - [Toolbox] FPS Counter
 - More userland patches
 - Improved PS5 Game support (itemzflow)
 - More (consider donating)

## etaHEN INI Configuration file 
etaHEN's ini settings file can be found at `/data/etaHEN/config.ini` and can be accessed using the built-in FTP
and is automatically created when you run etaHEN for the first time

| INI Key             | Description                                                 | Default value |
|---------------------|-------------------------------------------------------------|---------------|
| `PS5Debug`          | 0 = disables PS5Debug (Sistr0) auto load, 1 = enable PS5Debug auto load | 0 (disabled) |
| `FTP`               | 0 = disables etaHEN built-in FTP, 1 = enables it          | 1 (enabled) |
| `discord_rpc`       | 0 = disables Discord RPC server, 1 = enables it           | 0 (disabled) |
| `toolbox_auto_start` | 0 = disabled, 1 = enabled                                 | 1 (enabled) |
| `Allow_data_in_sandbox` | 0 = disables /data in an apps sandbox, 1 = enables it | 1 (enabled) |
| `DPI`               | 0 = disables The Direct PKG Installer service, 1 = enables it | 0 (disabled) |
| `DPI_v2`            | 0 = disables DPI version 2, 1 = enables it                | 0 (disabled) |
| `Klog`              | 0 = disables kernel logging, 1 = enables it               | 0 (disabled) |
| `ALLOW_FTP_DEV_ACCESS` | 0 = disables FTP developer access, 1 = enables it      | 0 (disabled) |
| `StartOption`       | 0=None, 1=Home menu, 2=Settings, 3=Toolbox, 4=itemzflow  | 0 (None) |
| `Rest_Mode_Delay_Seconds` | Delay in seconds before patching shellui coming out rest mode | 0 (no delay) |
| `Util_rest_kill`    | 0 = don't kill the util daemon during rest, 1 = Do kill it on rest | 0 (disabled) |
| `Game_rest_kill`    | 0 = don't kill the open game during rest, 1 = Do kill it on rest | 0 (disabled) |
| `disable_toolbox_auto_start_for_rest_mode` | 0 = disabled, 1 = enabled | 0 (disabled) |
| `libhijacker_cheats` | 0 = disables libhijacker cheats, 1 = enables it          | 0 (disabled) |
| `launch_itemzflow`  | 0 = disabled, 1 = enables auto launch of itemzflow        | 0 (disabled) |
| `testkit`           | 0 = disabled, 1 = enables testkit mode                    | 0 (disabled) |
| `Display_tids`      | 0 = disabled, 1 = enables display of title IDs            | 0 (disabled) |
| `APP_JB_Debug_Msg`  | 0 = disabled, 1 = enables app jailbreak debug messages    | 0 (disabled) |
| `etaHEN_Game_Options` | 0 = disabled, 1 = enables etaHEN game options           | 1 (enabled) |
| `auto_eject_disc`   | 0 = disabled, 1 = enables automatic disc ejection         | 0 (disabled) |
| `Cheats_shortcut_opt` | Multi-select option for cheats shortcut                 | 0 (CHEATS_SC_OFF) |
| `Toolbox_shortcut_opt` | Multi-select option for toolbox shortcut               | 0 (TOOLBOX_SC_OFF) |
| `Games_shortcut_opt` | Multi-select option for games shortcut                   | 0 (GAMES_SC_OFF) |
| `Kstuff_shortcut_opt` | Multi-select option for kstuff shortcut                | 0 (KSTUFF_SC_OFF) |
| `auto_eject_disc`  | 0 = disabled, 1 = enabled        | 0 (disabled) |
| `overlay_ram`           | 0 = disabled, 1 = enabled                    | 0 (disabled) |
| `overlay_cpu`      | 0 = disabled, 1 = enabled            | 0 (disabled) |
| `overlay_gpu`  | 0 = disabled, 1 = enabled    | 0 (disabled) |
| `overlay_ip` | 0 = disabled, 1 = enabled           | 1 (enabled) |
| `overlay_kstuff` | 0 = disabled, 1 = enabled           | 1 (enabled) |
| `Overlay_pos` | Multi-select option for game overlay                | 0 (OVERLAY_POS_TOP_LEFT) |

## DPI API details for tool creators 
etaHEN's Direct PKG Installer currently is very simple and is considered a WIP
the service flow is as follows

1. Connect to etaHEN's TCP server via port 9090 (using the PS5s IP)
2. Send a URL to etaHEN in the following json format
```
{ "url" : "http://xxxx" }
```
3. etaHEN will then send back the return value (0 on success)
```
{ "res" : "0" }
```
4. etaHEN will close the client socket after the return json is sent


## Jailbreaking an app (FPKG) using etaHEN (non-whitelist method, Network and Legacy CMD server toolbox setting required)

```
enum Commands : int {
  INVALID_CMD = -1,
  ACTIVE_CMD = 0,
  LAUNCH_CMD,
  PROCLIST_CMD,
  KILL_CMD,
  KILL_APP_CMD,
  JAILBREAK_CMD
};

struct HijackerCommand
{
  int magic = 0xDEADBEEF;
  Commands cmd = INVALID_CMD;
  int PID = -1;
  int ret = -1337;
  char msg1[0x500];
  char msg2[0x500];
};

int HJOpenConnectionforBC() {

  SceNetSockaddrIn address;
  address.sin_len = sizeof(address);
  address.sin_family = AF_INET;
  address.sin_port = sceNetHtons(9028); //command serve port
  memset(address.sin_zero, 0, sizeof(address.sin_zero));
  sceNetInetPton(AF_INET, "127.0.0.1", &address.sin_addr.s_addr);

  int socket = sceNetSocket("IPC_CMD_SERVER", AF_INET, SOCK_STREAM, 0);
  if (sceNetConnect(socket, (SceNetSockaddr*)&address, sizeof(address)) < 0) {
    close(socket), socket = -1;
  }

  return socket;
}

bool HJJailbreakforBC(int& sock) {

  // send jailbreak IPC command
  HijackerCommand cmd;
  cmd.PID = getpid();
  cmd.cmd = JAILBREAK_CMD;

  if (send(sock, (void*)&cmd, sizeof(cmd), MSG_NOSIGNAL) == -1) {
      puts("failed to send command");
      return false;
  }
  else {
    // get ret val from daemon
    recv(sock, reinterpret_cast<void*>(&cmd), sizeof(cmd), MSG_NOSIGNAL);
    close(sock), sock = -1;
    if (cmd.ret != 0 && cmd.ret != -1337) {
      puts("Jailbreak has failed");
      return false;
    }
    return true;
  }

  return false;
}

int main()
{

     int ret = HJOpenConnectionforBC();
     if (ret < 0) {
         puts("Failed to connect to daemon");
         return -1;
     }
     if (!HJJailbreakforBC(ret))
     {
          puts("Jailbreak failed");
          return -1;
     }

     return 0;
}
```

## Contributors
- [John Tornblom / PS5-Payload-dev](https://github.com/john-tornblom)
- [Buzzer](https://github.com/buzzer-re)
- [sleirsgoevy](https://github.com/sleirsgoevy)
- [ChendoChap](https://github.com/ChendoChap)
- [astrelsky](https://github.com/astrelsky)
- [illusion](https://github.com/illusion0001)
- CTN & [SiSTR0](https://github.com/SiSTR0) for PS5Debug
- [Nomadic](https://github.com/jeroendev-one) (Discord RPC feature)

## Testers
- [Echo Stretch](https://twitter.com/StretchEcho)
- [idlesauce](https://github.com/idlesauce)
- [Dizz](https://github.com/DizzRL)
- [BedroZen](https://twitter.com/BedroZen)
- [MODDED WARFARE](https://twitter.com/MODDED_WARFARE)


## Join us on the Support Discord
- https://discord.gg/xs2F46tKzK
