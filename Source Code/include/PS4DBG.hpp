#pragma once
#include "Platform.hpp"
#include "Process.hpp"
#include "Registers.hpp"

#include "util.hpp"
#include "pthread.h"

using DebuggerInterruptCallback = std::function<void(uint32_t lwpid, uint32_t status, const std::string& tdname, libdebug::regs regs, libdebug::fpregs fpregs, libdebug::dbregs dbregs)>;

namespace libdebug
{
	class PS4DBG
	{
	private:
		Socket sock;
		sockaddr_in server;
		pthread_t debugThread;
		bool connected = false;
		bool debugging = false;

		inline static std::string LIBRARY_VERSION = "1.2";

		static constexpr int32_t PS4DBG_PORT = 744;
		static constexpr int32_t PS4DBG_DEBUG_PORT = 755;
		static constexpr int32_t NET_MAX_LENGTH = 8192;

		static constexpr int32_t BROADCAST_PORT = 1010;
		static constexpr uint32_t BROADCAST_MAGIC = 0xFFFFAAAA;

		static constexpr uint32_t CMD_PACKET_MAGIC = 0xFFAABBCC;

		static constexpr uint32_t MAX_BREAKPOINTS = 10;
		static constexpr uint32_t MAX_WATCHPOINTS = 4;

		//proc
		// send size
		static constexpr int32_t CMD_PROC_READ_PACKET_SIZE = 16;
		static constexpr int32_t CMD_PROC_WRITE_PACKET_SIZE = 16;
		static constexpr int32_t CMD_PROC_MAPS_PACKET_SIZE = 4;
		static constexpr int32_t CMD_PROC_INSTALL_PACKET_SIZE = 4;
		static constexpr int32_t CMD_PROC_CALL_PACKET_SIZE = 68;
		static constexpr int32_t CMD_PROC_ELF_PACKET_SIZE = 8;
		static constexpr int32_t CMD_PROC_PROTECT_PACKET_SIZE = 20;
		static constexpr int32_t CMD_PROC_SCAN_PACKET_SIZE = 10;
		static constexpr int32_t CMD_PROC_INFO_PACKET_SIZE = 4;
		static constexpr int32_t CMD_PROC_ALLOC_PACKET_SIZE = 8;
		static constexpr int32_t CMD_PROC_FREE_PACKET_SIZE = 16;
		// receive size
		static constexpr int32_t PROC_LIST_ENTRY_SIZE = 36;
		static constexpr int32_t PROC_MAP_ENTRY_SIZE = 58;
		static constexpr int32_t PROC_INSTALL_SIZE = 8;
		static constexpr int32_t PROC_CALL_SIZE = 12;
		static constexpr int32_t PROC_PROC_INFO_SIZE = 184;
		static constexpr int32_t PROC_ALLOC_SIZE = 8;

		// kernel
		//send size
		static constexpr int32_t CMD_KERN_READ_PACKET_SIZE = 12;
		static constexpr int32_t CMD_KERN_WRITE_PACKET_SIZE = 12;
		//receive size
		static constexpr int32_t KERN_BASE_SIZE = 8;

		//console
		// send size
		static constexpr int32_t CMD_CONSOLE_PRINT_PACKET_SIZE = 4;
		static constexpr int32_t CMD_CONSOLE_NOTIFY_PACKET_SIZE = 8;

		//debug
		//send size
		static constexpr int32_t CMD_DEBUG_ATTACH_PACKET_SIZE = 4;
		static constexpr int32_t CMD_DEBUG_BREAKPT_PACKET_SIZE = 16;
		static constexpr int32_t CMD_DEBUG_WATCHPT_PACKET_SIZE = 24;
		static constexpr int32_t CMD_DEBUG_STOPTHR_PACKET_SIZE = 4;
		static constexpr int32_t CMD_DEBUG_RESUMETHR_PACKET_SIZE = 4;
		static constexpr int32_t CMD_DEBUG_GETREGS_PACKET_SIZE = 4;
		static constexpr int32_t CMD_DEBUG_SETREGS_PACKET_SIZE = 8;
		static constexpr int32_t CMD_DEBUG_STOPGO_PACKET_SIZE = 4;
		static constexpr int32_t CMD_DEBUG_THRINFO_PACKET_SIZE = 4;
		//receive size
		static constexpr int32_t DEBUG_INTERRUPT_SIZE = 0x4A0;
		static constexpr int32_t DEBUG_THRINFO_SIZE = 40;
		static constexpr int32_t DEBUG_REGS_SIZE = 0xB0;
		static constexpr int32_t DEBUG_FPREGS_SIZE = 0x340;
		static constexpr int32_t DEBUG_DBGREGS_SIZE = 0x80;

		enum class CMDS : uint32_t
		{
			CMD_VERSION = 0xBD000001,

			CMD_PROC_LIST = 0xBDAA0001,
			CMD_PROC_READ = 0xBDAA0002,
			CMD_PROC_WRITE = 0xBDAA0003,
			CMD_PROC_MAPS = 0xBDAA0004,
			CMD_PROC_INTALL = 0xBDAA0005,
			CMD_PROC_CALL = 0xBDAA0006,
			CMD_PROC_ELF = 0xBDAA0007,
			CMD_PROC_PROTECT = 0xBDAA0008,
			CMD_PROC_SCAN = 0xBDAA0009,
			CMD_PROC_INFO = 0xBDAA000A,
			CMD_PROC_ALLOC = 0xBDAA000B,
			CMD_PROC_FREE = 0xBDAA000C,

			CMD_DEBUG_ATTACH = 0xBDBB0001,
			CMD_DEBUG_DETACH = 0xBDBB0002,
			CMD_DEBUG_BREAKPT = 0xBDBB0003,
			CMD_DEBUG_WATCHPT = 0xBDBB0004,
			CMD_DEBUG_THREADS = 0xBDBB0005,
			CMD_DEBUG_STOPTHR = 0xBDBB0006,
			CMD_DEBUG_RESUMETHR = 0xBDBB0007,
			CMD_DEBUG_GETREGS = 0xBDBB0008,
			CMD_DEBUG_SETREGS = 0xBDBB0009,
			CMD_DEBUG_GETFPREGS = 0xBDBB000A,
			CMD_DEBUG_SETFPREGS = 0xBDBB000B,
			CMD_DEBUG_GETDBGREGS = 0xBDBB000C,
			CMD_DEBUG_SETDBGREGS = 0xBDBB000D,
			CMD_DEBUG_STOPGO = 0xBDBB0010,
			CMD_DEBUG_THRINFO = 0xBDBB0011,
			CMD_DEBUG_SINGLESTEP = 0xBDBB0012,

			CMD_KERN_BASE = 0xBDCC0001,
			CMD_KERN_READ = 0xBDCC0002,
			CMD_KERN_WRITE = 0xBDCC0003,

			CMD_CONSOLE_REBOOT = 0xBDDD0001,
			CMD_CONSOLE_END = 0xBDDD0002,
			CMD_CONSOLE_PRINT = 0xBDDD0003,
			CMD_CONSOLE_NOTIFY = 0xBDDD0004,
			CMD_CONSOLE_INFO = 0xBDDD0005,
		};

		enum class CMD_STATUS : uint32_t
		{
			CMD_SUCCESS = 0x80000000,
			CMD_ERROR = 0xF0000001,
			CMD_TOO_MUCH_DATA = 0xF0000002,
			CMD_DATA_NULL = 0xF0000003,
			CMD_ALREADY_DEBUG = 0xF0000004,
			CMD_INVALID_INDEX = 0xF0000005
		};


		struct CMDPacket
		{
			uint32_t magic;
			uint32_t cmd;
			uint32_t datalen;
		};
		struct DebuggerInterruptPacket
		{
			uint32_t lwpid;
			uint32_t status;			
			uint8_t tdname[40];
			regs reg64;
			fpregs savefpu;
			dbregs dbreg64;
		};

	public:
		enum class VM_PROTECTIONS : uint32_t
		{
			VM_PROT_NONE = 0x00,
			VM_PROT_READ = 0x01,
			VM_PROT_WRITE = 0x02,
			VM_PROT_EXECUTE = 0x04,
			VM_PROT_DEFAULT = (VM_PROT_READ | VM_PROT_WRITE),
			VM_PROT_ALL = (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE),
			VM_PROT_NO_CHANGE = 0x08,
			VM_PROT_COPY = 0x10,
			VM_PROT_WANTS_COPY = 0x10
		};
		enum class WATCHPT_LENGTH : uint32_t
		{
			DBREG_DR7_LEN_1 = 0x00,	/* 1 byte length */
			DBREG_DR7_LEN_2 = 0x01,
			DBREG_DR7_LEN_4 = 0x03,
			DBREG_DR7_LEN_8 = 0x02,
		};
		enum class WATCHPT_BREAKTYPE : uint32_t
		{
			DBREG_DR7_EXEC = 0x00,	/* break on execute       */
			DBREG_DR7_WRONLY = 0x01,	/* break on write         */
			DBREG_DR7_RDWR = 0x03,	/* break on read or write */
		};

	private:
		void SendCMDPacket(CMDS cmd, int32_t length, const std::vector<std::any> &fields = {});
		CMD_STATUS ReceiveStatus();
		CMD_STATUS CheckStatus();
		void CheckConnected();
		void CheckDebugging();
		void SendData(const std::vector<uint8_t> &data, int32_t length);
		std::vector<uint8_t> ReceiveData(int32_t length);

		
	public:
		PS4DBG(const std::string &ip);
		~PS4DBG();
		void Connect();
		void Disconnect();
		static std::string GetLibraryDebugVersion();
		std::string GetConsoleDebugVersion();
		bool IsConnected();
		bool IsDebugging();
		//proc
		ProcessList GetProcessList();
		std::vector<uint8_t> ReadMemory(int32_t pid, uint64_t address, int32_t length);
        void WriteMemory(int32_t pid, uint64_t address, const std::vector<uint8_t> &data);
		ProcessMap GetProcessMaps(int32_t pid);
		uint64_t InstallRPC(int32_t pid);
        uint64_t Call(int32_t pid, uint64_t rpcstub, uint64_t address, const std::vector<std::any> &args);
        void LoadElf(int32_t pid, const std::vector<uint8_t> &elf);
        void LoadElf(int32_t pid, const std::string &filePath);
		void ChangeProtection(int32_t pid, uint64_t address, uint32_t length, VM_PROTECTIONS newProt);
		ProcessInfo GetProcessInfo(int32_t pid);
		uint64_t AllocateMemory(int32_t pid, int32_t length);
		void FreeMemory(int32_t pid, uint64_t address, int32_t length);
		
		//kernel
		uint64_t KernelBase();
        std::vector<uint8_t> KernelReadMemory(uint64_t address, int32_t length);
        void KernelWriteMemory(uint64_t address, const std::vector<uint8_t> &data);
        
		//console
		void Reboot();
		void Print(const std::string &str);
		void Notify(int32_t messageType, const std::string &message);
		//debug
		void AttachDebugger(int32_t pid, DebuggerInterruptCallback callback);
		void DetachDebugger();
		void ProcessStop();
		void ProcessKill();
		void ProcessResume();
		void ChangeBreakpoint(int32_t index, bool enabled, uint64_t address);
		void ChangeWatchpoint(int32_t index, bool enabled, WATCHPT_LENGTH length, WATCHPT_BREAKTYPE breaktype, uint64_t address);

		std::vector<uint32_t> GetThreadList();
		ThreadInfo GetThreadInfo(uint32_t lwpid);
		void StopThread(uint32_t lwpid);
		void ResumeThread(uint32_t lwpid);
		regs GetRegisters(uint32_t lwpid);
		void SetRegisters(uint32_t lwpid, regs regs);
		fpregs GetFloatRegisters(uint32_t lwpid);
		void SetFloatRegisters(uint32_t lwpid, fpregs fpregs);
		dbregs GetDebugRegisters(uint32_t lwpid);
		void SetDebugRegisters(uint32_t lwpid, dbregs dbregs);
		void SingleStep();
	private:
		void DebuggerThread(DebuggerInterruptCallback obj);
	};
}

