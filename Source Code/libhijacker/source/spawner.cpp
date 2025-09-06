#include "dbg/dbg.hpp"
#include "hijacker.hpp"
#include "hijacker/hijacker.hpp"
#include "util.hpp"
#include <sys/_stdint.h>
#include <stdio.h>
#include <unistd.h>

// this always seems to be the case
static constexpr uintptr_t ENTRYPOINT_OFFSET = 0x70;
static constexpr int SYSTEM_SERVICE_HANDLE = 38;

struct LoopBuilder {
	static constexpr size_t LOOB_BUILDER_SIZE = 39;
	static constexpr size_t LOOP_BUILDER_TARGET_OFFSET = 2;
	uint8_t data[LOOB_BUILDER_SIZE];

	void setTarget(uintptr_t addr) {
		*reinterpret_cast<uintptr_t *>(data + LOOP_BUILDER_TARGET_OFFSET) = addr;
	}
};

static inline constexpr LoopBuilder SLEEP_LOOP{
	// // 48 b8 xx xx xx xx xx xx xx xx 48 c7 c7 40 42 0f 00 ff d0 eb eb
	//loop:
	//	MOV RAX, _nanosleep
	0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// MOV RDI, 1000000000 // 1 second
	0x48, 0xc7, 0xc7, 0x00, 0xca, 0x9a, 0x3b,
	// MOV RSI, 0
	0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00,
	// PUSH RDI
	0x57,
	// PUSH RSI
	0x56,
	// CALL RAX
	0xff, 0xd0,
	// JMP loop
	0xeb, 0xe2
};

namespace {
	// shellcode to hack into your ps5 and steal your nudes
	extern const uint8_t SHELLCODE[282];
}

struct Args {
	struct Result {
		int32_t state;
		int32_t err;
	} result;
	uintptr_t sceSystemServiceGetAppStatus;
	uintptr_t sceSystemServiceAddLocalProcess;
	uintptr_t socketpair;
	uintptr_t usleep;
	uintptr_t errno;

	Args(Hijacker &hijacker) :
			result({0, 0}), socketpair(hijacker.getLibKernelFunctionAddress(nid::socketpair)),
			usleep(hijacker.getLibKernelFunctionAddress(nid::usleep)), errno(hijacker.getLibKernelFunctionAddress(nid::_errno)) {
		UniquePtr<SharedLib> libSceSystemService = hijacker.getLib(SYSTEM_SERVICE_HANDLE);
		SharedLib *lib = libSceSystemService.get();
		sceSystemServiceGetAppStatus = hijacker.getFunctionAddress(lib, nid::sceSystemServiceGetAppStatus);
		sceSystemServiceAddLocalProcess = hijacker.getFunctionAddress(lib, nid::sceSystemServiceAddLocalProcess);
	}
};

static int32_t getResult(const Hijacker &hijacker, ProcessPointer<int32_t> &state, dbg::IdArray &pids, int pid) {

	// we are done when a new process has spawned or the hijacked process has died

	auto frame = hijacker.getTrapFrame();
	if (frame == nullptr) {
		return -2;
	}

	int32_t res = *state;
	if (res != 0) {
		return res;
	}

	auto ids = dbg::getAllPids();

	return ids.contains(pid) && ids.length() > pids.length();
}

UniquePtr<Hijacker> Spawner::spawn() {
	LoopBuilder loop = SLEEP_LOOP;

	const int lastPid = pids[0];

	// this should never miss because the pid lock is currently
	// held by the kernel when creating the new process
	// if spawning fails it's because the redis server can only do this once
	// we'll end up obtaining the previously spawned one
	// may be a good idea to rename the process
	int id = dbg::getAllPids()[0];

	if (id == lastPid) {
		// catastrophic failure
		puts("catastrophic failure\n");
		printf("lastPid %d id %d\n", lastPid, id);
		return nullptr;
	}

	UniquePtr<dbg::ProcessInfo> info = new dbg::ProcessInfo(id);

	printf("spawned %s\n", info->name().c_str());
	// TODO: time from here until the stack pointer is set
	UniquePtr<Hijacker> spawned = nullptr;
	while (spawned == nullptr) {
		spawned = Hijacker::getHijacker(id);
		usleep(10); // NOLINT(*)
	}

	uintptr_t base = 0;
	while (base == 0) {
		base = spawned->getLibKernelBase();
	}

	loop.setTarget(base + nanosleepOffset);
	base = spawned->imagebase();

	// force the entrypoint to an infinite loop so that it doesn't start until we're ready
	dbg::write(id, base + ENTRYPOINT_OFFSET, loop.data, sizeof(loop.data));

	return spawned;
}

UniquePtr<Hijacker> Spawner::bootstrap(Hijacker &hijacker) {

	uintptr_t entry = hijacker.textAllocator.allocate(sizeof(SHELLCODE));
	hijacker.write(entry, SHELLCODE);

	uintptr_t argbuf = hijacker.dataAllocator.allocate(sizeof(Args));
	Args args{hijacker};
	dbg::write(pid, argbuf, &args, sizeof(args));

	ProcessPointer<int32_t> pstate = {pid, argbuf};

	ScopedSuspender suspender{&hijacker};
	auto frame = hijacker.getTrapFrame();
	if (frame == nullptr) {
		return nullptr;
	}

	UniquePtr<TrapFrame> backup{new TrapFrame(*frame.get())};

	frame->setRdi(argbuf)
		.setRip(entry)
		.setRsp(frame->getRsp())
		.flush();

	// wait for the new process to spawn
	hijacker.resume();
	int32_t state = 0;
	do { // NOLINT(cppcoreguidelines-avoid-do-while)
		state = getResult(hijacker, pstate, pids, pid);
	} while (state == 0);

	if (state != 1) [[unlikely]] {
		if (state == -2) {
			// process died
			return nullptr;
		}
		ProcessPointer<Args::Result> pres{pid, argbuf};
		Args::Result res = *pres;
		if (res.state == -1) {
			printf("spawn failed err: %s\n", strerror(res.err));
		} else if (res.state > 1) {
			printf("spawn failed %d\n", res.state);
		} else {
			printf("spawn failed state: %llx err: 0x%llx\n", (unsigned long long) res.state, (unsigned long long) res.err);
		}
		return nullptr;
	}

	hijacker.suspend();
	hijacker.getTrapFrame()->setFrame(backup.get())
		.flush();

	return spawn();
}

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers)

namespace {

// see shellcode/spawner.c for source
const uint8_t SHELLCODE[]{
	0x53, 0x48, 0x83, 0xec, 0x60, 0x48, 0x89, 0xfb, 0x48, 0x8d, 0x7c, 0x24, 0x40, 0xff, 0x53, 0x08,
	0x85, 0xc0, 0x0f, 0x88, 0xa2, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x4c, 0x24, 0x10, 0xbf, 0x01, 0x00,
	0x00, 0x00, 0xbe, 0x01, 0x00, 0x00, 0x00, 0x31, 0xd2, 0xc7, 0x44, 0x24, 0x10, 0x00, 0x00, 0x00,
	0x00, 0xc7, 0x44, 0x24, 0x14, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x18, 0x01, 0x00, 0x00,
	0x00, 0xc7, 0x44, 0x24, 0x1c, 0xff, 0xff, 0xff, 0xff, 0x48, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00,
	0x00, 0x00, 0x48, 0xc7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00, 0xff, 0x53, 0x18, 0x83, 0xf8,
	0xff, 0x74, 0x77, 0x48, 0xb8, 0x2f, 0x61, 0x70, 0x70, 0x30, 0x2f, 0x65, 0x62, 0x48, 0x8d, 0x74,
	0x24, 0x30, 0x48, 0x8d, 0x54, 0x24, 0x08, 0x48, 0x8d, 0x4c, 0x24, 0x10, 0x48, 0x89, 0x44, 0x24,
	0x30, 0x48, 0xb8, 0x6f, 0x6f, 0x74, 0x2e, 0x62, 0x69, 0x6e, 0x00, 0x48, 0x89, 0x44, 0x24, 0x38,
	0x48, 0xc7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x7c, 0x24, 0x40, 0xff, 0x53, 0x10,
	0x85, 0xc0, 0x78, 0x56, 0xc7, 0x03, 0x01, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
	0xbf, 0x40, 0x42, 0x0f, 0x00, 0xff, 0x53, 0x20, 0xeb, 0xf6, 0xc7, 0x03, 0x02, 0x00, 0x00, 0x00,
	0x89, 0x43, 0x04, 0x66, 0x66, 0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xbf, 0x40, 0x42, 0x0f, 0x00, 0xff, 0x53, 0x20, 0xeb, 0xf6, 0xff, 0x53, 0x28, 0x8b, 0x00, 0xc7,
	0x03, 0x03, 0x00, 0x00, 0x00, 0x89, 0x43, 0x04, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xbf, 0x40, 0x42, 0x0f, 0x00, 0xff, 0x53, 0x20, 0xeb, 0xf6, 0xc7, 0x03, 0x02, 0x00, 0x00, 0x00,
	0x89, 0x43, 0x04, 0x66, 0x66, 0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xbf, 0x40, 0x42, 0x0f, 0x00, 0xff, 0x53, 0x20, 0xeb, 0xf6
};

} // anonymous namespace

// NOLINTEND(cppcoreguidelines-avoid-magic-numbers)
