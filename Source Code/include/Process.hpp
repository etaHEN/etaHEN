#pragma once

//#include <string>
//#include <vector>
//#include <cstdint>
//#include <memory>
#include "util.hpp"

namespace libdebug
{
	class Process 
	{
	public:
		const String name;
		const int32_t pid;
		
		Process(const String &name, int32_t pid);
	};
	
	class ProcessList 
	{
	public:
		Vector<void*> processes;
	
		ProcessList(int32_t number, const Vector<String> &names, const Vector<int32_t> &pids);
		void* FindProcess(const String &name, bool contains = false);
	};
	
	struct MemoryEntry
	{
	public:
		String name;
		uint64_t start;
		uint64_t end;
		uint64_t offset;
		uint32_t prot;
	};
	
	class ProcessMap
	{
	public:
		const int32_t pid;
		const Vector<void*> entries;
		
		ProcessMap(int32_t pid, Vector<void*> entries);
		
		void* FindEntry(const String &name, bool contains = false);
		void* FindEntry(uint64_t size);
	};
	
	struct ProcessInfo
	{
		int32_t pid;
		uint8_t name[40];
		uint8_t path[64];
		uint8_t titleid[16];
		uint8_t contentid[64];
	};
	
	struct ThreadInfo
	{
		int32_t pid;
		int32_t priority;
		uint8_t name[32];
	};
}
