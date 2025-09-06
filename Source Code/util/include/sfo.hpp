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
#include <string>
#include <vector>

#define u8  uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t
#define s8  int8_t
#define s16 int16_t
#define s32 int32_t
#define s64 int64_t
#define unat uintptr_t

struct SfoHeader {
	u32 magic;
	u32 version;
	u32 keyTabOffs;
	u32 dataTabOffs;
	u32 entryCount;
};

struct SfoEntry {
	u16 keyOffs;
	u16 paramFmt;
	u32 paramLen;
	u32 paramMax;
	u32 dataOffs;
};


enum FmtParam : u16 {
	Fmt_StrS	= 0x004,
	Fmt_Utf8	= 0x204,
	Fmt_SInt32	= 0x404,

	Fmt_Invalid = 0x000
};


class SfoReader
{
	u64 size=0;
	const u8* data=nullptr;

	SfoHeader* hdr=nullptr;
	SfoEntry* entries=nullptr;


	static bool isNum (SfoEntry* e) { return (e &&  e->paramFmt==Fmt_SInt32); }
	static bool isText(SfoEntry* e) { return (e && (e->paramFmt==Fmt_StrS || Fmt_Utf8==e->paramFmt)); }

public:

	void setData(const u8* sfoData = nullptr, const u64 sfoSize = 0)
	{
		if (sfoData && sfoSize) {
			data = sfoData;
			size = sfoSize;

			hdr     = (SfoHeader*)(data);
			entries = (SfoEntry *)(data + sizeof(SfoHeader));
		}
	}

	SfoReader(const u8* sfoData = nullptr, const u64 sfoSize = 0)
	{
		setData(sfoData, sfoSize);
	}
	
	SfoReader(const std::vector<u8>& sfoData)
	{
		setData(&sfoData[0], sfoData.size());
	}



	template<typename T>
	inline T operator[](SfoEntry* e)
	{
		T rv = 0;
		std::vector<u8> eData;
		if(getEntryData(e,eData)) {
			rv=*(T*)&eData[0];
		}
		return rv;
	}

	// apparently doesn't work 
	template<> inline std::string operator[](SfoEntry* e)
	{
		std::string s;
		std::vector<u8> eData;
		if(e && getEntryData(e,eData)) {
			s= std::string((char*)&eData[0]);
		}
		return s;
	}


	inline SfoEntry* _ent(u32 index)	//  operator[]
	{
		if (hdr && entries && index < hdr->entryCount && size > (sizeof(SfoHeader)+sizeof(SfoEntry)*index))
			return &entries[index];

		return nullptr;
	}

#if 0
	template<typename T> T operator[](const std::string key)
	{
		for (u32 i=0; i<hdr->entryCount; i++) {
			SfoEntry *e = &entries[i];
			std::string k;
			if (getEntryKey(e, k) && k==key) {
				return (T)this->operator[](e);
			}
		}
		return T();
	}
	template<typename T> T operator[](const char* key)
	{
		return this->operator[](std::string(key));
	}
#endif

	template<typename T> T GetValueFor(const std::string key)
	{
		for (u32 i=0; i<hdr->entryCount; i++) {
			SfoEntry *e = _ent(i); // &entries[i];
			std::string k;
			if (e && getEntryKey(e, k) && k==key) {
				return (T)this->operator[]<T>(e);
			}
		}
		return T();
	}

	template<> u64 GetValueFor(const std::string key)
	{
		for (u32 i=0; i<hdr->entryCount; i++) {
			SfoEntry *e = _ent(i); // &entries[i];
			std::string k;
			if (e && getEntryKey(e, k) && k==key) {
				return GetValue(e);
			}
		}
		return ~0;
	}

	// yet same specialization works fine here 
	template<> std::string GetValueFor(const std::string key)
	{
		for (u32 i=0; i<hdr->entryCount; i++) {
			SfoEntry *e = _ent(i); // &entries[i];
			std::string k;
			if (e && getEntryKey(e, k) && k==key) {
				return GetString(e);
			}
        }

		return std::string();
	}
#if 0
	template<typename T> T GetValueFor(const char* key)
	{
		return GetValueFor<std::string>(std::string(key));
	}
#endif

	inline bool getEntryKey(SfoEntry* e, std::string& keyStr)
	{
		unat fileOffs = hdr->keyTabOffs + e->keyOffs;

		keyStr = "INVALID";
		if (fileOffs < size) {	// ParamLen2 ?
			keyStr = std::string((const char*)(data + fileOffs));
			return true;
		}
		return false;
	}
	inline bool getEntryKey(u32 index, std::string& keyStr)
	{
		SfoEntry *e = _ent(index);	//this->operator[](index);
		return e && getEntryKey(e, keyStr);
	}

	inline bool getEntryData(SfoEntry* e, std::vector<u8>& entData)
	{
		entData.clear();
		u64 fileOffs = hdr->dataTabOffs + e->dataOffs;
		if (fileOffs + e->paramLen < size) {
			entData.resize(e->paramLen);
			memcpy(&entData[0], data + fileOffs, e->paramLen);
			return true;
		}
		return false;
	}
	inline bool getEntryData(u32 index, std::vector<u8>& data)
	{
		SfoEntry *e = _ent(index);	//this->operator[](index);
		return e && getEntryData(e, data);
	}
	
	std::string GetKey(SfoEntry *e, std::string defVal= std::string())
	{
		std::string s(defVal);

		if(!getEntryKey(e,s)) {
			printf("GetKey() failed!\n");
		}
		return s;
	}

	std::string GetString(SfoEntry *e, std::string defVal= std::string(), bool* res=nullptr)
	{
		if (res) *res=false;
		std::string s(defVal);

		if (e && isText(e)) {
			std::vector<u8> eData;
			if(getEntryData(e,eData)) {
				s=std::string((char*)&eData[0]);
				if (res) *res=true;
			}
		}
		return s;
	}
	std::string GetString(u32 index, std::string defVal=std::string(), bool* res=nullptr)
	{
		SfoEntry *e = _ent(index);		// this->operator[](index);
		return GetString(e,defVal,res);
	}

	u32 GetValue(SfoEntry *e, u32 defVal=~0, bool* res=nullptr)
	{
		if (res) *res=false;
		u32 rv=defVal;

		if (e && isNum(e)) {
			std::vector<u8> eData;
			if(getEntryData(e,eData)) {
				rv=*(u32*)&eData[0];
				if (res) *res=true;
			}
		}
		return rv;
	}

	// T must be integer
	template<typename T> inline T GetValue(SfoEntry *e, T defVal=~0, bool* res=nullptr)
	{
		return T(GetValue(e,defVal,res));
	}

	template<typename T> inline T GetValue(u32 index, T defVal=~0, bool* res=nullptr)
	{
		SfoEntry *e = _ent(index);// this->operator[](index);
		return T(GetValue(e,defVal,res));
	}


};