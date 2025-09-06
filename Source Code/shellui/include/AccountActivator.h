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
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "external_symbols.hpp"
#include "HookedFuncs.hpp"


#define USERNAME_ENTITY_NUMBER      0x7800200
#define USERNAME_ENTITY_NUMBER_2    0x7940200

#define ACCOUNT_ID_ENTITY_NUMBER    0x7800500
#define ACCOUNT_ID_ENTITY_NUMBER_2  0x7940500

#define ACCOUNT_TYPE_ENTITY_NUMBER   0x780b007
#define ACCOUNT_TYPE_ENTITY_NUMBER_2 0x794b007

#define ACCOUNT_ENTITY_FLAGS_NUMBER    0x7800800
#define ACCOUNT_ENTITY_FLAGS_NUMBER_2  0x7940800


#define REMOTE_PLAY_ENABLE_REGISTRY     0x41810000

#define ACCOUNT_TYPE_MAX 17

extern "C" int sceUserServiceInitialize(uint32_t*);
extern "C" int sceUserServiceGetForegroundUser(int*);
extern "C" int sceUserServiceGetUserName(int, char*, size_t);
extern "C" int sceUserServiceTerminate(void);

extern "C" int sceRegMgrGetStr(int, char*, size_t);
extern "C" int sceRegMgrGetBin(int, void*, size_t);

extern "C" int sceRegMgrSetInt(int, int);
extern "C" int sceRegMgrSetBin(int, const void*, size_t);
extern "C" int sceRegMgrSetStr(int, const char*, size_t);

typedef std::vector<std::string> AccountList;


struct User
{
    std::string Username;
    uint32_t account_number;
    uint64_t accountID;
    char AccountType[ACCOUNT_TYPE_MAX];
};


class Activator
{
public:
    Activator(bool skip_userservice_init = false);
    bool Activate();
    void GetPSAccount(std::string& account);

    inline bool Valid() const { return currentUser.account_number != -1; }
    bool IsNotActivated();

    User currentUser;
private:
    int GetEntityNumber(int a, int d, int e);
    uint32_t GetRegistryFromUsername(const std::string& username);
    uint64_t GetAccountID(uint32_t account_number);
    uint32_t GetAccountType(uint32_t account_number, char* account_type);
    uint32_t GetAccountFlags(uint32_t account_number);
    uint64_t GenerateAccountID(const char* username);

    
    void SetAccountID(uint32_t account_number, uint64_t AccountID);
    void SetAccountType(uint32_t account_number, char* AccountType);
    void SetAccountFlags(uint32_t account_number, uint32_t Flags);




};