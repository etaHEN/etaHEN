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

#include "../include/AccountActivator.h"


Activator::Activator(bool skip_userservice_init)
{

    if (!skip_userservice_init)
    {
        int ret = sceUserServiceInitialize(NULL);

        if (ret)
        {
            std::puts("Error sceUserServiceInitialize");
            return;
        }
    }

    //
    // Get current logged user
    //
    int user_id;
    char username[100] = {0};
    sceUserServiceGetForegroundUser(&user_id);
    sceUserServiceGetUserName(user_id, username, sizeof(username));  
    currentUser.Username = std::string(username);
    // currentUser.Username = "User1";
    currentUser.account_number = GetRegistryFromUsername(currentUser.Username);

    if (currentUser.account_number == -1)
    {
        std::printf("Invalid user %s, aborting...\n", currentUser.Username.c_str());
        return;    
    }

    currentUser.accountID = GetAccountID(currentUser.account_number);
    GetAccountType(currentUser.account_number, currentUser.AccountType);

    std::printf("Current user => %s\n", currentUser.Username.c_str());
    std::printf("Account register number => %d\n", currentUser.account_number);
    std::printf("User Account ID => %lx\n", currentUser.accountID);
    std::printf("AccountType => %s\n", currentUser.AccountType);
    std::printf("Account Flags => %d\n", GetAccountFlags(currentUser.account_number));
    
    if (!skip_userservice_init)
    {
        sceUserServiceTerminate();
    }
}


uint32_t Activator::GetRegistryFromUsername(const std::string& username)
{
    char reg_username[100] = {0};

    for (ssize_t i = 0; i < 100; ++i)
    {
        int reg_number = GetEntityNumber(i, USERNAME_ENTITY_NUMBER, USERNAME_ENTITY_NUMBER_2);
        sceRegMgrGetStr(reg_number, reg_username, 100);
        
        if (!strncmp(username.c_str(), reg_username, username.size()))
        {
            return i;
        }
    }

    return -1;
}


uint64_t Activator::GetAccountID(uint32_t account_number)
{
    int n = GetEntityNumber(account_number, ACCOUNT_ID_ENTITY_NUMBER, ACCOUNT_ID_ENTITY_NUMBER_2);
    uint64_t val = 0;

    sceRegMgrGetBin(n, &val, sizeof(uint64_t));

    return val;
}


void Activator::SetAccountID(uint32_t account_number, uint64_t AccountID)
{
    int n = GetEntityNumber(account_number, ACCOUNT_ID_ENTITY_NUMBER, ACCOUNT_ID_ENTITY_NUMBER_2);

    sceRegMgrSetBin(n, &AccountID, sizeof(uint64_t));
}


void Activator::SetAccountType(uint32_t account_number, char* AccountType)
{
    int n = GetEntityNumber(account_number, ACCOUNT_TYPE_ENTITY_NUMBER, ACCOUNT_TYPE_ENTITY_NUMBER_2);
    
    sceRegMgrSetStr(n, AccountType, ACCOUNT_TYPE_MAX);
}


uint32_t Activator::GetAccountType(uint32_t account_number, char* account_type)
{
    int n = GetEntityNumber(account_number, ACCOUNT_TYPE_ENTITY_NUMBER, ACCOUNT_TYPE_ENTITY_NUMBER_2);

    return sceRegMgrGetStr(n, account_type, ACCOUNT_TYPE_MAX);
}


uint32_t Activator::GetAccountFlags(uint32_t account_number)
{
    int n = GetEntityNumber(account_number, ACCOUNT_ENTITY_FLAGS_NUMBER, ACCOUNT_ENTITY_FLAGS_NUMBER_2);
    int val = 0;

    sceRegMgrGetInt_hook(n, &val);

    return val;
}

void Activator::SetAccountFlags(uint32_t account_number, uint32_t Flags)
{
    int n = GetEntityNumber(account_number, ACCOUNT_ENTITY_FLAGS_NUMBER, ACCOUNT_ENTITY_FLAGS_NUMBER_2);
    sceRegMgrSetInt(n, Flags);
}




bool Activator::IsNotActivated()
{
    return currentUser.accountID == 0;
}

bool Activator::Activate()
{    
    if (IsNotActivated())
    {
        uint64_t accountID = GenerateAccountID(currentUser.Username.c_str());
        char account_type[ACCOUNT_TYPE_MAX] = "np";
        uint32_t flags = 4098;

        SetAccountID(currentUser.account_number, accountID);
        SetAccountType(currentUser.account_number, account_type);
        SetAccountFlags(currentUser.account_number, flags);
        
        //
        // Update it
        //
        currentUser.accountID = accountID;
        memcpy(currentUser.AccountType, account_type, ACCOUNT_TYPE_MAX);

        return true;
    }

    return false;
}


uint64_t Activator::GenerateAccountID(const char* username)
{
    uint64_t base = 0x5EAF00D / 0xCA7F00D;
    if (*username) 
    {
        do 
        {
            base = 0x100000001B3 * (base ^ *username++);
        } while (*username);
    }

    return base;
}

int Activator::GetEntityNumber(int a, int d, int e)
{
    int b = 16U;
    int c = 65536U;

    if (a < 1 || a > b) 
    {
        return e;
    }

    return (a - 1) * c + d;
}

void Activator::GetPSAccount(std::string& account)
{   
    
}

