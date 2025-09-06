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

#include "RemotePlay.h"

bool IsRunningConfirmRegistLoop = false;
pthread_t ConfirmRegistLoop_Thread;

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void Base64Encode(uint64_t input, char* output)
{
    // Convert uint64_t to byte array
    unsigned char bytes[8];
    for (int i = 0; i < 8; i++) {
        bytes[i] = (input >> (i * 8)) & 0xFF;
    }
    
    int i = 0, j = 0;
    
    // Process all bytes in groups of 3
    while (i < 8) {
        uint32_t octet_a = i < 8 ? bytes[i++] : 0;
        uint32_t octet_b = i < 8 ? bytes[i++] : 0;
        uint32_t octet_c = i < 8 ? bytes[i++] : 0;
        
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        
        output[j++] = base64_table[(triple >> 18) & 0x3F];
        output[j++] = base64_table[(triple >> 12) & 0x3F];
        output[j++] = base64_table[(triple >> 6) & 0x3F];
        output[j++] = base64_table[triple & 0x3F];
    }
    
    // Add padding
    for (int k = 0; k < (3 - 8 % 3) % 3; k++) {
        output[j - k - 1] = '=';
    }
    
    output[j] = '\0';
}
    

void InitRemotePlay()
{    
    int rp_enable = 0, err = 0;
    if ((err = sceRegMgrGetInt_hook(REMOTE_PLAY_ENABLE_REGISTRY, &rp_enable)))
    {
      notify("SCE_REGMGR: unable to get REMOTEPLAY_rp_enable (0x%x)", err);
    }
    else if (rp_enable != 1)
    {
      rp_enable = 1;
      if ((err = sceRegMgrSetInt(REMOTE_PLAY_ENABLE_REGISTRY, rp_enable)))
      {
        notify("SCE_REGMGR: unable to set REMOTEPLAY_rp_enable (0x%x)", err);
      }
      notify("[DEBUG] set regkey");
    }

    sceRemoteplayInitialize(0, 0);
}


uint32_t GeneratePINCode()
{
    uint32_t pin;
    //
    // invalidate any previous PIN
    //
    sceRemoteplayNotifyPinCodeError(1);
    //
    // Generate PIN
    //
    sceRemoteplayGeneratePinCode(&pin);
    //
    // Run loop to accept new registration
    //

    StopConfirmRegistLoop();
    pthread_create(&ConfirmRegistLoop_Thread, NULL, (void *(*)(void *))ConfirmRegistLoop, NULL);

    return pin;
}


void StopConfirmRegistLoop()
{
    if (IsRunningConfirmRegistLoop)
    {
        IsRunningConfirmRegistLoop = false;
        void* retval;
        pthread_join(ConfirmRegistLoop_Thread, &retval);
    }
}


void GetEncodedAccountID(char* buff, uint64_t &accountid)
{
    Activator activator(true);

    if (activator.IsNotActivated())
    {
        activator.Activate();
    }

    Base64Encode(activator.currentUser.accountID, buff);
    accountid = activator.currentUser.accountID;
}


void ConfirmRegistLoop()
{
    IsRunningConfirmRegistLoop = true;
    int pair_stat = -1, pair_err = -1, err = -1;

    while(IsRunningConfirmRegistLoop)
    {
        if((err=sceRemoteplayConfirmDeviceRegist(&pair_stat, &pair_err))) {
            notify("sceRemoteplayConfirmDeviceRegist 0x%X pair_stat: %d pair_err: %d\n", err, pair_stat, pair_err);
            break;
        }    
        else if (pair_stat == 2) {
            notify("Remote Play paired! For a better stability a reboot is recommended");
            break;
        }
    }

    IsRunningConfirmRegistLoop = false;
}


bool IsNotActivated()
{
    Activator activator(true);

    return activator.IsNotActivated();
}