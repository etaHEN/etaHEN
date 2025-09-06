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
#include "AccountActivator.h"
#include <pthread.h>

extern void notify(const char* text, ...);
extern bool IsRunningConfirmRegistLoop; 

void Base64Encode(uint64_t input, char* output);
void InitRemotePlay();
uint32_t GeneratePINCode();
void GetEncodedAccountID(char* buff, uint64_t &accountid);
void StopConfirmRegistLoop();
void ConfirmRegistLoop();
bool IsNotActivated();