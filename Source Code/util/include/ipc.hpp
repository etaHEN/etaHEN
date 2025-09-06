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
#include <msg.hpp>
struct clientArgs {
    std::string ip;
    int socket;
    int cl_nmb;

};
extern bool show_notification;
#ifdef __cplusplus
#define restrict // Define restrict as empty for C++
#endif



void startMessageReceiver();
bool hasPrefixHandler(const uint32_t prefix) noexcept;
void* messageThread(void*);
bool GetFileContents(const char *path, char **buffer);