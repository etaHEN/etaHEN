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

#include <ps5/kernel.h>
#include <ps5/klog.h>
#include <stdint.h>
#include <sys/stat.h>

#include "elfldr.h"
#include "pt.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../../extern/7zip-sdk/C/LzmaLib.h"
#include <elf.h>
#include <unistd.h>

#define LZMA_CLI_HEADER_SIZE 13

typedef struct {
  int32_t type;             // 0x00
  int32_t req_id;           // 0x04
  int32_t priority;         // 0x08
  int32_t msg_id;           // 0x0C
  int32_t target_id;        // 0x10
  int32_t user_id;          // 0x14
  int32_t unk1;             // 0x18
  int32_t unk2;             // 0x1C
  int32_t app_id;           // 0x20
  int32_t error_num;        // 0x24
  int32_t unk3;             // 0x28
  char use_icon_image_uri;  // 0x2C
  char message[1024];       // 0x2D
  char uri[1024];           // 0x42D
  char unkstr[1024];        // 0x82D
} OrbisNotificationRequest; // Size = 0xC30

typedef struct {
  uint64_t pad0;
  char version_str[0x1C];
  uint32_t version;
  uint64_t pad1;
} OrbisKernelSwVersion;

/**
 * sceKernelSpawn() is not available in libkernel_web, which is what is used by
 * the webkit exploit entry point. However, we do not actually use it initially,
 * hence we just define an empty stub to silence the linker.
 **/
int sceKernelSpawn(int *pid, int dbg, const char *path, char *root,
                   char *argv[]) {
  return -1;
}

int sceKernelSendNotificationRequest(int32_t device,
                                     OrbisNotificationRequest *req, size_t size,
                                     int32_t blocking);
int sceKernelGetProsperoSystemSwVersion(OrbisKernelSwVersion *sw);

void notify(const char *text, ...) {
  OrbisNotificationRequest req;
  va_list args;

  // Process args
  va_start(args, text);
  vsnprintf(req.message, sizeof(req.message), text, args);
  va_end(args);

  req.type = 0;
  req.unk3 = 0;
  req.use_icon_image_uri = 1;
  req.target_id = -1;
  snprintf(req.uri, sizeof(req.uri), "cxml://psnotification/tex_icon_system");

  printf("Notify: %s\n", req.message);
  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

__asm__(".intel_syntax noprefix\n"
        ".section .data\n"
        ".global etahen_compressed\n"
        ".type   etahen_compressed, @object\n"
        ".align  16\n"
        "etahen_compressed:\n"
        ".incbin \"../../bin/bootstrapper.elf.lzma\"\n"
        "etahen_compressed_end:\n"
        ".global etahen_compressed_size\n"
        ".type  etahen_compressed_size, @object\n"
        ".align  4\n"
        "etahen_compressed_size:\n"
        ".int    etahen_compressed_end - etahen_compressed\n"
        ".global etahen_decompressed_size\n"
        ".type   etahen_decompressed_size, @object\n"
        ".align  16\n"
        "etahen_decompressed_size:\n"
        ".incbin \"../../bin/bootstrapper.elf.lzma.size\"\n");

extern uint32_t etahen_compressed_size;
extern uint8_t etahen_compressed[];
extern uint8_t etahen_compressed_end[];
extern uint8_t etahen_decompressed_size[];

int main() {

  pid_t mypid = getpid();
  uint8_t qa_flags[16];
  uint8_t caps[16];
  uint64_t authid;
  intptr_t vnode;
  pid_t vpid;

  OrbisKernelSwVersion sys_ver;
  sceKernelGetProsperoSystemSwVersion(&sys_ver);

  if (etahen_compressed_size <= 0) {
    printf("Invalid etaHEN payload! unable to unpack it!");
    return 0;
  }

  size_t decompress_size = atoi((char *)etahen_decompressed_size);
  // printf("Decompressed size: %zu bytes\nCompressed: %d\n", size,
  // etahen_compressed_size); printf("Payload has %d bytes, decompressing...\n",
  // etahen_compressed_size);
  uint8_t *decompressed = (uint8_t *)malloc(decompress_size);
  if (!decompressed) {
    notify("Failed to allocate memory for decompressed etaHEN payload!");
    return -1;
  }
  size_t size = decompress_size;
  size_t srcLen = etahen_compressed_size;

  //
  // The PROPS used by the LZMA is located at the first 5 bytes of the file, the
  // size of the whole LZMA cli header is 13 bytes we skip it to get the real
  // compressed data
  //
  int res = LzmaUncompress(decompressed, &size,
                           etahen_compressed + LZMA_CLI_HEADER_SIZE, &srcLen,
                           etahen_compressed, LZMA_PROPS_SIZE);
  if (res != 0) {
    notify("Failed to decompress etaHEN payload! error: %d", res);
    free(decompressed);
    return -1;
  }

  puts("Bootstrapping etaHEN.elf...");

  mkdir("/data/etaHEN", 0777);
  // create the payload for exiting lite mode via Johns elf loader
  int fd = open("/data/etaHEN/etaHEN.bin", O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (fd >= 0) {

    // Write the buffer to the file
    if (write(fd, decompressed, decompress_size) == -1) {
      perror("write failed");
    }

    // Close the file descriptor
    close(fd);
  }

  if ((sys_ver.version >> 16) < 0x700) {
    // enable debugging with ptrace
    if (kernel_get_qaflags(qa_flags)) {
      notify("kernel_get_qa_flags failed");
      return -1;
    }
    qa_flags[1] |= 0x03;
    if (kernel_set_qaflags(qa_flags)) {
      notify("kernel_set_qa_flags failed");
      return -1;
    }
  }

  // backup my privileges
  if (!(vnode = kernel_get_proc_rootdir(mypid))) {
    notify("kernel_get_proc_rootdir failed");
    return -1;
  }

  if (kernel_get_ucred_caps(mypid, caps)) {
    notify("kernel_get_ucred_caps failed");
    return -1;
  }
  if (!(authid = kernel_get_ucred_authid(mypid))) {
    notify("kernel_get_ucred_authid failed");
    return -1;
  }

  // launch bootstrap.elf inside SceRedisServer
  if ((vpid = elfldr_find_pid("SceRedisServer")) < 0) {
    notify("elfldr_find_pid failed");
    return -1;
  } else if (elfldr_raise_privileges(mypid)) {
    notify("Unable to raise privileges");
    return -1;
  } else if (pt_attach(vpid)) {
    notify("pt_attach");
    return -1;
  } else {
    if (elfldr_exec(vpid, STDOUT_FILENO, decompressed) != 0) {
      notify("etaHEN failed to start: ELF");
      return -1;
    }
  }

  // restore my privileges
  if (kernel_set_proc_jaildir(mypid, vnode)) {
    notify("kernel_set_proc_jaildir failed");
    return -1;
  }
  if (kernel_set_proc_rootdir(mypid, vnode)) {
    notify("kernel_set_proc_rootdir failed");
    return -1;
  }
  if (kernel_set_ucred_caps(mypid, caps)) {
    notify("kernel_set_ucred_caps failed");
    return -1;
  }
  if (kernel_set_ucred_authid(mypid, authid)) {
    notify("kernel_set_ucred_authid failed");
    return -1;
  }

  free(decompressed);

  return 0;
}
