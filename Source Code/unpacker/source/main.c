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
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
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

int sceKernelSendNotificationRequest(int32_t device,
                                     OrbisNotificationRequest *req, size_t size,
                                     int32_t blocking);

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
        ".incbin \"../bin/bootstrapper.elf.lzma\"\n"
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
        ".incbin \"../bin/bootstrapper.elf.lzma.size\"\n");

extern uint32_t etahen_compressed_size;
extern uint8_t etahen_compressed[];
extern uint8_t etahen_compressed_end[];
extern uint8_t etahen_decompressed_size[];

bool send_to_elfldr(const void* buffer, size_t buffer_size) {
    int sockfd = -1;
    struct sockaddr_in server_addr;
    int bytes_sent = 0;
    int total_sent = 0;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("Failed to create socket: %d\n", sockfd);
        return false;
    }

    // Set socket options (optional - for faster reuse)
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Set up server address (always localhost)
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(9021);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("Failed to connect to localhost:9021\n");
        close(sockfd);
        return false;
    }

    printf("Connected to localhost:9021\n");

    // Send all data in the buffer
    const char* data_ptr = (const char*)buffer;
    while (total_sent < buffer_size) {
        bytes_sent = send(sockfd, data_ptr + total_sent, buffer_size - total_sent, 0);
        if (bytes_sent <= 0) {
            printf("Failed to send data: %d\n", bytes_sent);
            close(sockfd);
            return false;
        }
        total_sent += bytes_sent;
    }

    printf("Successfully sent %d bytes to localhost:9021\n", total_sent);

    // Close socket
    close(sockfd);

    return true;
}

int main() {

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

  if(!send_to_elfldr(decompressed, decompress_size)) {
    notify("The elfldr on port 9021 is REQUIRED for etaHEN make sure its running and try again!");
    free(decompressed);
    return -1;
  }

 
  free(decompressed);

  return 0;
}
