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

#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#define XOR_KEY "5nsWTJebELBNNXKx52Y8mDW8xksBVTNF"  // Define your own XOR key
#define BUFFER_SIZE 1024
#define PREFIX "etaHEN Console Code: "

extern "C" void notify(const char *text, ...);

// Function to decrypt data using XOR encryption
void decrypt_xor(char *data, size_t data_len, const char *key, size_t key_len) {
    for (size_t i = 0; i < data_len; ++i) {
        data[i] ^= key[i % key_len];
    }
}

// Function to read and decrypt the console code
bool read_and_decrypt_code(int file_fd, char* output_buffer, size_t buffer_size) {
    unsigned char encrypted_data[BUFFER_SIZE];
    memset(encrypted_data, 0, sizeof(encrypted_data));

    // Read the encrypted console code from the file
    size_t bytes_read = read(file_fd, encrypted_data, sizeof(encrypted_data));
    if (bytes_read == (size_t)-1) {
        perror("Failed to read data");
        close(file_fd);
        return false;
    }

    close(file_fd);

    if (bytes_read < strlen(PREFIX)) {
        printf("Data too short to contain valid prefix\n");
        return false;
    }

    // Check if the data contains the expected prefix
    if (strncmp((char*)encrypted_data, PREFIX, strlen(PREFIX)) != 0) {
        printf("Invalid prefix or data format\n");
        return false;
    }

    // Find the position after the prefix
    unsigned char* encrypted_code = encrypted_data + strlen(PREFIX);
    size_t encrypted_code_len = bytes_read - strlen(PREFIX);

    // Decrypt the part after the prefix
    decrypt_xor((char*)encrypted_code, encrypted_code_len, XOR_KEY, strlen(XOR_KEY));

    // Check buffer size
    if (encrypted_code_len >= buffer_size) {
        printf("Output buffer is too small\n");
        return false;
    }

    // Copy the decrypted code to the output buffer, ensuring not to exceed the buffer size
    memcpy(output_buffer, encrypted_code, encrypted_code_len);
    output_buffer[encrypted_code_len] = '\0'; // Ensure null-termination if buffer allows

    printf("Decrypted output: %s\n", output_buffer);

    return true;
}
bool GetDecryptedConsoleCode(char* encrypted_codee) {
    int fd = open("/mnt/usb0/etaHEN_approval.bin", 0, 0);
    if (fd < 0) {
        //notify("Failed to open approval file from USB0 with error code %d (%s)", fd, strerror(errno));
        fd = open("/mnt/usb1/etaHEN_approval.bin", 0, 0);
        if (fd < 0) {
            fd = ((open("/mnt/usb2/etaHEN_approval.bin", 0, 0) < 0 ) ? fd = open("/data/etaHEN_approval.bin", 0, 0) : fd);
            if (fd < 0) {
                printf("Failed to open approval file\n");
               // notify("Failed to open approval file from USB or /data");
                return false;
            }
        }
    }

    if (!read_and_decrypt_code(fd, encrypted_codee, 255)) {
        notify("Failed to read and decrypt console code");
        return false;
    }

    return true;
}

bool is_console_whitelisted(char* outbuf, const char* comp) {
  uint8_t s_PsId[16] = {
    0
  };

  size_t v2 = 16;
  if (sysctlbyname("machdep.openpsid_for_sys", & s_PsId, & v2, 0, 0) < 0) {
    printf("sceKernelGetOpenPsIdForSystem failed\n");
    return true;
  }

  char psid_buf[255] = {
    0
  };

  for (int i = 0; i < 16; i++) {
    snprintf(psid_buf + strlen(psid_buf), 255 - strlen(psid_buf), "%02x", s_PsId[i]);
  }

  const char * whitelisted_psids[] = {
 //   "b345df7d4c77618d40f19a90e438ad87",
    "ab535275b7196e7e7d43f4f9e7806724"
  };

  for (int i = 0; i < sizeof(whitelisted_psids) / sizeof(whitelisted_psids[0]); i++) {
    if (strcmp(psid_buf, whitelisted_psids[i]) == 0) {
      // printf("PSID (%s) whitelisted\n", psid_buf);
      return true;
    }
  }

   if (strcmp(psid_buf, comp) == 0) {
      // printf("PSID (%s) whitelisted\n", psid_buf);
    //  printf("etaHEN Console Code: %s : %s\n", psid_buf, comp);
      return true;
   }

 //  notify("etaHEN Console Code: %s : %s\n", psid_buf, comp);

 // printf("etaHEN Console Code: %s\n", psid_buf);
  snprintf(outbuf, 255, "etaHEN Console Code: %s", psid_buf);
  

  //printf("PSID (%s) Not whitelisted\n", psid_buf);
  return false;
}

/*
	printf("11/15 %s\n", isPastBetaDate(2024, 11, 15) ? "EXPIRED" : "NOT EXPIRED");

	printf("11/6 %s\n", isPastBetaDate(2024, 11, 6) ? "EXPIRED" : "NOT EXPIRED");

	printf("10/5/2019 %s\n", isPastBetaDate(2019, 10, 5) ? "EXPIRED" : "NOT EXPIRED");
	
	printf("10/5/2025 %s\n", isPastBetaDate(2025, 10, 5) ? "EXPIRED" : "NOT EXPIRED");

	printf("10/5/2000 %s\n", isPastBetaDate(2000, 10, 5) ? "EXPIRED" : "NOT EXPIRED");
*/


bool isPastBetaDate(int year, int month, int day) {
    // Current time
    time_t now;
    time(&now);
    localtime(&now);

    // Target time setup
    struct tm target_time = {0};
    target_time.tm_year = year - 1900;  // tm_year is year since 1900
    target_time.tm_mon = month - 1;     // tm_mon is month from 0 to 11
    target_time.tm_mday = day;
    target_time.tm_hour = 0;
    target_time.tm_min = 0;
    target_time.tm_sec = 0;

    // Convert target_time to time_t
    time_t target = mktime(&target_time);

    // Compare current time with target time
    return difftime(now, target) > 0;
}
