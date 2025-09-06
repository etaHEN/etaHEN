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

#include "common_utils.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <libhttp2.h>
#include <minizip/unzip.h>
#include "../extern/tiny-json/tiny-json.hpp"

#define TEST_USER_AGENT "etaHEN_Downloader"

#define NET_HEAP_SIZE	(32 * 1024)
#define MAX_CONCURRENT_REQUEST	(4)
#define PRIVATE_CA_CERT_NUM		(0)
#define SSL_HEAP_SIZE	((((MAX_CONCURRENT_REQUEST-1) / 3) +1)*256*1024 + 4*1024*PRIVATE_CA_CERT_NUM)
#define HTTP2_HEAP_SIZE	((((MAX_CONCURRENT_REQUEST-1) / 3) +1)*256*1024)
#define COMMIT_HASH_FILE "/data/etaHEN/cheats/cheat_commit_hash.txt"
#define GITHUB_API_URL "https://api.github.com/repos/etaHEN/PS5_Cheats/commits"

uint64_t sceKernelGetProcessTime(void);

int libnetMemId = 0, libsslCtxId = 0, libhttp2CtxId = 0;


int netInit(void) {

  /* libnet */
  int ret = sceNetInit();
  ret = sceNetPoolCreate("simple", NET_HEAP_SIZE, 0);
  libnetMemId = ret;

  return libnetMemId;
}

bool IniliatizeHTTP() {

  int ret = netInit();
  if (ret < 0){
    etaHEN_log("netInit() error: 0x%08X", ret);
    return false;
  }

  ret = sceSslInit(SSL_HEAP_SIZE);
  if (ret < 0){
    etaHEN_log("sceSslInit() error: 0x%08X", ret);
    return false;
  }

  libsslCtxId = ret;

  etaHEN_log("libsslCtxId = %x", libsslCtxId);

  ret = sceHttp2Init(libnetMemId, libsslCtxId, HTTP2_HEAP_SIZE, MAX_CONCURRENT_REQUEST);
  if (ret < 0){
    etaHEN_log("sceHttpInit() error: 0x%08X", ret);
    return false;
  }

  libhttp2CtxId = ret;

  return true;
}

static int skipSSLCallback(int libsslCtxId,
	unsigned int verifyErr,
	void * const sslCert[],
	int certNum,
	void *userArg
) {

  etaHEN_log("skipSSLCallback() called");
  return 0;
}

bool download_file(const char* url, const char* dst)
{
    int ret = -1;
    int libhttp2TmplId = -1;
    int reqId = -1;
    int statusCode = -1;
    int contentLengthType = -1;
    uint64_t contentLength = 0;
    bool success = false;
    
    // For notification timing
    uint64_t last_notify_time = 0;
    uint64_t current_time = 0;
    const uint64_t notify_interval = 6 * 1000000; // 6 seconds in microseconds
    
    // Remove destination file if it exists
    unlink(dst);
    
    // Create HTTP template
    libhttp2TmplId = sceHttp2CreateTemplate(libhttp2CtxId, TEST_USER_AGENT, 
                                          SCE_HTTP2_VERSION_2_0, true);
    if (libhttp2TmplId < 0) {
        etaHEN_log("sceHttp2CreateTemplate() error: 0x%08X", libhttp2TmplId);
        goto error;
    }
    
    // Disable SSL options if needed
    ret = sceHttp2SetSslCallback(libhttp2TmplId, skipSSLCallback, NULL);
    if (ret < 0) {
        etaHEN_log("sceHttp2SslDisableOption() error: 0x%08X", ret);
        goto error;
    }
    
    // Create HTTP request
    ret = sceHttp2CreateRequestWithURL(libhttp2TmplId, "GET", url, 0);
    if (ret < 0) {
        etaHEN_log("sceHttp2CreateRequestWithURL() error: 0x%08X", ret);
        goto error;
    }
    reqId = ret;
    
    // Send the request
    ret = sceHttp2SendRequest(reqId, NULL, 0);
    if (ret < 0) {
        etaHEN_log("sceHttp2SendRequest() error: 0x%08X", ret);
        goto error;
    }
    
    // Get status code
    ret = sceHttp2GetStatusCode(reqId, &statusCode);
    if (ret < 0) {
        etaHEN_log("sceHttp2GetStatusCode() error: 0x%08X", ret);
        goto error;
    }
    etaHEN_log("Response status code: %d", statusCode);
    
    if (statusCode != 200) {
        etaHEN_log("HTTP error: unexpected status code %d", statusCode);
        goto error;
    }
    
    // Get content length
    ret = sceHttp2GetResponseContentLength(reqId, &contentLengthType, &contentLength);
    if (ret < 0) {
        etaHEN_log("sceHttp2GetResponseContentLength() error: 0x%08X", ret);
        goto error;
    }
    
    if (contentLengthType == SCE_HTTP2_CONTENTLEN_EXIST) {
        etaHEN_log("Content-Length: %llu bytes", contentLength);
    } else {
        etaHEN_log("Content-Length not available");
    }
    
    // Open file for writing
    int fd = sceKernelOpen(dst, O_WRONLY | O_CREAT, 0777);
    if (fd < 0) {
        etaHEN_log("Failed to open destination file: %s (error: 0x%08X)", dst, fd);
        goto error;
    }
    
    // Initialize progress display
    etaHEN_log("Downloading %s to %s", url, dst);
    etaHEN_log("Progress: 0%%");
    
    // Initial notification
    char notifyMsg[256];
    const char *filename = strrchr(dst, '/');
    filename = filename ? filename + 1 : dst; // Get just the filename without the path
    
    snprintf(notifyMsg, sizeof(notifyMsg), "Downloading the latest cheats repo ...");
    notify(true, notifyMsg);
    
    // Get current time for notification timing
    last_notify_time = sceKernelGetProcessTime();
    
    // Read data and write to file
    char buf[4096];
    int total_read = 0;
    
    while (true) {
        int read = sceHttp2ReadData(reqId, buf, sizeof(buf));
        if (read < 0) {
            etaHEN_log("sceHttp2ReadData() error: 0x%08X", read);
            sceKernelClose(fd);
            goto error;
        }
        
        if (read == 0) {
            // Download complete
            etaHEN_log("Download complete: %d bytes", total_read);
            break;
        }
        
        ret = sceKernelWrite(fd, buf, read);
        if (ret < 0 || ret != read) {
            etaHEN_log("sceKernelWrite() error: 0x%08X", ret);
            sceKernelClose(fd);
            goto error;
        }
        
        total_read += read;
        
        // Get current time to check if we should notify
        current_time = sceKernelGetProcessTime();
        
        // Update progress and check for notification interval
        if (current_time - last_notify_time >= notify_interval) {
            // Format size in a readable way
            float total_mb = (float)total_read / (1024 * 1024);
            
            if (contentLengthType == SCE_HTTP2_CONTENTLEN_EXIST && contentLength > 0) {
                float total_size_mb = (float)contentLength / (1024 * 1024);
                int progress = (int)(((float)total_read / contentLength) * 100);
                
                snprintf(notifyMsg, sizeof(notifyMsg), 
                         "Downloading the cheats repo:..\n%.1f/%.1f MB (%d%%)", 
                         total_mb, total_size_mb, progress);
            } else {
                snprintf(notifyMsg, sizeof(notifyMsg), 
                         "Downloading the cheats repo...\n%.1f MB Downloaded", 
                         total_mb);
            }
            
            notify(true, notifyMsg);
            last_notify_time = current_time;
        }
    }
    
    // Final notification
    snprintf(notifyMsg, sizeof(notifyMsg), 
             "Successfully downloaded the cheats repo\nTotal Size: %.1f MB", 
             (float)total_read / (1024 * 1024));
    notify(true, notifyMsg);
    
    etaHEN_log("Download complete: %d bytes", total_read);
    sceKernelClose(fd);
    success = true;
    
error:
    // Clean up resources
    if (reqId > 0) {
        int tmpRet = sceHttp2DeleteRequest(reqId);
        if (tmpRet < 0) {
            etaHEN_log("sceHttp2DeleteRequest() error: 0x%08X", tmpRet);
        }
    }
    
    if (libhttp2TmplId > 0) {
        int tmpRet = sceHttp2DeleteTemplate(libhttp2TmplId);
        if (tmpRet < 0) {
            etaHEN_log("sceHttp2DeleteTemplate() error: 0x%08X", tmpRet);
        }
    }
    
    if (!success) {
        // Notify on error
        notify(true, "Failed to download the cheats repo!\n\nCheck your internet connection and try again.");
    }
    
    return success;
}

// Function to create directory if it doesn't exist
static void ensure_directory(const char *path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        mkdir(path, 0755);
    }
}
// Simple function to extract a zip file
bool extract_zip(const char *zip_path, const char *extract_dir) {
    unzFile zip = unzOpen(zip_path);
    if (!zip) {
        etaHEN_log("Failed to open zip file: %s", zip_path);
        notify(true, "Failed to open zip file");
        return false;
    }
    
    ensure_directory(extract_dir);
    
    // Go to the first file
    if (unzGoToFirstFile(zip) != UNZ_OK) {
        etaHEN_log("Empty zip file");
        unzClose(zip);
        notify(true, "Empty zip file");
        return false;
    }
    
    // For notification timing
    uint64_t last_notify_time = 0;
    uint64_t current_time = 0;
    const uint64_t notify_interval = 6 * 1000000; // 6 seconds in microseconds
    
    // Count total files for progress reporting
    int total_files = 0;
    int processed_files = 0;
    
    // First pass - count files
    do {
        total_files++;
    } while (unzGoToNextFile(zip) == UNZ_OK);
    
    // Reset to first file
    unzGoToFirstFile(zip);
    
    // Extract the zip filename for notifications
    const char *zip_filename = strrchr(zip_path, '/');
    zip_filename = zip_filename ? zip_filename + 1 : zip_path;
    
    // Initial notification
    char notifyMsg[256];
    snprintf(notifyMsg, sizeof(notifyMsg), "Preparing to extract the cheats repo (%d files)", total_files);
    notify(true, notifyMsg);
    etaHEN_log("%s", notifyMsg);
    
    // Get current time for notification timing
    last_notify_time = sceKernelGetProcessTime();
    
    char filename[512];
    char full_path[1024];
    int skip_root = 1;  // Flag to skip the root GitHub folder
    char root_folder[256] = {0};
    int root_folder_len = 0;
    
    // Get the root folder name (first entry)
    unz_file_info file_info;
    unzGetCurrentFileInfo(zip, &file_info, filename, sizeof(filename), NULL, 0, NULL, 0);
    char *first_slash = strchr(filename, '/');
    if (first_slash) {
        root_folder_len = first_slash - filename + 1;
        strncpy(root_folder, filename, root_folder_len);
        root_folder[root_folder_len] = '\0';
        etaHEN_log("Detected root folder: %s", root_folder);
    }
    
    // Reset to the first file
    unzGoToFirstFile(zip);
    
    do {
        unzGetCurrentFileInfo(zip, &file_info, filename, sizeof(filename), NULL, 0, NULL, 0);
        
        // Skip the root folder if needed
        char *actual_filename = filename;
        if (skip_root && root_folder_len > 0 && strncmp(filename, root_folder, root_folder_len) == 0) {
            actual_filename = filename + root_folder_len;
            if (strlen(actual_filename) == 0) {
                // Skip empty names (the root directory entry)
                continue;
            }
        }
        
        // Create the output path
        snprintf(full_path, sizeof(full_path), "%s/%s", extract_dir, actual_filename);
        
        // Check if this is a directory
        if (filename[strlen(filename) - 1] == '/') {
            etaHEN_log("Creating directory: %s", full_path);
            ensure_directory(full_path);
            processed_files++;
            continue;
        }
        
       // etaHEN_log("Extracting: %s", full_path);
        
        // Create directories in the path
        char *last_slash = strrchr(full_path, '/');
        if (last_slash) {
            *last_slash = '\0';
            ensure_directory(full_path);
            *last_slash = '/';
        }
        
        // Extract the file
        if (unzOpenCurrentFile(zip) != UNZ_OK) {
            etaHEN_log("Failed to open file in zip");
            continue;
        }
        
        // Open with POSIX open() instead of fopen()
        int out = open(full_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out == -1) {
            etaHEN_log("Failed to create output file: %s (error: %d)", full_path, errno);
            unzCloseCurrentFile(zip);
            continue;
        }
        
        char buffer[8192];
        int bytes;
        while ((bytes = unzReadCurrentFile(zip, buffer, sizeof(buffer))) > 0) {
            // Use write() instead of fwrite()
            write(out, buffer, bytes);
        }
        
        // Use close() instead of fclose()
        close(out);
        unzCloseCurrentFile(zip);
        
        // Increment processed files count
        processed_files++;
        
        // Check if it's time to show a notification
        current_time = sceKernelGetProcessTime();
        if (current_time - last_notify_time >= notify_interval) {
            int progress_percent = (processed_files * 100) / total_files;
            snprintf(notifyMsg, sizeof(notifyMsg), 
                     "Extracting the cheats: %d/%d files (%d%%)", 
                     processed_files, total_files, progress_percent);
            notify(true, notifyMsg);
            etaHEN_log("%s", notifyMsg);
            last_notify_time = current_time;
        }
        
    } while (unzGoToNextFile(zip) == UNZ_OK);
    
    // Final notification
    snprintf(notifyMsg, sizeof(notifyMsg), 
             "Cheats Extraction complete (%d files)", 
             processed_files);
    notify(true, notifyMsg);
    etaHEN_log("%s", notifyMsg);
    
    unzClose(zip);
    return true;
}

// Function to download JSON data from URL
static char* download_json(const char* url) {
    int ret = -1;
    int libhttp2TmplId = -1;
    int reqId = -1;
    int statusCode = -1;
    char* json_data = NULL;
    
    // Create HTTP template
    libhttp2TmplId = sceHttp2CreateTemplate(libhttp2CtxId, TEST_USER_AGENT, 
                                          SCE_HTTP2_VERSION_2_0, true);
    if (libhttp2TmplId < 0) {
        etaHEN_log("sceHttp2CreateTemplate() error: 0x%08X", libhttp2TmplId);
        goto error;
    }
    
    // Disable SSL callback
    ret = sceHttp2SetSslCallback(libhttp2TmplId, skipSSLCallback, NULL);
    if (ret < 0) {
        etaHEN_log("sceHttp2SslDisableOption() error: 0x%08X", ret);
        goto error;
    }
    
    // Create HTTP request
    ret = sceHttp2CreateRequestWithURL(libhttp2TmplId, "GET", url, 0);
    if (ret < 0) {
        etaHEN_log("sceHttp2CreateRequestWithURL() error: 0x%08X", ret);
        goto error;
    }
    reqId = ret;
    
    // Send the request
    ret = sceHttp2SendRequest(reqId, NULL, 0);
    if (ret < 0) {
        etaHEN_log("sceHttp2SendRequest() error: 0x%08X", ret);
        goto error;
    }
    
    // Get status code
    ret = sceHttp2GetStatusCode(reqId, &statusCode);
    if (ret < 0) {
        etaHEN_log("sceHttp2GetStatusCode() error: 0x%08X", ret);
        goto error;
    }
    
    if (statusCode != 200) {
        etaHEN_log("HTTP error: unexpected status code %d", statusCode);
        goto error;
    }
    
    // Allocate buffer for JSON data (32KB should be enough for commit info)
    const int buffer_size = 32768;
    json_data = (char*)malloc(buffer_size);
    if (!json_data) {
        etaHEN_log("Failed to allocate memory for JSON data");
        goto error;
    }
    
    // Read JSON data
    char buf[4096];
    int total_read = 0;
    
    while (total_read < buffer_size - 1) {
        int read = sceHttp2ReadData(reqId, buf, sizeof(buf));
        if (read < 0) {
            etaHEN_log("sceHttp2ReadData() error: 0x%08X", read);
            free(json_data);
            json_data = NULL;
            goto error;
        }
        
        if (read == 0) {
            break; // Download complete
        }
        
        // Make sure we don't overflow the buffer
        if (total_read + read >= buffer_size - 1) {
            read = buffer_size - 1 - total_read;
        }
        
        memcpy(json_data + total_read, buf, read);
        total_read += read;
        
        if (total_read >= buffer_size - 1) {
            break;
        }
    }
    
    json_data[total_read] = '\0';
    etaHEN_log("Downloaded %d bytes of JSON data", total_read);
    
error:
    // Clean up resources
    if (reqId > 0) {
        sceHttp2DeleteRequest(reqId);
    }
    
    if (libhttp2TmplId > 0) {
        sceHttp2DeleteTemplate(libhttp2TmplId);
    }
    
    return json_data;
}

// Function to extract SHA from JSON response
static bool extract_commit_sha(const char* json_data, char* sha_buffer, size_t buffer_size) {
    if (!json_data || !sha_buffer) {
        return false;
    }

    etaHEN_log("json_data %s", json_data);
    
    // Look for the first "sha" field in the JSON
    const char* sha_start = strstr(json_data, "\"sha\":");
    if (!sha_start) {
        etaHEN_log("Could not find 'sha' field in JSON response");
        return false;
    }
    
    // Move past "sha":
    sha_start += 6;
    
    // Skip whitespace and find the opening quote
    while (*sha_start == ' ' || *sha_start == '\t') {
        sha_start++;
    }
    
    if (*sha_start != '"') {
        etaHEN_log("Invalid JSON format - expected quote after 'sha':");
        return false;
    }
    
    sha_start++; // Skip the opening quote
    
    // Find the closing quote
    const char* sha_end = strchr(sha_start, '"');
    if (!sha_end) {
        etaHEN_log("Invalid JSON format - no closing quote for sha value");
        return false;
    }
    
    // Calculate length and copy
    size_t sha_length = sha_end - sha_start;
    if (sha_length >= buffer_size) {
        etaHEN_log("SHA too long for buffer");
        return false;
    }
    
    strncpy(sha_buffer, sha_start, sha_length);
    sha_buffer[sha_length] = '\0';
    
    etaHEN_log("Extracted commit SHA: %s", sha_buffer);
    return true;
}

// Function to read stored commit hash from file
static bool read_stored_commit_hash(char* hash_buffer, size_t buffer_size) {
    int fd = sceKernelOpen(COMMIT_HASH_FILE, O_RDONLY, 0);
    if (fd < 0) {
        etaHEN_log("No stored commit hash file found");
        return false;
    }
    
    int read_bytes = sceKernelRead(fd, hash_buffer, buffer_size - 1);
    sceKernelClose(fd);
    
    if (read_bytes <= 0) {
        etaHEN_log("Failed to read stored commit hash");
        return false;
    }
    
    hash_buffer[read_bytes] = '\0';
    
    // Remove any trailing newline or whitespace
    char* end = hash_buffer + strlen(hash_buffer) - 1;
    while (end > hash_buffer && (*end == '\n' || *end == '\r' || *end == ' ')) {
        *end = '\0';
        end--;
    }
    
    etaHEN_log("Read stored commit hash: %s", hash_buffer);
    return true;
}

// Function to write commit hash to file
static bool write_commit_hash(const char* hash) {
    int fd = sceKernelOpen(COMMIT_HASH_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        etaHEN_log("Failed to open commit hash file for writing: 0x%08X", fd);
        return false;
    }
    
    int written = sceKernelWrite(fd, hash, strlen(hash));
    sceKernelClose(fd);
    
    if (written != (int)strlen(hash)) {
        etaHEN_log("Failed to write commit hash to file");
        return false;
    }
    
    etaHEN_log("Stored new commit hash: %s", hash);
    return true;
}

// Main function to check for new commits
bool check_for_new_commit() {
    char* json_data = NULL;
    char latest_commit[64] = {0};
    char stored_commit[64] = {0};
    bool has_new_commit = false;
    
    etaHEN_log("Checking for new commits...");
    notify(true, "Checking for updates to the cheats repo...");
    
    // Download the latest commit information
    json_data = download_json(GITHUB_API_URL);
    if (!json_data) {
        etaHEN_log("Failed to download commit information from GitHub API");
        notify(true, "Failed to check the cheats repo for updates\nCheck your Connection and try again");
        return false;
    }
    
    // Extract the latest commit SHA
    if (!extract_commit_sha(json_data, latest_commit, sizeof(latest_commit))) {
        etaHEN_log("Failed to extract commit SHA from JSON response");
        notify(true, "Failed to parse update information\nUsing existing cheats repo");
        free(json_data);
        return false;
    }
    
    // Read the stored commit hash
    bool has_stored_hash = read_stored_commit_hash(stored_commit, sizeof(stored_commit));
    if (!has_stored_hash) {
        etaHEN_log("No stored commit hash - treating as new commit");
        has_new_commit = true;
    } else {
        // Compare the commits
        if (strcmp(latest_commit, stored_commit) != 0) {
            etaHEN_log("New commit detected: %s (was: %s)", latest_commit, stored_commit);
            has_new_commit = true;
        } else {
            etaHEN_log("No new commits - repo is up to date");
            has_new_commit = false;
        }
    }
    
    // If there's a new commit, store the new hash
    if (has_new_commit) {
        if (!write_commit_hash(latest_commit)) {
            etaHEN_log("Warning: Failed to store new commit hash");
        }
        notify(true, "New cheats update found!\nDownloading latest version...");
    } else {
        notify(true, "Cheats repo is up to date!");
    }
    
    free(json_data);
    return has_new_commit;
}