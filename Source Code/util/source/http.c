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
#include <curl/curl.h>

#define NET_HEAP_SIZE	(32 * 1024)
#define MAX_CONCURRENT_REQUEST	(4)
#define PRIVATE_CA_CERT_NUM		(0)
#define COMMIT_HASH_FILE "/data/etaHEN/cheat_commit_hash.txt"
#define GITHUB_API_URL "https://api.github.com/repos/etaHEN/PS5_Cheats/commits"

uint64_t sceKernelGetProcessTime(void);

// Structure for download progress tracking
struct download_progress {
    int fd;
    uint64_t last_notify_time;
    const uint64_t notify_interval;
    const char* filename;
};

// Structure for JSON download
struct json_data {
    char* data;
    size_t size;
    size_t capacity;
};

bool IniliatizeHTTP() {
    CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (res != CURLE_OK) {
        etaHEN_log("curl_global_init() error: %s", curl_easy_strerror(res));
        return false;
    }

	etaHEN_log("cURL initialized successfully, version %s", curl_version());
    return true;
}

// Callback function to write downloaded data to file
static size_t write_file_callback(void* contents, size_t size, size_t nmemb, void* userdata) {
    struct download_progress* progress = (struct download_progress*)userdata;
    size_t real_size = size * nmemb;

    ssize_t written = sceKernelWrite(progress->fd, contents, real_size);
    if (written != real_size) {
        etaHEN_log("sceKernelWrite() error: written %ld, expected %zu", written, real_size);
        return 0; // This will cause curl to abort
    }

    return real_size;
}

// Progress callback for file downloads
static int progress_callback(void* clientp, curl_off_t dltotal, curl_off_t dlnow,
    curl_off_t ultotal, curl_off_t ulnow) {
    struct download_progress* progress = (struct download_progress*)clientp;
    uint64_t current_time = sceKernelGetProcessTime();

    // Check if we should notify
    if (current_time - progress->last_notify_time >= progress->notify_interval) {
        char notifyMsg[256];
        float dlnow_mb = (float)dlnow / (1024 * 1024);

        if (dltotal > 0) {
            float dltotal_mb = (float)dltotal / (1024 * 1024);
            int percent = (int)(((float)dlnow / dltotal) * 100);

            snprintf(notifyMsg, sizeof(notifyMsg),
                "Downloading the cheats repo:..\n%.1f/%.1f MB (%d%%)",
                dlnow_mb, dltotal_mb, percent);
        }
        else {
            snprintf(notifyMsg, sizeof(notifyMsg),
                "Downloading the cheats repo...\n%.1f MB Downloaded",
                dlnow_mb);
        }

        notify(true, notifyMsg);
        progress->last_notify_time = current_time;
    }

    return 0; // Return 0 to continue
}

bool download_file(const char* url, const char* dst) {
    CURL* curl;
    CURLcode res;
    bool success = false;
	char notifyMsg[1000];

    const char* filename = strrchr(dst, '/');
    filename = filename ? filename + 1 : dst; // Get just the filename without the path

    // Remove destination file if it exists
    unlink(dst);

    // Open file for writing
    int fd = sceKernelOpen(dst, O_WRONLY | O_CREAT, 0777);
    if (fd < 0) {
        etaHEN_log("Failed to open destination file: %s (error: 0x%08X)", dst, fd);
        return false;
    }

    // Initialize progress structure
    struct download_progress progress = {
        .fd = fd,
        .last_notify_time = sceKernelGetProcessTime(),
        .notify_interval = 6 * 1000000, // 6 seconds in microseconds
        .filename = strrchr(dst, '/') ? strrchr(dst, '/') + 1 : dst
    };

    // Initialize curl
    curl = curl_easy_init();
    if (!curl) {
        etaHEN_log("curl_easy_init() failed");
        sceKernelClose(fd);
        return false;
    }

    // Initial notification
    etaHEN_log("Downloading %s to %s", url, dst);

    // Set curl options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &progress);
    curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress_callback);
    curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, &progress);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, TEST_USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // Skip SSL verification
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L); // 5 minute timeout

    // Perform the request
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        etaHEN_log("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        notify(true, "Failed to download the %s!\n\nCheck your internet connection and try again.\nError: %s", filename, curl_easy_strerror(res));
    }
    else {
        // Check HTTP response code
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        etaHEN_log("Response status code: %ld", response_code);

        if (response_code == 200) {
            // Get download size info
            curl_off_t download_size;
            curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &download_size);

            snprintf(notifyMsg, sizeof(notifyMsg),
                "Successfully downloaded the %s\nTotal Size: %.1f MB", filename,
                (float)download_size / (1024 * 1024));
            notify(true, notifyMsg);
            etaHEN_log("Download complete: %lld bytes", download_size);
            success = true;
        }
        else {
            etaHEN_log("HTTP error: unexpected status code %ld", response_code);
            notify(true, "Failed to download the %s!\n\nServer returned an error.", filename);
        }
    }

    // Cleanup
    curl_easy_cleanup(curl);
    sceKernelClose(fd);

    return success;
}

// Callback function to write JSON data to memory
static size_t write_json_callback(void* contents, size_t size, size_t nmemb, void* userdata) {
    struct json_data* json = (struct json_data*)userdata;
    size_t real_size = size * nmemb;

    // Resize buffer if needed
    if (json->size + real_size >= json->capacity) {
        size_t new_capacity = json->capacity * 2;
        if (new_capacity < json->size + real_size + 1) {
            new_capacity = json->size + real_size + 1;
        }

        char* new_data = realloc(json->data, new_capacity);
        if (!new_data) {
            etaHEN_log("Failed to reallocate memory for JSON data");
            return 0; // This will cause curl to abort
        }

        json->data = new_data;
        json->capacity = new_capacity;
    }

    // Copy data
    memcpy(json->data + json->size, contents, real_size);
    json->size += real_size;
    json->data[json->size] = '\0'; // Null terminate

    return real_size;
}

// Function to download JSON data from URL
static char* download_json(const char* url) {
    CURL* curl;
    CURLcode res;
    char* result = NULL;

    // Initialize JSON data structure
    struct json_data json = {
        .data = malloc(1024),
        .size = 0,
        .capacity = 1024
    };

    if (!json.data) {
        etaHEN_log("Failed to allocate initial memory for JSON data");
        return NULL;
    }

    json.data[0] = '\0';

    // Initialize curl
    curl = curl_easy_init();
    if (!curl) {
        etaHEN_log("curl_easy_init() failed");
        free(json.data);
        return NULL;
    }

    // Set curl options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_json_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &json);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, TEST_USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // Skip SSL verification
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L); // 30 second timeout

    // Perform the request
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        etaHEN_log("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        free(json.data);
    }
    else {
        // Check HTTP response code
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        if (response_code == 200) {
            etaHEN_log("Downloaded %zu bytes of JSON data", json.size);
            result = json.data; // Return the data
        }
        else {
            etaHEN_log("HTTP error: unexpected status code %ld", response_code);
            free(json.data);
        }
    }

    // Cleanup
    curl_easy_cleanup(curl);

    return result;
}

// Function to create directory if it doesn't exist
static void ensure_directory(const char* path) {
    struct stat st = { 0 };
    if (stat(path, &st) == -1) {
        mkdir(path, 0755);
    }
}

// Simple function to extract a zip file
bool extract_zip(const char* zip_path, const char* extract_dir) {
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
    const char* zip_filename = strrchr(zip_path, '/');
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
    char root_folder[256] = { 0 };
    int root_folder_len = 0;

    // Get the root folder name (first entry)
    unz_file_info file_info;
    unzGetCurrentFileInfo(zip, &file_info, filename, sizeof(filename), NULL, 0, NULL, 0);
    char* first_slash = strchr(filename, '/');
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
        char* actual_filename = filename;
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

        // Create directories in the path
        char* last_slash = strrchr(full_path, '/');
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
            write(out, buffer, bytes);
        }

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