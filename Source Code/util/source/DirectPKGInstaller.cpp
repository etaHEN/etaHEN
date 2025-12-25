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

#include <string>
#include <pthread.h>
#include "error_translator.hpp"
extern "C" {
#include "common_utils.h"
#include <dirent.h>
#include <microhttpd.h>
#include <signal.h>
}

struct MHD_Daemon *httpd = NULL;
int srvfd = -1;
void notify(bool show_watermark, const char *text, ...);
pthread_t pkg_installer_thread, pkg_installer_thread_v2;
enum AppInstErrorCodes {
  SCE_APP_INSTALLER_ERROR_UNKNOWN = -2136801279,
  SCE_APP_INSTALLER_ERROR_NOSPACE,
  SCE_APP_INSTALLER_ERROR_PARAM,
  SCE_APP_INSTALLER_ERROR_APP_NOT_FOUND,
  SCE_APP_INSTALLER_ERROR_DISC_NOT_INSERTED,
  SCE_APP_INSTALLER_ERROR_PKG_INVALID_DRM_TYPE,
  SCE_APP_INSTALLER_ERROR_OUT_OF_MEMORY,
  SCE_APP_INSTALLER_ERROR_APP_BROKEN,
  SCE_APP_INSTALLER_ERROR_PKG_INVALID_CONTENT_TYPE,
  SCE_APP_INSTALLER_ERROR_USED_APP_NOT_FOUND,
  SCE_APP_INSTALLER_ERROR_ADDCONT_BROKEN,
  SCE_APP_INSTALLER_ERROR_APP_IS_RUNNING,
  SCE_APP_INSTALLER_ERROR_SYSTEM_VERSION,
  SCE_APP_INSTALLER_ERROR_NOT_INSTALL,
  SCE_APP_INSTALLER_ERROR_CONTENT_ID_DISAGREE,
  SCE_APP_INSTALLER_ERROR_NOSPACE_KERNEL,
  SCE_APP_INSTALLER_ERROR_APP_VER,
  SCE_APP_INSTALLER_ERROR_DB_DISABLE,
  SCE_APP_INSTALLER_ERROR_CANCELED,
  SCE_APP_INSTALLER_ERROR_ENTRYDIGEST,
  SCE_APP_INSTALLER_ERROR_BUSY,
  SCE_APP_INSTALLER_ERROR_DLAPP_ALREADY_INSTALLED,
  SCE_APP_INSTALLER_ERROR_NEED_ADDCONT_INSTALL,
  SCE_APP_INSTALLER_ERROR_APP_MOUNTED_BY_HOST_TOOL,
  SCE_APP_INSTALLER_ERROR_INVALID_PATCH_PKG,
  SCE_APP_INSTALLER_ERROR_NEED_ADDCONT_INSTALL_NO_CHANGE_TYPE = -2136801248,
  SCE_APP_INSTALLER_ERROR_ADDCONT_IS_INSTALLING,
  SCE_APP_INSTALLER_ERROR_ADDCONT_ALREADY_INSTALLED,
  SCE_APP_INSTALLER_ERROR_CANNOT_READ_DISC,
  SCE_APP_INSTALLER_ERROR_DATA_DISC_NOT_INSTALLED,
  SCE_APP_INSTALLER_ERROR_NOT_TRANSFER_DISC_VERSION,
  SCE_APP_INSTALLER_ERROR_NO_SLOT_SPACE,
  SCE_APP_INSTALLER_ERROR_NO_SLOT_INFORMATION,
  SCE_APP_INSTALLER_ERROR_INSTALL_MAIN_MISSING,
  SCE_APP_INSTALLER_ERROR_INSTALL_TIME_VALID_IN_FUTURE,
  SCE_APP_INSTALLER_ERROR_SYSTEM_FILE_DISAGREE,
  SCE_APP_INSTALLER_ERROR_INSTALL_BLANK_SLOT,
  SCE_APP_INSTALLER_ERROR_INSTALL_LINK_SLOT,
  SCE_APP_INSTALLER_ERROR_INSTALL_PKG_NOT_COMPLETED,
  SCE_APP_INSTALLER_ERROR_NOSPACE_IN_EXTERNAL_HDD,
  SCE_APP_INSTALLER_ERROR_NOSPACE_KERNEL_IN_EXTERNAL_HDD,
  SCE_APP_INSTALLER_ERROR_COMPILATION_DISC_INSERTED,
  SCE_APP_INSTALLER_ERROR_COMPILATION_DISC_INSERTED_NOT_VISIBLE_DISC_ICON,
  SCE_APP_INSTALLER_ERROR_ACCESS_FAILED_IN_EXTERNAL_HDD,
  SCE_APP_INSTALLER_ERROR_MOVE_FAILED_SOME_APPLICATIONS,
  SCE_APP_INSTALLER_ERROR_DUPLICATION,
  SCE_APP_INSTALLER_ERROR_INVALID_STATE,
  SCE_APP_INSTALLER_ERROR_NOSPACE_DISC,
  SCE_APP_INSTALLER_ERROR_NOSPACE_DISC_IN_EXTERNAL_HDD,
  SCE_APP_INST_UTIL_ERROR_NOT_INITIALIZED = -2136797184,
  SCE_APP_INST_UTIL_ERROR_OUT_OF_MEMORY
};

typedef struct {
  int32_t error_code;
  int32_t version;
  char description[512];
  char type[9];
} SceAppInstallErrorInfo;

typedef struct {
  char status[16];
  char src_type[8];
  uint32_t remain_time;
  uint64_t downloaded_size;
  uint64_t initial_chunk_size;
  uint64_t total_size;
  uint32_t promote_progress;
  SceAppInstallErrorInfo error_info;
  int32_t local_copy_percent;
  bool is_copy_only;
} SceAppInstallStatusInstalled;

void etaHEN_log(const char *fmt, ...);
extern "C" {
int sceAppInstUtilInstallByPackage(MetaInfo *arg1,
                                   SceAppInstallPkgInfo *pkg_info,
                                   PlayGoInfo *arg2);
int sceAppInstUtilInitialize(void);
int sceAppInstUtilGetInstallStatus(const char *content_id,
                                   SceAppInstallStatusInstalled *status);
int sceAppInstUtilGetContentIdFromPkg(const char *pkg_path, char *content_id,
                                      bool *is_app);
}
#define UNUSED(x) (void)x
void call_func();
int server_fd, new_socket = -1;
struct sockaddr_in address;
int addrlen = 0;
atomic_bool is_running = false, is_running_v2 = false;
// make a new thread for installl pkgs
void *runDirectPKGInstaller(void *args) {
  UNUSED(args);
  json_t const *my_json = NULL;
  const uint32_t MAX_TOKENS = 256;
  json_t pool[MAX_TOKENS];
  const char *url = NULL;
  char json_str[0x255]; // Adjust the size based on your actual JSON content
  bool first_run = true;
  is_running = true;

  PlayGoInfo arg3;
  SceAppInstallPkgInfo pkg_info;
  (void)memset(&arg3, 0, sizeof(arg3));

  for (size_t i = 0; i < NUM_LANGUAGES; i++) {
    strncpy(arg3.languages[i], "", sizeof(arg3.languages[i]) - 1);
  }

  for (size_t i = 0; i < NUM_IDS; i++) {
    strncpy(arg3.playgo_scenario_ids[i], "", sizeof(playgo_scenario_id_t) - 1);
    strncpy(*arg3.content_ids, "", sizeof(content_id_t) - 1);
  }

  while (is_running) {
    // Endlessly wait for a URL
    if (!first_run)
      notify(true, "DPI: Waiting for Requests...");

    first_run = false;

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                             (socklen_t *)&addrlen)) < 0) {
      if (errno == 0xA3) {
        break;
      }
      notify(true, "DPI: Failed to accept socket address %s", strerror(errno));
      continue; // If accept fails, try again
    }
    char buffer[1024] = {0};
    long valread = read(new_socket, buffer, 1024);
    if (valread > 0) {
      my_json = json_create(buffer, pool, MAX_TOKENS);
      if (!my_json) {
        etaHEN_log("Error parsing JSON");
        notify(true, "Error parsing JSON");
        continue;
      }

      if ((url = json_getPropertyValue(my_json, "url")) == NULL) {
        notify(true, "DPI: URL not found in JSON");
        continue;
      }

      etaHEN_log("DPI: URL Received: %s", url);

      MetaInfo arg1 = {.uri = url,
                       .ex_uri = "",
                       .playgo_scenario_id = "",
                       .content_id = "",
                       .content_name = "etaHEN DPI",
                       .icon_url = ""};

      int num = sceAppInstUtilInstallByPackage(&arg1, &pkg_info, &arg3);
      if (num == 0) {
        notify(true, "DPI: Download and Install console Task initiated");
      } else {
        notify(true, "DPI: Install failed with error code %d", num);
      }

      snprintf(json_str, sizeof(json_str), "{\"res\":\"%d\"}", num);
      etaHEN_log("DPI: Sending response: %s", json_str);
      send(new_socket, json_str, strlen(json_str), MSG_NOSIGNAL);
      #if 0
      SceAppInstallStatusInstalled status;
      float prog = 0;
      while (strcmp(status.status, "playable") != 0) {
        sceAppInstUtilGetInstallStatus(pkg_info.content_id, &status);
        if (status.total_size != 0) {
          prog = ((float)status.downloaded_size / status.total_size) *
                 100.0f; // Cast to float and multiply by 100 for percentage
        }

        etaHEN_log("DPI: content_id %s, Status: %s | error: %d | progress %.2f%% (%llu/%llu)",
                   pkg_info.content_id,status.status, status.error_info.error_code, prog,
                   status.downloaded_size, status.total_size);
      }
      #endif
    } else {
      notify(true, "DPI: No data received, or connection closed by client.");
    }

    close(new_socket); // Close the connection and wait for the next one
  }

  close(server_fd);
  is_running = false;
  pthread_exit(NULL);

  return NULL;
}

void shutdownDirectPKGInstaller(bool is_v2) {
  if (!is_v2 && !is_running) {
    etaHEN_log("DPI: DirectPKGInstaller is not running");
    return;
  }
  if (is_v2 && !is_running_v2) {
    etaHEN_log("DPI: DirectPKGInstallerV2 is not running");
    return;
  }

  is_v2 ? is_running_v2 = false : is_running = false;

  // Wake up the runDirectPKGInstaller thread if it's blocked on accept
  if (is_v2) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock != -1) {
      struct sockaddr_in addr;
      addr.sin_family = AF_INET;
      addr.sin_port = htons(12800);
      addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      connect(sock, (struct sockaddr *)&addr, sizeof(addr));
      close(sock);
    }
    pthread_join(pkg_installer_thread_v2, NULL);
    return;
  }

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock != -1) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9090);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
  }
  pthread_join(pkg_installer_thread, NULL);
}
void *DPI_v2(void *args);
bool startDirectPKGInstaller(bool is_v2) {
  if (!is_v2 && is_running) {
    etaHEN_log("DPI: DirectPKGInstaller is already running");
    return true;
  }
  if (is_v2 && is_running_v2) {
    etaHEN_log("DPI: DirectPKGInstallerV2 is already running");
    return true;
  }

  int rv = sceAppInstUtilInitialize();
  if (rv != 0) {
    notify(true, "DPI 3: Failed to initialize libSceAppInstUtil.sprx");
    return false;
  }

  if (is_v2) {
    if (pthread_create(&pkg_installer_thread_v2, NULL, DPI_v2, NULL) != 0) {
      notify(true, "Failed to create runDirectPKGInstaller thread");
      return false;
    }
    return true;
  }
  int opt = 1;
  addrlen = sizeof(address);
  const int PORT = 9090;

  // Creating socket file descriptor
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    notify(true, "DPI 4: Failed to create socket file descriptor %s",
           strerror(errno));
    return false;
  }

  // Forcefully attaching socket to the port 8080
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
    notify(true, "DPI 5: Failed to set socket options %s", strerror(errno));
    return false;
  }
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  // Forcefully attaching socket to the port 8080
  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    notify(true, "DPI 6: Failed to bind socket to port %s", strerror(errno));
    return false;
  }
  if (listen(server_fd, 3) < 0) {
    notify(true, "DPI 7: Failed to listen on socket %s", strerror(errno));
    return false;
  }

  if (pthread_create(&pkg_installer_thread, NULL, runDirectPKGInstaller,
                     NULL) != 0) {
    notify(true, "Failed to create runDirectPKGInstaller thread");
    return false;
  }

  return true;
}

/*======================================= DPI V2
 * ================================================================*/
 /*======================================= DPI V2
  * ================================================================*/

#define PAGE_404                                                               \
  "<html>"                                                                     \
  "<head>"                                                                     \
  "<title>File not found</title>"                                              \
  "</head>"                                                                    \
  "<body>File not found</body>"                                                \
  "</html>"

  // Structure definitions
typedef struct post_data {
    char* key;
    uint8_t* val;
    size_t len = 0;
    struct post_data* next;
} post_data_t;

typedef struct post_request {
    struct MHD_PostProcessor* pp;
    post_data_t* data;
    FILE* temp_file;
    size_t offset;
    char* orig_filename;
} post_request_t;

typedef struct asset {
    const char* path;
    const char* mime;
    void* data;
    size_t size;
    struct asset* next;
} asset_t;

static asset_t* g_asset_head = 0;

// Function declarations
static post_data_t* post_data_get(post_data_t* data, const char* key);
static const char* post_data_val(post_data_t* data, const char* key);
static enum MHD_Result post_iterator(void* cls, enum MHD_ValueKind kind,
    const char* key, const char* filename,
    const char* mime, const char* encoding,
    const char* value, uint64_t off,
    size_t size);
static enum MHD_Result queue_response(struct MHD_Connection* conn,
    unsigned int status,
    struct MHD_Response* resp);
static void asset_normalize_path(const char* url, char* path);
void asset_register(const char* path, void* data, size_t size,
    const char* mime);
static enum MHD_Result asset_request(struct MHD_Connection* conn,
    const char* url);
static enum MHD_Result handle_clear_tmp(struct MHD_Connection* conn);
static enum MHD_Result handle_file_download(struct MHD_Connection* conn,
    const char* url);
static enum MHD_Result dpiv2_on_request(void* cls, struct MHD_Connection* conn,
    const char* url, const char* method,
    const char* version,
    const char* upload_data,
    size_t* upload_data_size,
    void** con_cls);
static void dpiv2_on_completed(void* cls, struct MHD_Connection* connection,
    void** con_cls,
    enum MHD_RequestTerminationCode toe);

// Implementation
static post_data_t* post_data_get(post_data_t* data, const char* key) {
    if (!data)
        return 0;
    if (!strcmp(key, data->key))
        return data;
    return post_data_get(data->next, key);
}

static const char* post_data_val(post_data_t* data, const char* key) {
    data = post_data_get(data, key);
    return data ? (const char*)data->val : 0;
}

static enum MHD_Result post_iterator(void* cls, enum MHD_ValueKind kind,
    const char* key, const char* filename,
    const char* mime, const char* encoding,
    const char* value, uint64_t off,
    size_t size) {
    post_request_t* req = (post_request_t*)cls;
    post_data_t* data = post_data_get(req->data, key);

    if (!data) {
        data = (post_data_t*)malloc(sizeof(post_data_t));
        if (!data)
            return MHD_NO;
        data->key = strdup(key);
        data->val = NULL;
        data->len = 0;
        data->next = req->data;
        req->data = data;
    }

    if (strcmp(key, "file") == 0) {
        static int temp_id = 0;
        char temp_path[256];
        snprintf(temp_path, sizeof(temp_path), "/user/data/tmp/upload_%d_%lu.pkg",
            temp_id++, (unsigned long)time(NULL));

        if (!req->temp_file) {
            req->temp_file = fopen(temp_path, "wb");
            if (!req->temp_file) {
                return MHD_NO;
            }

            data->val = (uint8_t*)strdup(temp_path);
            data->len = strlen(temp_path);
            req->offset = 0;

            if (!req->orig_filename && filename && strlen(filename) > 0) {
                req->orig_filename = strdup(filename);
            }
        }
        else {
            if (fseek(req->temp_file, off, SEEK_SET) != 0) {
                fclose(req->temp_file);
                req->temp_file = 0;
                return MHD_NO;
            }
        }

        size_t written = fwrite(value, 1, size, req->temp_file);
        if (written != size) {
            fclose(req->temp_file);
            req->temp_file = 0;
            return MHD_NO;
        }
        req->offset += size;
    }
    else {
        if (!data->val) {
            data->val = (uint8_t*)malloc(size + 1);
            if (!data->val)
                return MHD_NO;
            memcpy(data->val, value, size);
            data->val[size] = '\0';
            data->len = size;
        }
        else {
            uint8_t* new_val = (uint8_t*)realloc(data->val, data->len + size + 1);
            if (!new_val)
                return MHD_NO;
            data->val = new_val;
            memcpy(data->val + data->len, value, size);
            data->len += size;
            data->val[data->len] = '\0';
        }
    }

    return MHD_YES;
}

static enum MHD_Result queue_response(struct MHD_Connection* conn,
    unsigned int status,
    struct MHD_Response* resp) {
    MHD_add_response_header(resp, MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN,
        "*");
    return MHD_queue_response(conn, status, resp);
}

static void format_file_size(char* buffer, size_t buffer_size, size_t bytes) {
    const char* units[] = { "bytes", "KB", "MB", "GB", "TB" };
    int unit_index = 0;
    double size = bytes;

    while (size >= 1024 && unit_index < 4) {
        size /= 1024;
        unit_index++;
    }

    if (unit_index == 0) {
        snprintf(buffer, buffer_size, "%.0f %s", size, units[unit_index]);
    }
    else {
        snprintf(buffer, buffer_size, "%.2f %s", size, units[unit_index]);
    }
}

static void asset_normalize_path(const char* url, char* path) {
    char* ptr = path;
    for (size_t i = 0; i < strlen(url); i++) {
        if (url[i] == '/' && url[i + 1] == '/') {
            continue;
        }
        *ptr = url[i];
        ptr++;
    }
    *ptr = '\0';
}

void asset_register(const char* path, void* data, size_t size,
    const char* mime) {
    asset_t* a = (asset_t*)calloc(1, sizeof(asset_t));
    a->path = path;
    a->mime = mime;
    a->data = data;
    a->size = size;
    a->next = g_asset_head;
    g_asset_head = a;
}

static enum MHD_Result asset_request(struct MHD_Connection* conn,
    const char* url) {
    unsigned int status = MHD_HTTP_NOT_FOUND;
    enum MHD_Result ret = MHD_NO;
    size_t size = strlen(PAGE_404);
    struct MHD_Response* resp;
    void* data = (void*)PAGE_404;
    const char* mime = 0;
    char path[PATH_MAX];

    asset_normalize_path(url, path);
    for (asset_t* a = g_asset_head; a != 0; a = a->next) {
        if (!strcmp(path, a->path)) {
            data = a->data;
            size = a->size;
            mime = a->mime;
            status = MHD_HTTP_OK;
            break;
        }
    }

    if ((resp = MHD_create_response_from_buffer(size, data,
        MHD_RESPMEM_PERSISTENT))) {
        if (mime) {
            MHD_add_response_header(resp, "Content-Type", mime);
        }
        ret = queue_response(conn, status, resp);
        MHD_destroy_response(resp);
    }

    return ret;
}

static enum MHD_Result handle_clear_tmp(struct MHD_Connection* conn) {
    const char* tmp_dir = "/user/data/tmp/";
    char response_buffer[1024];
    int files_deleted = 0;
    int error_count = 0;

    DIR* dir = opendir(tmp_dir);
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            char full_path[512];
            snprintf(full_path, sizeof(full_path), "%s%s", tmp_dir, entry->d_name);

            if (unlink(full_path) == 0) {
                files_deleted++;
            }
            else {
                error_count++;
            }
        }
        closedir(dir);

        snprintf(response_buffer, sizeof(response_buffer),
            "SUCCESS: Deleted %d temporary files. %s", files_deleted,
            error_count > 0 ? "Some files could not be deleted." : "");
    }
    else {
        snprintf(response_buffer, sizeof(response_buffer),
            "FAILED: Could not open temporary directory.");
    }

    struct MHD_Response* response = MHD_create_response_from_buffer(
        strlen(response_buffer), response_buffer, MHD_RESPMEM_MUST_COPY);

    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    return ret;
}

static enum MHD_Result handle_file_download(struct MHD_Connection* conn,
    const char* url) {
    char file_path[PATH_MAX];
    struct stat st;
    FILE* fp;
    enum MHD_Result ret = MHD_NO;
    struct MHD_Response* response;

    // Convert URL to file path (remove leading slash from URL if present)
    const char* path_start = url;
    if (path_start[0] == '/')
        path_start++;

    snprintf(file_path, sizeof(file_path), "/%s", path_start);

    // Check if file exists
    if (stat(file_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        const char* error_msg = "File not found";
        response = MHD_create_response_from_buffer(
            strlen(error_msg), (void*)error_msg, MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response(conn, MHD_HTTP_NOT_FOUND, response);
        MHD_destroy_response(response);
        return ret;
    }

    fp = fopen(file_path, "rb");
    if (!fp) {
        const char* error_msg = "Cannot open file";
        response = MHD_create_response_from_buffer(
            strlen(error_msg), (void*)error_msg, MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        MHD_destroy_response(response);
        return ret;
    }

    // Check for Range header
    const char* range_header = MHD_lookup_connection_value(
        conn, MHD_HEADER_KIND, MHD_HTTP_HEADER_RANGE);

    uint64_t start = 0;
    uint64_t end = st.st_size - 1;
    uint64_t content_length = st.st_size;
    unsigned int status_code = MHD_HTTP_OK;

    // Parse range header if present
    if (range_header && strncmp(range_header, "bytes=", 6) == 0) {
        const char* range_spec = range_header + 6;
        const char* dash = strchr(range_spec, '-');

        if (dash) {
            if (dash != range_spec) {
                start = strtoull(range_spec, NULL, 10);
            }
            if (*(dash + 1) != '\0') {
                end = strtoull(dash + 1, NULL, 10);
            }

            if (start > end || start >= (uint64_t)st.st_size) {
                fclose(fp);
                const char* error_msg = "Invalid range";
                response = MHD_create_response_from_buffer(
                    strlen(error_msg), (void*)error_msg, MHD_RESPMEM_PERSISTENT);
                ret = MHD_queue_response(
                    conn, MHD_HTTP_RANGE_NOT_SATISFIABLE, response);
                MHD_destroy_response(response);
                return ret;
            }

            if (end >= (uint64_t)st.st_size) {
                end = st.st_size - 1;
            }

            content_length = end - start + 1;
            status_code = MHD_HTTP_PARTIAL_CONTENT;

            fseek(fp, start, SEEK_SET);
        }
    }

    // Allocate buffer and read file content
    void* file_data = malloc(content_length);
    if (!file_data) {
        fclose(fp);
        const char* error_msg = "Memory allocation failed";
        response = MHD_create_response_from_buffer(
            strlen(error_msg), (void*)error_msg, MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        MHD_destroy_response(response);
        return ret;
    }

    size_t bytes_read = fread(file_data, 1, content_length, fp);
    fclose(fp);

    if (bytes_read != content_length) {
        free(file_data);
        const char* error_msg = "Error reading file";
        response = MHD_create_response_from_buffer(
            strlen(error_msg), (void*)error_msg, MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
        MHD_destroy_response(response);
        return ret;
    }

    response = MHD_create_response_from_buffer(content_length, file_data,
        MHD_RESPMEM_MUST_FREE);

    if (!response) {
        free(file_data);
        return MHD_NO;
    }

    // Add headers
    MHD_add_response_header(response, MHD_HTTP_HEADER_ACCEPT_RANGES, "bytes");

    // Determine content type
    const char* content_type = "application/octet-stream";
    if (strstr(file_path, ".pkg"))
        content_type = "application/octet-stream";
    else if (strstr(file_path, ".html"))
        content_type = "text/html";
    else if (strstr(file_path, ".json"))
        content_type = "application/json";
    else if (strstr(file_path, ".txt"))
        content_type = "text/plain";

    MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE,
        content_type);

    // Add Content-Disposition with filename
    char* filename = strrchr(file_path, '/');
    if (filename) {
        filename++;
        char disposition[512];
        snprintf(disposition, sizeof(disposition), "attachment; filename=\"%s\"",
            filename);
        MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_DISPOSITION,
            disposition);
    }

    // Add range-specific headers
    if (status_code == MHD_HTTP_PARTIAL_CONTENT) {
        char content_range[128];
        snprintf(content_range, sizeof(content_range),
            "bytes %llu-%llu/%lld", (unsigned long long)start,
            (unsigned long long)end, (long long)st.st_size);
        MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_RANGE,
            content_range);
    }

    ret = queue_response(conn, status_code, response);
    MHD_destroy_response(response);

    return ret;
}

static enum MHD_Result dpiv2_on_request(void* cls, struct MHD_Connection* conn,
    const char* url, const char* method,
    const char* version,
    const char* upload_data,
    size_t* upload_data_size,
    void** con_cls) {
    post_request_t* req = (post_request_t*)*con_cls;
    enum MHD_Result ret = MHD_NO;

    PlayGoInfo arg3;
    SceAppInstallPkgInfo pkg_info;
    memset(&arg3, 0, sizeof(arg3));

    for (size_t i = 0; i < NUM_LANGUAGES; i++) {
        strncpy(arg3.languages[i], "", sizeof(arg3.languages[i]) - 1);
    }

    for (size_t i = 0; i < NUM_IDS; i++) {
        strncpy(arg3.playgo_scenario_ids[i], "", sizeof(playgo_scenario_id_t) - 1);
        strncpy(*arg3.content_ids, "", sizeof(content_id_t) - 1);
    }

    if (!strcmp(method, MHD_HTTP_METHOD_POST) && !strcmp(url, "/cleartmp")) {
        return handle_clear_tmp(conn);
    }

    if (!strcmp(method, MHD_HTTP_METHOD_GET)) {
        if (!strcmp("/", url) || !url[0]) {
            const char* page =
                "<!DOCTYPE html>\n"
                "<html>\n"
                "<head>\n"
                "  <title>etaHEN DPIv2</title>\n"
                "  <style>\n"
                "    body { font-family: Arial, sans-serif; max-width: 600px; "
                "margin: 0 auto; padding: 20px; }\n"
                "    .container { border: 1px solid #ccc; padding: 20px; "
                "border-radius: 5px; }\n"
                "    .form-group { margin-bottom: 15px; }\n"
                "    label { display: block; margin-bottom: 5px; }\n"
                "    .btn { background: #4285f4; color: white; border: none; "
                "padding: 10px 15px; border-radius: 4px; cursor: pointer; }\n"
                "    .btn-warning { background: #ff9800; }\n"
                "    input[type=text], input[type=file] { width: 100%; padding: 8px; "
                "box-sizing: border-box; }\n"
                "    .or-divider { text-align: center; margin: 15px 0; position: "
                "relative; }\n"
                "    .or-divider:before { content: ''; position: absolute; top: 50%; "
                "left: 0; right: 0; height: 1px; background: #ccc; }\n"
                "    .or-divider span { background: white; padding: 0 10px; "
                "position: relative; }\n"
                "    .progress-container { margin-top: 20px; display: none; }\n"
                "    .progress { width: 100%; height: 20px; background-color: "
                "#f3f3f3; border-radius: 10px; overflow: hidden; }\n"
                "    .progress-bar { height: 100%; background-color: #4CAF50; width: "
                "0%; transition: width 0.3s; }\n"
                "    .progress-info { text-align: center; margin-top: 5px; "
                "font-size: 0.9em; color: #666; }\n"
                "    .success { color: #4CAF50; font-weight: bold; }\n"
                "    .error { color: #f44336; font-weight: bold; }\n"
                "    .success-box { background-color: #e8f5e9; border: 1px solid "
                "#4CAF50; padding: 10px; border-radius: 5px; }\n"
                "    .error-box { background-color: #ffebee; border: 1px solid "
                "#f44336; padding: 10px; border-radius: 5px; }\n"
                "    .note { font-size: 0.9em; color: #666; margin-top: 5px; "
                "font-style: italic; }\n"
                "    .maintenance { margin-top: 30px; border-top: 1px solid #eee; "
                "padding-top: 20px; }\n"
                "  </style>\n"
                "</head>\n"
                "<body>\n"
                "  <div class='container'>\n"
                "    <h2>etaHEN DPIv2 Web Interface</h2>\n"
                "    <form id='uploadForm' action='/upload' method='post' "
                "enctype='multipart/form-data'>\n"
                "      <div class='form-group'>\n"
                "        <label for='file'>Upload and Install PKG file:</label>\n"
                "        <input type='file' id='file' name='file' accept='.pkg'>\n"
                "      </div>\n"
                "      <div class='or-divider'><span>OR</span></div>\n"
                "      <div class='form-group'>\n"
                "        <label for='url'>PKG HTTP Url (Fastest Option):</label>\n"
                "        <input type='text' id='url' name='url' "
                "placeholder='http://xxx.xxx.xx.xx/game.pkg'>\n"
                "      </div>\n"
                "      <button type='submit' class='btn'>Upload and "
                "Install</button>\n"
                "    </form>\n"
                "    <div class='progress-container' id='progressContainer'>\n"
                "      <div class='progress'>\n"
                "        <div class='progress-bar' id='progressBar'></div>\n"
                "      </div>\n"
                "      <div class='progress-info' id='progressInfo'>0%</div>\n"
                "    </div>\n"
                "    <div id='result'></div>\n"
                "    <div class='maintenance'>\n"
                "      <h3>Maintenance</h3>\n"
                "      <button id='clearTmpBtn' class='btn btn-warning'>Clear "
                "Temporary Files</button>\n"
                "      <p class='note'>This will delete all temporary PKG files that "
                "were uploaded to the console. \n"
                "      Use this to free up disk space after installing "
                "packages.</p>\n"
                "      <div id='clearResult'></div>\n"
                "    </div>\n"
                "  </div>\n"
                "  <script>\n"
                "    function formatSpeed(bytesPerSecond) {\n"
                "      if (bytesPerSecond < 1024) {\n"
                "        return bytesPerSecond.toFixed(1) + ' B/s';\n"
                "      } else if (bytesPerSecond < 1024 * 1024) {\n"
                "        return (bytesPerSecond / 1024).toFixed(1) + ' KB/s';\n"
                "      } else if (bytesPerSecond < 1024 * 1024 * 1024) {\n"
                "        return (bytesPerSecond / (1024 * 1024)).toFixed(1) + ' "
                "MB/s';\n"
                "      } else {\n"
                "        return (bytesPerSecond / (1024 * 1024 * 1024)).toFixed(1) + "
                "' GB/s';\n"
                "      }\n"
                "    }\n"
                "    \n"
                "    "
                "document.getElementById('uploadForm').addEventListener('submit', "
                "function(e) {\n"
                "      e.preventDefault();\n"
                "      \n"
                "      var fileInput = document.getElementById('file');\n"
                "      var urlInput = document.getElementById('url');\n"
                "      var resultDiv = document.getElementById('result');\n"
                "      \n"
                "      if (fileInput.files.length === 0 && urlInput.value.trim() === "
                "'') {\n"
                "        resultDiv.innerHTML = '<div class=\"error-box\"><h3 "
                "class=\"error\">Validation Error</h3>' +\n"
                "                             '<p class=\"error\">Please either "
                "select a PKG file to upload or enter a URL.</p></div>';\n"
                "        return;\n"
                "      }\n"
                "      \n"
                "      var formData = new FormData(this);\n"
                "      var xhr = new XMLHttpRequest();\n"
                "      var progressContainer = "
                "document.getElementById('progressContainer');\n"
                "      var progressBar = document.getElementById('progressBar');\n"
                "      var progressInfo = document.getElementById('progressInfo');\n"
                "      \n"
                "      resultDiv.innerHTML = '<h3>Processing...</h3>';\n"
                "      \n"
                "      if (fileInput.files.length > 0) {\n"
                "        progressContainer.style.display = 'block';\n"
                "        progressBar.style.width = '0%';\n"
                "        progressInfo.textContent = '0%';\n"
                "      }\n"
                "      \n"
                "      xhr.upload.addEventListener('progress', function(e) {\n"
                "        if (e.lengthComputable) {\n"
                "          var percentComplete = (e.loaded / e.total) * 100;\n"
                "          progressBar.style.width = percentComplete + '%';\n"
                "          progressInfo.textContent = Math.round(percentComplete) + "
                "'%';\n"
                "          \n"
                "          if (window.uploadStartTime) {\n"
                "            var elapsed = (new Date().getTime() - "
                "window.uploadStartTime) / 1000;\n"
                "            var bytesPerSecond = e.loaded / elapsed;\n"
                "            var speedText = formatSpeed(bytesPerSecond);\n"
                "            var remainingBytes = e.total - e.loaded;\n"
                "            var remainingTime = remainingBytes / bytesPerSecond;\n"
                "            \n"
                "            var timeText = '';\n"
                "            \n"
                "            if (remainingTime < 60) {\n"
                "              timeText = Math.round(remainingTime) + ' seconds "
                "remaining';\n"
                "            } else if (remainingTime < 3600) {\n"
                "              timeText = Math.round(remainingTime/60) + ' minutes "
                "remaining';\n"
                "            } else {\n"
                "              var hours = Math.floor(remainingTime / 3600);\n"
                "              var minutes = Math.floor((remainingTime % 3600) / "
                "60);\n"
                "              timeText = hours + ' hours ' + minutes + ' minutes "
                "remaining';\n"
                "            }\n"
                "            \n"
                "            progressInfo.textContent = Math.round(percentComplete) "
                "+ '% - ' + speedText + ' - ' + timeText;\n"
                "          }\n"
                "        }\n"
                "      });\n"
                "      \n"
                "      xhr.addEventListener('load', function() {\n"
                "        if (xhr.status === 200) {\n"
                "          var response = xhr.responseText;\n"
                "          if (response.includes('SUCCESS')) {\n"
                "            resultDiv.innerHTML = '<div class=\"success-box\"><h3 "
                "class=\"success\">Installation Started!</h3>' + \n"
                "                                 '<p class=\"success\">' + response "
                "+ '</p></div>';\n"
                "            \n"
                "            fileInput.value = '';\n"
                "            urlInput.value = '';\n"
                "            \n"
                "            progressBar.style.width = '0%';\n"
                "            progressInfo.textContent = '0%';\n"
                "          } else if (response.includes('FAILED')) {\n"
                "            resultDiv.innerHTML = '<div class=\"error-box\"><h3 "
                "class=\"error\">Installation Failed!</h3>' + \n"
                "                                 '<p class=\"error\">' + response + "
                "'</p></div>';\n"
                "          } else {\n"
                "            resultDiv.innerHTML = '<h3>Result:</h3><p>' + response "
                "+ '</p>';\n"
                "          }\n"
                "        } else {\n"
                "          resultDiv.innerHTML = '<div class=\"error-box\"><h3 "
                "class=\"error\">Error!</h3>' + \n"
                "                               '<p class=\"error\">Status: ' + "
                "xhr.status + '</p></div>';\n"
                "        }\n"
                "        progressContainer.style.display = 'none';\n"
                "      });\n"
                "      \n"
                "      xhr.addEventListener('error', function() {\n"
                "        resultDiv.innerHTML = '<div class=\"error-box\"><h3 "
                "class=\"error\">Connection Error!</h3>' + \n"
                "                             '<p class=\"error\">Failed to connect "
                "to the server.</p></div>';\n"
                "        progressContainer.style.display = 'none';\n"
                "      });\n"
                "      \n"
                "      xhr.addEventListener('abort', function() {\n"
                "        resultDiv.innerHTML = '<div class=\"error-box\"><h3 "
                "class=\"error\">Upload Aborted</h3>' + \n"
                "                             '<p class=\"error\">The file upload "
                "was canceled.</p></div>';\n"
                "        progressContainer.style.display = 'none';\n"
                "      });\n"
                "      \n"
                "      window.uploadStartTime = new Date().getTime();\n"
                "      xhr.open('POST', '/upload');\n"
                "      xhr.send(formData);\n"
                "    });\n"
                "    \n"
                "    "
                "document.getElementById('clearTmpBtn').addEventListener('click', "
                "function() {\n"
                "      var clearResultDiv = document.getElementById('clearResult');\n"
                "      clearResultDiv.innerHTML = '<p>Clearing temporary "
                "files...</p>';\n"
                "      \n"
                "      var xhr = new XMLHttpRequest();\n"
                "      xhr.onload = function() {\n"
                "        if (xhr.status === 200) {\n"
                "          var response = xhr.responseText;\n"
                "          if (response.includes('SUCCESS')) {\n"
                "            clearResultDiv.innerHTML = '<div "
                "class=\"success-box\"><p class=\"success\">' + response + "
                "'</p></div>';\n"
                "          } else {\n"
                "            clearResultDiv.innerHTML = '<div class=\"error-box\"><p "
                "class=\"error\">' + response + '</p></div>';\n"
                "          }\n"
                "        } else {\n"
                "          clearResultDiv.innerHTML = '<div class=\"error-box\"><p "
                "class=\"error\">Error: ' + xhr.status + '</p></div>';\n"
                "        }\n"
                "      };\n"
                "      xhr.onerror = function() {\n"
                "        clearResultDiv.innerHTML = '<div class=\"error-box\"><p "
                "class=\"error\">Connection error occurred</p></div>';\n"
                "      };\n"
                "      xhr.open('POST', '/cleartmp');\n"
                "      xhr.send();\n"
                "    });\n"
                "  </script>\n"
                "</body>\n"
                "</html>\n";

            struct MHD_Response* response = MHD_create_response_from_buffer(
                strlen(page), (void*)page, MHD_RESPMEM_PERSISTENT);

            if (!response)
                return MHD_NO;

            MHD_add_response_header(response, "Content-Type", "text/html");
            ret = MHD_queue_response(conn, MHD_HTTP_OK, response);
            MHD_destroy_response(response);

            return ret;
        }

        // Handle file download requests for paths starting with /data, /user, etc.
        if (strncmp(url, "/data/", 6) == 0 || strncmp(url, "/user/", 6) == 0 ||
            strncmp(url, "/system/", 8) == 0 || strncmp(url, "/mnt/", 5) == 0) {
            return handle_file_download(conn, url);
        }

        return asset_request(conn, url);
    }

    if (strcmp(method, MHD_HTTP_METHOD_POST)) {
        return MHD_NO;
    }

    if (!req) {
        *con_cls = malloc(sizeof(post_request_t));
        req = (post_request_t*)*con_cls;
        req->pp = MHD_create_post_processor(conn, 0x1000, &post_iterator, req);
        req->data = NULL;
        req->temp_file = NULL;
        req->offset = 0;
        req->orig_filename = NULL;
        return MHD_YES;
    }

    if (*upload_data_size) {
        ret = MHD_post_process(req->pp, upload_data, *upload_data_size);
        *upload_data_size = 0;
        return ret;
    }

    char response_buffer[1024] = "No data received";

    MetaInfo arg1 = { .uri = "",
                     .ex_uri = "",
                     .playgo_scenario_id = "",
                     .content_id = "",
                     .content_name = "etaHEN DPIv2",
                     .icon_url = "" };

    if (req->data) {
        const char* url_value = post_data_val(req->data, "url");
        int install_result = -1;

        if (url_value && strlen(url_value) > 0) {
            etaHEN_log("Received URL: %s", url_value);
            arg1.uri = url_value;

            install_result = sceAppInstUtilInstallByPackage(&arg1, &pkg_info, &arg3);

            if (install_result == 0) {
                snprintf(response_buffer, sizeof(response_buffer),
                    "SUCCESS: Direct install console Task started for URL: %s",
                    url_value);
                notify(true, "DPI: Direct install console Task started for %s",
                    url_value);
            }
            else {
                std::string error_message =
                    std::string(ErrorTranslator::instance().get(install_result));
                snprintf(response_buffer, sizeof(response_buffer),
                    "FAILED: Install failed with error %s, code %d (0x%X) for "
                    "URL: %s",
                    error_message.c_str(), install_result, install_result,
                    url_value);
                notify(true, "DPI: Install failed with error %s, code %d (0x%X)",
                    error_message.c_str(), install_result, install_result);
            }
        }
        else {
            post_data_t* file_data = post_data_get(req->data, "file");
            if (file_data && file_data->len > 0) {
                char* temp_path = (char*)file_data->val;

                if (req->temp_file) {
                    fclose(req->temp_file);
                    req->temp_file = 0;
                }

                arg1.uri = temp_path;
                std::string tempstr =
                    std::string("etaHEN DPIv2 | " + std::string(req->orig_filename));
                arg1.content_name =
                    req->orig_filename ? tempstr.c_str() : "etaHEN DPIv2";

                const char* display_filename =
                    req->orig_filename ? req->orig_filename : temp_path;

                install_result =
                    sceAppInstUtilInstallByPackage(&arg1, &pkg_info, &arg3);

                if (install_result == 0) {
                    char size_str[50];
                    format_file_size(size_str, sizeof(size_str), req->offset);

                    snprintf(response_buffer, sizeof(response_buffer),
                        "SUCCESS: PKG installation started from file: %s (size: %s)",
                        display_filename, size_str);
                    notify(true, "DPI: Installation started for uploaded PKG");
                }
                else {
                    std::string error_message =
                        std::string(ErrorTranslator::instance().get(install_result));
                    snprintf(response_buffer, sizeof(response_buffer),
                        "FAILED: Install failed with error %s, code %d (0x%X) for "
                        "file: %s",
                        error_message.c_str(), install_result, install_result,
                        display_filename);
                    notify(true, "DPI: Install failed with error %s, code %d",
                        error_message.c_str(), install_result);
                }
            }
        }

        struct MHD_Response* response = MHD_create_response_from_buffer(
            strlen(response_buffer), response_buffer, MHD_RESPMEM_MUST_COPY);

        ret = MHD_queue_response(conn, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
    }

    return ret;
}

static void dpiv2_on_completed(void* cls, struct MHD_Connection* connection,
    void** con_cls,
    enum MHD_RequestTerminationCode toe) {
    post_request_t* req = (post_request_t*)*con_cls;

    if (!req)
        return;

    if (req->temp_file) {
        fclose(req->temp_file);
        req->temp_file = 0;
    }

    if (req->orig_filename) {
        etaHEN_log("freeing og %p", req->orig_filename);
        free(req->orig_filename), req->orig_filename = NULL;
    }

    etaHEN_log("freeing data");
    post_data_t* data;
    while ((data = req->data)) {
        req->data = data->next;
        if (data->key)
            free(data->key);
        if (data->val)
            free(data->val);
        free(data);
    }

    MHD_destroy_post_processor(req->pp);
    free(req);
}

int DPIv2_listen(int port) {
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    char ip[INET_ADDRSTRLEN];
    struct ifaddrs* ifaddr;
    int ifaddr_wait = 1;
    socklen_t addr_len;
    int connfd;

    if (getifaddrs(&ifaddr) == -1) {
        etaHEN_log("getifaddrs");
        return -1;
    }

    signal(SIGPIPE, SIG_IGN);

    for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        if (ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        if (!strncmp("lo", ifa->ifa_name, 2)) {
            continue;
        }

        struct sockaddr_in* in = (struct sockaddr_in*)ifa->ifa_addr;
        inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

        if (!strncmp("0.", ip, 2)) {
            continue;
        }

        etaHEN_log("Serving on http://%s:%d (%s)", ip, port, ifa->ifa_name);
        ifaddr_wait = 0;
    }

    freeifaddrs(ifaddr);

    if (ifaddr_wait) {
        return 0;
    }

    if ((srvfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        notify(true, "DPIv2 error: socket | %s", strerror(errno));
        return -1;
    }
    int opt = 1;
    if (setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) < 0) {
        notify(true, "DPIv2 error: setsockopt | %s", strerror(errno));
        close(srvfd);
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);

    if (bind(srvfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        notify(true, "DPIv2 error: bind | %s", strerror(errno));
        close(srvfd);
        return -1;
    }

    if (listen(srvfd, 5) != 0) {
        notify(true, "DPIv2 error: listen | %s", strerror(errno));
        close(srvfd);
        return -1;
    }

    if (!(httpd = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_ITC |
        MHD_USE_NO_LISTEN_SOCKET | MHD_USE_DEBUG |
        MHD_USE_INTERNAL_POLLING_THREAD,
        0, NULL, NULL, &dpiv2_on_request, NULL,
        MHD_OPTION_NOTIFY_COMPLETED,
        &dpiv2_on_completed, NULL, MHD_OPTION_END))) {
        notify(true, "DPIv2 error: MHD_start_daemon code: %d", httpd);
        close(srvfd);
        return -1;
    }

    while (is_running_v2) {
        addr_len = sizeof(client_addr);
        if ((connfd = accept(srvfd, (struct sockaddr*)&client_addr, &addr_len)) <
            0) {
            perror("accept");
            break;
        }

        if (MHD_add_connection(httpd, connfd, (struct sockaddr*)&client_addr,
            addr_len) != MHD_YES) {
            etaHEN_log("error: MHD_add_connection");
            break;
        }
    }

    MHD_stop_daemon(httpd);

    return close(srvfd);
}

void* DPI_v2(void* args) {
    (void)args;
    is_running_v2 = true;
    mkdir("/user/data/", 0777);
    mkdir("/user/data/tmp/", 0777);
    while (is_running_v2) {
        DPIv2_listen(12800);
    }
    is_running_v2 = false;
    pthread_exit(NULL);
    return NULL;
}