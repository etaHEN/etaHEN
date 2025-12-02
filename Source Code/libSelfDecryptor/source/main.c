#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/elf64.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdarg.h>
#include <ps5/klog.h>

#include "selfpager.h"
#include "SelfDecryptor.h"

/* Full PS5 notification struct */
typedef struct {
    int type;                //0x00
    int req_id;              //0x04
    int priority;            //0x08
    int msg_id;              //0x0C
    int target_id;           //0x10
    int user_id;             //0x14
    int unk1;                //0x18
    int unk2;                //0x1C
    int app_id;              //0x20
    int error_num;           //0x24
    int unk3;                //0x28
    char use_icon_image_uri; //0x2C
    char message[1024];      //0x2D
    char uri[1024];          //0x42D
    char unkstr[1024];       //0x82D
} SceNotificationRequest;   //Size = 0xC30

int sceKernelSendNotificationRequest(int device,
    SceNotificationRequest* req,
    size_t size, int blocking);

void printf_notification(const char* fmt, ...)
{
    SceNotificationRequest noti;
    memset(&noti, 0, sizeof(noti));

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(noti.message, sizeof(noti.message), fmt, ap);
    va_end(ap);

    noti.type = 0;
    noti.use_icon_image_uri = 1;
    noti.target_id = -1;
    strncpy(noti.uri, "cxml://psnotification/tex_icon_system", sizeof(noti.uri) - 1);

    sceKernelSendNotificationRequest(0, &noti, sizeof(noti), 0);
    printf("%s\n", noti.message);
}

static void mkdirs(const char *dir) {
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0777);
            *p = '/';
        }
    mkdir(tmp, 0777);
}

int decrypt_self_ftp(const char* input_file_path, const char* output_file_path) {
	klog_printf("%d: decrypt_self_ftp called with input: %s, output: %s\n", __LINE__, input_file_path, output_file_path);
    int input_file_fd = open(input_file_path, O_RDONLY);
    if (input_file_fd < 0) {
        printf_notification("Failed to open input file");
        return -1;
    }
    klog_printf("%d: decrypt_self_ftp called with input: %s, output: %s\n", __LINE__, input_file_path, output_file_path);

    uint64_t output_file_size = 0;
    char* out_data = NULL;
    int res = decrypt_self(input_file_fd, &out_data, &output_file_size);
    klog_printf("%d: decrypt_self_ftp called with input: %s, output: %s\n", __LINE__, input_file_path, output_file_path);

    close(input_file_fd);
    if (res == DECRYPT_ERROR_INPUT_NOT_SELF) {
        return res;
    }
    else if (res != 0) {
        printf_notification("Failed to decrypt self: %s , error %d", input_file_path, res);
        return res;
    }
    klog_printf("%d: decrypt_self_ftp called with input: %s, output: %s\n", __LINE__, input_file_path, output_file_path);

    int output_file_fd = open(output_file_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (output_file_fd < 0) {
        printf_notification("Failed to open output file");
        munmap(out_data, output_file_size);
        unlink(output_file_path);
        return -1;
    }
    klog_printf("%d: decrypt_self_ftp called with input: %s, output: %s\n", __LINE__, input_file_path, output_file_path);

    ssize_t write_res = write(output_file_fd, out_data, output_file_size);
    klog_printf("%d: decrypt_self_ftp called with input: %s, output: %s\n", __LINE__, input_file_path, output_file_path);

    munmap(out_data, output_file_size);
    klog_printf("%d: decrypt_self_ftp called with input: %s, output: %s\n", __LINE__, input_file_path, output_file_path);

    close(output_file_fd);
    klog_printf("%d: decrypt_self_ftp called with input: %s, output: %s\n", __LINE__, input_file_path, output_file_path);

    if (write_res != output_file_size) {
        printf_notification("Failed to write complete output file");
        unlink(output_file_path);
        return -1;
    }
    printf_notification("Decrypted self: '%s' -> '%s'", input_file_path, output_file_path);

    return res;
}


int decrypt_self_by_path(const char *input_file_path, const char *output_file_path, int *num_success, int *num_failed) {
    int input_file_fd = open(input_file_path, O_RDONLY);
    if (input_file_fd < 0) {
        printf_notification("Failed to open input file");
        if (num_failed) (*num_failed)++;
        return -1;
    }

    uint64_t output_file_size = 0;
    char *out_data = NULL;
    int res = decrypt_self(input_file_fd, &out_data, &output_file_size);
    close(input_file_fd);
    if (res == DECRYPT_ERROR_INPUT_NOT_SELF) {
        return res;
    } else if (res != 0) {
        printf_notification("Failed to decrypt self: %s , error %d", input_file_path, res);
        if (num_failed) (*num_failed)++;
        return res;
    }

    char *last_slash = strrchr(output_file_path, '/');
    if (last_slash) {
        char output_dir_path[PATH_MAX];
        long dir_path_len = last_slash - output_file_path;
        strncpy(output_dir_path, output_file_path, dir_path_len);
        output_dir_path[dir_path_len] = '\0';
        mkdirs(output_dir_path);
    }
    int output_file_fd = open(output_file_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (output_file_fd < 0) {
        printf_notification("Failed to open output file");
        munmap(out_data, output_file_size);
        unlink(output_file_path);
        if (num_failed) (*num_failed)++;
        return -1;
    }
    ssize_t write_res = write(output_file_fd, out_data, output_file_size);
    munmap(out_data, output_file_size);
    close(output_file_fd);
    if (write_res != output_file_size) {
        printf_notification("Failed to write complete output file");
        unlink(output_file_path);
        if (num_failed) (*num_failed)++;
        return -1;
    }
    printf_notification("Decrypted self: '%s' -> '%s'", input_file_path, output_file_path);

    if (num_success) (*num_success)++;
    return res;
}

static const char *allowed_exts[] = {".elf", ".self", ".prx", ".sprx", ".bin"};
static const int allowed_exts_count = sizeof(allowed_exts) / sizeof(allowed_exts[0]);

static int decrypt_all_selfs_in_directory(const char *input_dir_path, const char *output_dir_path, int recursive, int *num_success, int *num_failed) {
    if (!input_dir_path || !output_dir_path) {
        return -1;
    }

    DIR *dir = opendir(input_dir_path);
    if (!dir) {
        printf_notification("Failed to open input directory");
        return -1;
    }

    struct dirent *entry;
    char inpath[PATH_MAX];
    char outpath[PATH_MAX];

    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }

        if (entry->d_type == DT_DIR && recursive) {
            // if the input dir starts with "/mnt/sandbox/pfsmnt" skip entry if ends with "-app0-patch0-union",
            // we only care about app0 and patch0
            if (entry->d_namlen == sizeof("PPSA00000-app0-patch0-union") - 1 &&
                strncmp(input_dir_path, "/mnt/sandbox/pfsmnt", sizeof("/mnt/sandbox/pfsmnt") - 1) == 0 &&
                strncmp(name + 9, "-app0-patch0-union", sizeof("-app0-patch0-union") - 1) == 0) {
                continue;
            }

            snprintf(inpath, sizeof(inpath), "%s/%s", input_dir_path, name);
            snprintf(outpath, sizeof(outpath), "%s/%s", output_dir_path, name);
            decrypt_all_selfs_in_directory(inpath, outpath, recursive, num_success, num_failed);
        } else if (entry->d_type == DT_REG) {
            int has_allowed_ext = 0;
            const char *ext = strrchr(name, '.');
            for (int i = 0; i < allowed_exts_count; i++) {
                if (ext && strcasecmp(ext, allowed_exts[i]) == 0) {
                    has_allowed_ext = 1;
                    break;
                }
            }
            if (!has_allowed_ext) {
                continue;
            }

            snprintf(outpath, sizeof(outpath), "%s/%s", output_dir_path, name);
            snprintf(inpath, sizeof(inpath), "%s/%s", input_dir_path, name);
            decrypt_self_by_path(inpath, outpath, num_success, num_failed);
        }
    }

    closedir(dir);
    return 0;
}

int decrypt_all(const char* src_game, const char* dst_game) {
    int num_success = 0;
    int num_failed = 0;
    decrypt_all_selfs_in_directory("/mnt/sandbox/pfsmnt", dst_game, 1, &num_success, &num_failed);

    printf_notification("Decryption Done. Success: %d, Failed: %d", num_success, num_failed);
    return num_failed == 0;
}