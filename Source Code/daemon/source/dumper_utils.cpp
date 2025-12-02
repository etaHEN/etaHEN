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

#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/sysctl.h>
#include "launcher.hpp"
#include <pthread.h>

#include <stdbool.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/stat.h>
#include "ipc.hpp"
#include <string>

extern "C"{
     #include "../../libSelfDecryptor/include/SelfDecryptor.h"
     int decrypt_game_dir(const char *source, const char *dest);
}
long totalSize = 0;
long copiedSoFar = 0;
clock_t lastTime = clock();
long lastBytes = 0;

std::string dump_message;
pthread_t notifyThread;
#define SELF_PROSPERO_MAGIC     0xEEF51454

void etaHEN_log(const char *fmt, ...);
bool if_exists(const char *path);
void notify(bool show_watermark, const char *text, ...);

bool rmtree(const char *path)
{
    DIR *dir = opendir(path);
    if (dir == NULL)
    {
        etaHEN_log("Error opening directory %s", path);
        return false;
    }

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL)
    {
        // Skip "." and ".." entries
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        char path_1[1000];
        snprintf(path_1, sizeof(path_1), "%s/%s", path, entry->d_name);

        if (entry->d_type == DT_DIR)
        {
            // Recursive call for subdirectories
            rmtree(path_1);
        }
        else
        {
            // Delete files
            if (unlink(path_1) != 0)
            {
                // perror("Error deleting file");
                etaHEN_log("Error deleting file %s", path);
            }
        }
    }

    closedir(dir);

    // Delete the empty folder
    if (rmdir(path) != 0)
    {
        // perror("Error deleting folder");
        etaHEN_log("Error deleting folder %s", path);
    }

    return true;
}

uint64_t calculateTotalSize(const char *path)
{
    long totalSize = 0;
    DIR *dir = opendir(path);
    struct dirent *entry;
    char fullPath[1024];

    if (dir == NULL)
    {
        notify(false, "calculateTotalSize failed for %s", path);
        return 0;
    }

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        snprintf(fullPath, sizeof(fullPath), "%s/%s", path, entry->d_name);
        struct stat st;
        if (stat(fullPath, &st) == 0)
        {
            if (S_ISDIR(st.st_mode))
            {
                totalSize += calculateTotalSize(fullPath);
            }
            else if (S_ISREG(st.st_mode))
            {
                totalSize += st.st_size;
            }
        }
    }

    closedir(dir);
    return totalSize;
}

static const char *sizes[] = {"EiB", "PiB", "TiB", "GiB", "MiB", "KiB", "B"};
static const uint64_t exbibytes = 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;

#define DIM(x) (sizeof(x) / sizeof(x[0]))

void calculateSize(uint64_t size, char *result)
{
    uint64_t multiplier = exbibytes;
    int i;

    for (i = 0; i < DIM(sizes); i++, multiplier /= 1024)
    {
        if (size < multiplier)
        {
            continue;
        }
        if (size % multiplier == 0)
        {
            sprintf(result, "%lu %s", size / multiplier, sizes[i]);
        }
        else
        {
            sprintf(result, "%.1f %s", (float)size / multiplier, sizes[i]);
        }

        return;
    }
    strcpy(result, "0");
}


bool copyFile(const char *source, const char *destination, bool for_dumper)
{

    FILE *src = fopen(source, "rb");
    if (src == NULL)
    {
        notify(false, "copyFile failed for %s", source);
        etaHEN_log("copyFile failed for %s", source);
        return false;
    }

    FILE *dest = fopen(destination, "wb");
    if (dest == NULL)
    {
        notify(false, "copyFile failed for %s", destination);
        etaHEN_log("copyFile failed for %s", destination);
        fclose(src);
        return false;
    }

    char buffer[1024];
    size_t bytes = 0;

    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0)
    {
        fwrite(buffer, 1, bytes, dest);
        if(for_dumper)
           copiedSoFar += bytes;
    }

    fclose(src);
    fclose(dest);

    return true;
}

bool copyRecursive(const char *source, const char *destination)
{

    struct dirent *entry;
    char srcPath[1024];
    char destPath[1024];

    DIR *dir = opendir(source);
    if (dir == NULL)
    {
        notify(false, "copyRecursive failed for %s", source);
        return false;
    }

    mkdir(destination, 0777);

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        snprintf(srcPath, sizeof(srcPath), "%s/%s", source, entry->d_name);
        snprintf(destPath, sizeof(destPath), "%s/%s", destination, entry->d_name);

        struct stat st;
        if (stat(srcPath, &st) == 0)
        {
            if (S_ISDIR(st.st_mode))
            {
                copyRecursive(srcPath, destPath);
            }
            else if (S_ISREG(st.st_mode))
            {
                if (!copyFile(srcPath, destPath, true))
                {
                    notify(false, "copyRecursive failed for %s", srcPath);
                    return false;
                }
            }
        }
    }

    closedir(dir);

    return true;
}

int decrypt_self(const char* path, const char* out_path) {
    int self_fd;
    uint64_t final_file_size;
    struct elf64_hdr_new* elf_header;
    struct elf64_phdr_new* start_phdrs;
    struct elf64_phdr_new* cur_phdr;
    struct sce_self_header* header;
    char* self_file_data;
    char* out_file_data;
    void* segment_data;
    char note_buf[0x1000];

    etaHEN_log("decrypt_self: path=[%s]", path);


    // Open SELF file
    self_fd = open(path, O_RDONLY);
    if (self_fd < 0) {
        etaHEN_log("Failed to open SELF file: %s", strerror(errno));
        return self_fd;
    }

    self_file_data = (char *) mmap(NULL, 0x1000, PROT_READ, MAP_SHARED, self_fd, 0);
    if (self_file_data == MAP_FAILED) {
        etaHEN_log("Failed to map self file errno: %d : %s", errno, strerror(errno));
        close(self_fd);
        return -ENOMEM;
    }

    header = (struct sce_self_header*)self_file_data;

    // Get ELF headers
    elf_header = (struct elf64_hdr_new*)(
        (char*)self_file_data + sizeof(struct sce_self_header) +
        (sizeof(struct sce_self_segment_header) * header->segment_count)
        );
    start_phdrs = (struct elf64_phdr_new*)((char*)(elf_header)+sizeof(struct elf64_hdr_new));

    // Allocate backing buffer for output file data. We'll get size by finding the NOTE program header which should be
    // in most SELFs
    cur_phdr = start_phdrs;
    final_file_size = 0;
    for (int i = 0; i < elf_header->e_phnum; i++) {
        final_file_size = MAX(final_file_size, cur_phdr->p_offset + cur_phdr->p_filesz);
        cur_phdr++;
    }

    if (final_file_size == 0) {
        munmap(self_file_data, 0x1000);
        close(self_fd);
        return -EINVAL;
    }

    // Map buffer for output data
    out_file_data = (char *) mmap(NULL, final_file_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (out_file_data == MAP_FAILED) {
        etaHEN_log("Failed to map out_file_data errno: %d : %s", errno, strerror(errno));
        munmap(self_file_data, 0x1000);
        close(self_fd);
        return -12;
    }

    // Copy ELF headers over
    memcpy(out_file_data, elf_header, sizeof(struct elf64_hdr_new));
    memcpy(out_file_data + sizeof(struct elf64_hdr_new), start_phdrs, elf_header->e_phnum * sizeof(struct elf64_phdr_new));

    // Decrypt and copy segments
    cur_phdr = start_phdrs;
    for (uint64_t i = 0; i < elf_header->e_phnum; i++) {
        if (cur_phdr->p_type == PT_LOAD || cur_phdr->p_type == 0x61000000) {
            //etaHEN_log("decrypt_self: seg=0x%lx\n", i);
            segment_data = mmap(NULL, cur_phdr->p_filesz, PROT_READ, MAP_SHARED | 0x80000, self_fd, (i << 32));
            if (segment_data == MAP_FAILED) {
                etaHEN_log("Failed to map segment_data errno: %d : %s", errno, strerror(errno));
                munmap(self_file_data, 0x1000);
                close(self_fd);
                return -EIO;
            }

            //etaHEN_log("decrypt_self: copying %p (size = 0x%lx)\n", segment_data, cur_phdr->p_filesz);
            //DumpHex(segment_data, 0x100);
            memcpy(out_file_data + cur_phdr->p_offset, segment_data, cur_phdr->p_filesz);
            //etaHEN_log("decrypt_self: unmap %p\n", segment_data);
            munmap(segment_data, cur_phdr->p_filesz);
            //etaHEN_log("decrypt_self: done\n");
        }

        if (cur_phdr->p_type == 0x6FFFFF00) {
            lseek(self_fd, cur_phdr->p_offset, SEEK_SET);
            read(self_fd, &note_buf, cur_phdr->p_filesz);
            memcpy(out_file_data + cur_phdr->p_offset, note_buf, cur_phdr->p_filesz);
        }
        cur_phdr++;
    }

    munmap(self_file_data, 0x1000);
    close(self_fd);

    // Write decrypted SELF to the specified USB path
    int out_fd = open(out_path, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (out_fd < 0) {
        munmap(out_file_data, final_file_size);
        etaHEN_log("Failed to open output file: %s", strerror(errno));
        return -EIO;
    }

    ssize_t written_bytes = write(out_fd, out_file_data, final_file_size);
    if (written_bytes != final_file_size) {
        munmap(out_file_data, final_file_size);
        close(out_fd);
        etaHEN_log("Failed to write entire output file: %s", strerror(errno));
        return -EIO;
    }

    munmap(out_file_data, final_file_size);
    close(out_fd);

    etaHEN_log("Successfully decrypted and saved to %s", out_path);
    return 0;
}
bool ends_with(const std::string& str, const std::string& suffix) {
    if (str.size() < suffix.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin());
}

 bool Check_ELF_Magic(const std::string & path, uint32_t FILE_MAGIC) {
  // Check for empty or pure whitespace path
  if (path.empty() || std::all_of(path.begin(), path.end(), [](char c) {
      return std::isspace(c);
    })) {
    etaHEN_log("Empty path argument!");
    return false;
  }

  int magic = 0;
  int file_fd = open(path.c_str(), O_RDONLY, 0);
  if (file_fd < 0) {
    etaHEN_log("Error opening file: %s", path.c_str());
    return false;
  }

  // Check if it's a Prospero SELF
  read(file_fd, (void * ) & magic, sizeof(magic));

  close(file_fd);
  return magic == FILE_MAGIC;

}
#define SELF_ORBIS_MAGIC        0x1D3D154F
bool decrypt_dir(const std::string& inputPath, const std::string& outputPath) {

    OrbisKernelSwVersion sys_ver;
    sceKernelGetProsperoSystemSwVersion(&sys_ver);
    bool alt_method = (sys_ver.version > 0x3000000);

    if (alt_method) {
        etaHEN_log("decrypt_self: using alt method");
        return decrypt_all(inputPath.c_str(), outputPath.c_str()) == 0;
    }
    DIR* dir = opendir(inputPath.c_str());
    if (!dir){
		etaHEN_log("Failed to open directory %s", inputPath.c_str());
		return false;
	}

    dirent* dp;
    bool result = true;  // Assume success unless proven otherwise

    while ((dp = readdir(dir)) != nullptr) {
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) continue;
        
        std::string sourcePath = inputPath + "/" + dp->d_name;
        std::string destinationPath = outputPath + "/" + dp->d_name;

        if (dp->d_type == DT_DIR) {
            mkdir(destinationPath.c_str(), 0777);
            if (!decrypt_dir(sourcePath, destinationPath)) {
                etaHEN_log("Failed to decrypt directory %s", sourcePath.c_str());
                result = false;
                break;  // Stop processing further and clean up
            }
        } else if (dp->d_type == DT_REG) {
            bool is_common_self_ext = ends_with(sourcePath, ".dll") || ends_with(sourcePath, ".bin") ||
                                      ends_with(sourcePath, ".prx") || ends_with(sourcePath, ".sprx") ||
                                      ends_with(sourcePath, ".elf");

            if(std::string(dp->d_name) == "right.sprx"){
                continue;
            }

            if (is_common_self_ext && (Check_ELF_Magic(sourcePath, SELF_PROSPERO_MAGIC ) || Check_ELF_Magic(sourcePath, SELF_ORBIS_MAGIC ) )) {
                if (decrypt_self(sourcePath.c_str(), destinationPath.c_str()) != 0) {
                    etaHEN_log("Failed to decrypt %s", sourcePath.c_str());
                    result = false;
                    break;  // Stop processing further and clean up
                }
                etaHEN_log("Decrypted %s", sourcePath.c_str());
            }
        }
    }

    closedir(dir);  // Ensure the directory is always closed
    return result;
}
