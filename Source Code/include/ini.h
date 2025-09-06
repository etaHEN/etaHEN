/* inih -- simple .INI file parser

SPDX-License-Identifier: BSD-3-Clause

Copyright (C) 2009-2020, Ben Hoyt

inih is released under the New BSD license (see LICENSE.txt). Go to the project
home page for more info:

https://github.com/benhoyt/inih

*/

#ifndef INI_H
#define INI_H

#include <stdio.h>
#include <unistd.h>

/* Make this header file easier to include in C++ code */
#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LINE 256
#define MAX_PAIRS 100

typedef struct {
    char key[MAX_LINE];
    char value[MAX_LINE];
} KeyValue;

typedef struct {
    KeyValue pairs[MAX_PAIRS];
    int count;
} IniParser;


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>

static void trim(char* str) {
    char* end = 0;
    // Trim leading space
    while (isspace((unsigned char)*str)) str++;

    // Trim trailing space
    if (*str == 0) return;

    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator
    *(end + 1) = 0;
}
static char* my_strchr(const char* str, int c) {
    while (*str != '\0') {
        if (*str == (char)c) {
            return (char*)str;
        }
        str++;
    }
    return NULL;
}
static int ini_parser_load(IniParser* parser, const char* filename) {
    int fd = open(filename, O_RDONLY, 0);
    if (fd < 0) {
        return 0;
    }
    parser->count = 0;

    char buffer[MAX_LINE];
    ssize_t bytesRead;
    int bufferIndex = 0;
    char section[MAX_LINE] = "";

    while ((bytesRead = read(fd, buffer + bufferIndex, sizeof(buffer) - bufferIndex - 1)) > 0) {
        buffer[bytesRead + bufferIndex] = '\0';
        bufferIndex += bytesRead;
        char* line = buffer;
        char* lineEnd;

        //shellui_log("Buffer: %s", buffer);

        while ((lineEnd = my_strchr(line, '\n')) != NULL) {
            *lineEnd = '\0';
            char trimmedLine[MAX_LINE];
            strncpy(trimmedLine, line, MAX_LINE);
            trim(trimmedLine);

            if (trimmedLine[0] == ';' || trimmedLine[0] == '#' || trimmedLine[0] == '\0') {
                // Skip comments and empty lines
            }
            else if (trimmedLine[0] == '[' && trimmedLine[strlen(trimmedLine) - 1] == ']') {
                // Section header
                strncpy(section, trimmedLine + 1, strlen(trimmedLine) - 2);
                section[strlen(trimmedLine) - 2] = '\0';
                trim(section);
            }
            else {
                // Key-value pair
                char* delimiter = my_strchr(trimmedLine, '=');
                if (delimiter) {
                    *delimiter = '\0';
                    char key[MAX_LINE];
                    sprintf(key, "%s.%s", section, trimmedLine);
                    trim(key);
                    char* value = delimiter + 1;
                    trim(value);

                    if (parser->count < MAX_PAIRS) {
                        strncpy(parser->pairs[parser->count].key, key, MAX_LINE);
                        strncpy(parser->pairs[parser->count].value, value, MAX_LINE);
                        parser->count++;
                    }
                }
            }

            line = lineEnd + 1;
        }

        bufferIndex = strlen(line);
        memmove(buffer, line, bufferIndex);
    }

    close(fd);
    return 1;
}


static const char* ini_parser_get(IniParser* parser, const char* key, const char* default_value) {
    for (int i = 0; i < parser->count; i++) {
        if (strcmp(parser->pairs[i].key, key) == 0) {
            return parser->pairs[i].value;
        }
    }
    return default_value;
}


#ifdef __cplusplus
}
#endif

#endif /* INI_H */
