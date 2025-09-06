#include "config.h"

#define CONFIG_MAX_LINE_SIZE 1024
#define CONFIG_MAX_SECTION_SIZE 128
#define CONFIG_MAX_NAME_SIZE 128

static char * safe_strncpy(char *dst, const char* src, size_t size) {
    strncpy(dst, src, size);
    dst[size - 1] = '\0';
    return dst;
}

static char * rstrip(char *s)
{
	char *p = s + strlen(s);
	while (p > s && isspace(*--p))
		*p = '\0';
	return s;
}

static char * lskip(const char *s) {
	while (*s != '\0' && isspace(*s))
		++s;
	return (char *)s;
}

static char * find_char_or_comment(const char *s, char c) {
	int was_whitespace = 0;
	while (*s != '\0' && *s != c && !(was_whitespace && *s == ';')) {
		was_whitespace = isspace(*s);
		++s;
	}
	return (char *)s;
}

int parse_config_file(const char *file_path, int (*handler)(void *, const char *, const char *, const char *), void *user) {
	char line_buf[CONFIG_MAX_LINE_SIZE];
	FILE *fp;

	char section[CONFIG_MAX_SECTION_SIZE];
	char prev_name[CONFIG_MAX_NAME_SIZE];

	char *name;
	char *value;
	char *start;
	char *end;

	int line;
	int error_line;

	fp = fopen(file_path, "r");
	if (!fp)
		return -1;

	memset(line_buf, 0, CONFIG_MAX_LINE_SIZE);
	memset(section, 0, CONFIG_MAX_SECTION_SIZE);
	memset(prev_name, 0, CONFIG_MAX_NAME_SIZE);

	line = 0;
	error_line = 0;

	while (fgets(line_buf, CONFIG_MAX_LINE_SIZE, fp) != NULL) {
		++line;

		start = line_buf;
		start = lskip(rstrip(start));

		if (*start == ';') {
		} else if (*start == '[') { /* a "[section]" line */
			end = find_char_or_comment(start + 1, ']');
			if (*end == ']') {
				*end = '\0';
				safe_strncpy(section, start + 1, CONFIG_MAX_SECTION_SIZE);
				*prev_name = '\0';
			}
			else if (!error_line) {
				error_line = line; /* no ']' found on section line */
			}
		} else if (*start != '\0' && *start != ';') { /* not a comment, must be a name[=:]value pair */
			end = find_char_or_comment(start, '=');
            if (*end != '=') {
                end = find_char_or_comment(start, ':');
            }
            if (*end == '=' || *end == ':') {
                *end = '\0';
                name = rstrip(start);
                value = lskip(end + 1);
                end = find_char_or_comment(value, '\0');
                if (*end == ';')
                    *end = '\0';
                rstrip(value);

                /* valid name[=:]value pair found, call handler */
                safe_strncpy(prev_name, name, CONFIG_MAX_NAME_SIZE);
                if ((*handler)(user, section, name, value) != 0 && !error_line)
                    error_line = line;
			} else if (!error_line) {
				/* no '=' or ':' found on name[=:]value line */
				error_line = line;
			}
		}
	}	

	fclose(fp);

	return error_line;
}
