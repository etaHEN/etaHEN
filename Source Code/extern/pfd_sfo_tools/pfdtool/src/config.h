#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "types.h"

int parse_config_file(const char *file_path, int (*handler)(void *, const char *, const char *, const char *), void *user);

#endif /* !_CONFIG_H_ */
