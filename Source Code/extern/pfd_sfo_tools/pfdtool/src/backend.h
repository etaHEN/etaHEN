#ifndef _PFD__BACKEND_H_
#define _PFD__BACKEND_H_

#include "types.h"
#include "list.h"
#include "pfd.h"

#define PFDTOOL_VERSION_BASE "0.2.3"
#define PFDTOOL_VERSION      PFDTOOL_VERSION_BASE

#define PFDTOOL_CONFIG_GLOBAL "global.conf"
#define PFDTOOL_CONFIG_GAMES  "games.conf"

#ifdef __cplusplus
extern "C" {
#endif

#define BACKEND_UPDATE_FLAG_NONE    (0)
#define BACKEND_UPDATE_FLAG_PARTIAL (1U << 0)

#define BACKEND_VALIDATE_FLAG_NONE    (0)
#define BACKEND_VALIDATE_FLAG_PARTIAL (1U << 0)

typedef struct secure_file_id_s {
	char file_path[MAX_PATH];
	char file_name[PFD_ENTRY_NAME_SIZE];
	u8 secure_file_id[PFD_PARAM_SFO_KEY_SIZE];
	u8 real_hash[PFD_HASH_SIZE];
	u8 *data;
	u64 data_size;
	int found;
} secure_file_id_t;

typedef struct structure_status_s {
	int top;
	int bottom;
} structure_status_t;

typedef struct entry_status_s {
	int signature;
} entry_status_t;

typedef struct file_status_s {
	char *file_name;
	int file;
	int cid;
	int dhk_cid2;
	int aid_uid;
} file_status_t;

typedef struct entry_info_s {
	u64 index;
	char *file_name;
	u64 file_size;
} entry_info_t;

typedef struct backend_s {
	pfd_config_t *config;
	list_t *secure_file_ids;
	pfd_context_t *pfd;

	union {
		struct {
			list_t *entries;
		} list;
		struct {
			structure_status_t structure;
			entry_status_t *entries;
			file_status_t *files;
		} validate;
	} storage;
} backend_t;

backend_t * backend_initialize(pfd_config_t *config, list_t *secure_file_ids, const char *directory_path);
int backend_shutdown(backend_t *ctx);

int backend_cmd_list(backend_t *ctx);
int backend_cmd_check(backend_t *ctx, u32 options);
int backend_cmd_update(backend_t *ctx, u32 options);
int backend_cmd_encrypt(backend_t *ctx, list_t *file_names);
int backend_cmd_decrypt(backend_t *ctx, list_t *file_names);
int backend_cmd_brute(backend_t *ctx, const char *file_path, u64 file_offset, s64 advance_offset, list_t *secure_file_ids);

#ifdef __cplusplus
}
#endif

#endif /* !_PFD__BACKEND_H_ */
