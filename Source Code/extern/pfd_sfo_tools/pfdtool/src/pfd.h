#ifndef _PFD__PFD_H_
#define _PFD__PFD_H_

#include "types.h"
#include "list.h"

#define PFD_KEY_SIZE 16
#define PFD_HASH_KEY_SIZE 20
#define PFD_HASH_SIZE 20
#define PFD_ENTRY_NAME_SIZE 65

#define PFD_AUTHENTICATION_ID_SIZE 8
#define PFD_CONSOLE_ID_SIZE 16
#define PFD_USER_ID_SIZE 8
#define PFD_SYSCON_MANAGER_KEY_SIZE 16
#define PFD_KEYGEN_KEY_SIZE 20
#define PFD_PARAM_SFO_KEY_SIZE 20
#define PFD_TROPSYS_DAT_KEY_SIZE 20
#define PFD_TROPUSR_DAT_KEY_SIZE 20
#define PFD_TROPTRNS_DAT_KEY_SIZE 20
#define PFD_TROPCONF_SFM_KEY_SIZE 20
#define PFD_DISC_HASH_KEY_SIZE 16
#define PFD_SECURE_FILE_ID_SIZE 16

#define PFD_ENTRY_HASH_FILE          0
#define PFD_ENTRY_HASH_FILE_CID      1
#define PFD_ENTRY_HASH_FILE_DHK_CID2 2
#define PFD_ENTRY_HASH_FILE_AID_UID  3

#define PFD_CONTINUE (0)
#define PFD_STOP (-1)

#define PFD_VALIDATE_TYPE_TOP           (1U << 0)
#define PFD_VALIDATE_TYPE_BOTTOM        (1U << 1)
#define PFD_VALIDATE_TYPE_ENTRY         (1U << 3)
#define PFD_VALIDATE_TYPE_FILE          (1U << 4)
#define PFD_VALIDATE_TYPE_FILE_CID      (1U << 5)
#define PFD_VALIDATE_TYPE_FILE_DHK_CID2 (1U << 6)
#define PFD_VALIDATE_TYPE_FILE_AID_UID  (1U << 7)
#define PFD_VALIDATE_TYPE_STRUCTURE     (PFD_VALIDATE_TYPE_TOP | PFD_VALIDATE_TYPE_BOTTOM)
#define PFD_VALIDATE_TYPE_FILE_ALL      (PFD_VALIDATE_TYPE_FILE | PFD_VALIDATE_TYPE_FILE_CID | PFD_VALIDATE_TYPE_FILE_DHK_CID2 | PFD_VALIDATE_TYPE_FILE_AID_UID)
#define PFD_VALIDATE_TYPE_ALL           (PFD_VALIDATE_TYPE_STRUCTURE | PFD_VALIDATE_TYPE_ENTRY | PFD_VALIDATE_TYPE_FILE_ALL)

#define PFD_VALIDATE_SUCCESS         (0)
#define PFD_VALIDATE_FAILURE_HASH    (-1)
#define PFD_VALIDATE_FAILURE_NO_DATA (-2)
#define PFD_VALIDATE_FAILURE_FILE    (-3)

#define PFD_UPDATE_TYPE_FILE          (1U << 0)
#define PFD_UPDATE_TYPE_FILE_CID      (1U << 1)
#define PFD_UPDATE_TYPE_FILE_DHK_CID2 (1U << 2)
#define PFD_UPDATE_TYPE_FILE_AID_UID  (1U << 3)
#define PFD_UPDATE_TYPE_ALL           (PFD_UPDATE_TYPE_FILE | PFD_UPDATE_TYPE_FILE_CID | PFD_UPDATE_TYPE_FILE_DHK_CID2 | PFD_UPDATE_TYPE_FILE_AID_UID)

#define PFD_UPDATE_SUCCESS         (0)
#define PFD_UPDATE_FAILURE_NO_DATA (-1)
#define PFD_UPDATE_FAILURE_FILE    (-2)

typedef struct pfd_config_s {
	u8 authentication_id[PFD_AUTHENTICATION_ID_SIZE];
	u8 console_id[PFD_CONSOLE_ID_SIZE];
	u8 user_id[PFD_USER_ID_SIZE];
	u8 syscon_manager_key[PFD_SYSCON_MANAGER_KEY_SIZE];
	u8 keygen_key[PFD_KEYGEN_KEY_SIZE];
	u8 savegame_param_sfo_key[PFD_PARAM_SFO_KEY_SIZE];
	u8 trophy_param_sfo_key[PFD_PARAM_SFO_KEY_SIZE];
	u8 tropsys_dat_key[PFD_TROPSYS_DAT_KEY_SIZE];
	u8 tropusr_dat_key[PFD_TROPUSR_DAT_KEY_SIZE];
	u8 troptrns_dat_key[PFD_TROPTRNS_DAT_KEY_SIZE];
	u8 tropconf_sfm_key[PFD_TROPCONF_SFM_KEY_SIZE];
	u8 fallback_disc_hash_key[PFD_DISC_HASH_KEY_SIZE];
	u8 disc_hash_key[PFD_DISC_HASH_KEY_SIZE];
} pfd_config_t;

typedef struct pfd_info_s {
	u64 version;
	u64 capacity;
	u64 num_used_entries;
	u64 num_reserved_entries;
	int is_trophy;
} pfd_info_t;

typedef struct pfd_entry_info_s {
	u64 index;
	char file_name[PFD_ENTRY_NAME_SIZE];
	u64 file_size;
} pfd_entry_info_t;

typedef struct pfd_validation_result_s {
	int status;

	union {
		struct {
			u64 index;
			s32 is_occupied;
			char file_name[PFD_ENTRY_NAME_SIZE];
		} entry;

		struct {
			u64 entry_index;
			char file_name[PFD_ENTRY_NAME_SIZE];
		} file;
	};
} pfd_validation_status_t;

typedef struct pfd_context_s pfd_context_t;

typedef int (*pfd_enumerate_callback_pfn)(
	void *user,
	pfd_entry_info_t *entry_info
);

typedef int (*pfd_validate_callback_pfn)(
	void *user,
	u32 type,
	pfd_validation_status_t *status
);

typedef u8 * (*pfd_get_secure_file_id_callback_pfn)(
	void *user,
	const char *file_name
);

#ifdef __cplusplus
extern "C" {
#endif

/*! */
pfd_context_t * pfd_init(
	pfd_config_t *config,
	const char *directory_path,
	pfd_enumerate_callback_pfn enumerate_callback,
	pfd_validate_callback_pfn validate_callback,
	pfd_get_secure_file_id_callback_pfn get_secure_file_id_callback,
	void *user
);

/*! */
int pfd_destroy(pfd_context_t *ctx);

/*! */
int pfd_import(pfd_context_t *ctx);

/*! */
int pfd_export(pfd_context_t *ctx);

/*! */
int pfd_get_info(pfd_context_t *ctx, pfd_info_t *info);

/*! */
int pfd_validate(pfd_context_t *ctx, u32 type);

/*! */
int pfd_update(pfd_context_t *ctx, u32 type);

/*! */
int pfd_encrypt_file(pfd_context_t *ctx, const char *file_name);

/*! */
int pfd_decrypt_file(pfd_context_t *ctx, const char *file_name);

/*! */
int pfd_get_hash_key_from_secure_file_id(pfd_context_t *ctx, const u8 *secure_file_id, u8 hash_key[PFD_HASH_KEY_SIZE], u32 *hash_key_size);

/*! */
int pfd_get_file_hash(pfd_context_t *ctx, const char *file_name, u32 type, u8 hash[PFD_HASH_SIZE]);

/*! */
int pfd_get_file_path(pfd_context_t *ctx, const char *file_name, char *file_path, u32 max_length);

/*! */
int pfd_enumerate(pfd_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* !_PFD__PFD_H_ */
