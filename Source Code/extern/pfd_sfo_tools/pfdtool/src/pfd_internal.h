#ifndef _PFD__PFD_INTERNAL_H_
#define _PFD__PFD_INTERNAL_H_

#define PFD_MAGIC 0x50464442ull
#define PFD_VERSION_V3 0x3ULL
#define PFD_VERSION_V4 0x4ULL

#define PFD_ENTRY_INDEX_SIZE 8
#define PFD_ENTRY_KEY_SIZE 64
#define PFD_ENTRY_HASHED_DATA_SIZE 257
#define PFD_ENTRY_DATA_SIZE 192
#define PFD_ENTRY_SIZE 272
#define PFD_FILE_SIZE_ALIGNMENT 16
#define PFD_MAX_FILE_SIZE 32768

#define PFD_HEADER_OFFSET 0
#define PFD_HEADER_SIZE 16

#define PFD_HEADER_KEY_OFFSET (PFD_HEADER_OFFSET + PFD_HEADER_SIZE)
#define PFD_HEADER_KEY_SIZE 16

#define PFD_SIGNATURE_OFFSET (PFD_HEADER_KEY_OFFSET + PFD_HEADER_KEY_SIZE)
#define PFD_SIGNATURE_SIZE 64

#define PFD_HASH_TABLE_OFFSET (PFD_SIGNATURE_OFFSET + PFD_SIGNATURE_SIZE)
#define PFD_HASH_TABLE_HEADER_SIZE 24
#define PFD_HASH_TABLE_SIZE(_hash_table) (PFD_HASH_TABLE_HEADER_SIZE + ES64(_hash_table->capacity) * PFD_ENTRY_INDEX_SIZE)

#define PFD_ENTRY_TABLE_OFFSET(_hash_table) (PFD_HASH_TABLE_OFFSET + PFD_HASH_TABLE_HEADER_SIZE + ES64(_hash_table->capacity) * PFD_ENTRY_INDEX_SIZE)
#define PFD_ENTRY_TABLE_SIZE(_hash_table) (ES64(_hash_table->capacity) * PFD_ENTRY_INDEX_SIZE)

#define PFD_ENTRY_SIGNATURE_TABLE_OFFSET(_hash_table) (PFD_ENTRY_TABLE_OFFSET(_hash_table) + ES64(_hash_table->num_reserved) * PFD_ENTRY_SIZE)
#define PFD_ENTRY_SIGNATURE_TABLE_SIZE(_hash_table) (ES64(_hash_table->capacity) * PFD_HASH_SIZE)

#pragma pack(push, 1)

typedef char pfd_entry_name_t[PFD_ENTRY_NAME_SIZE];
typedef u8 pfd_key_t[PFD_KEY_SIZE];
typedef u8 pfd_hash_key_t[PFD_HASH_KEY_SIZE];
typedef u8 pfd_hash_t[PFD_HASH_SIZE];
typedef u8 pfd_entry_key_t[PFD_ENTRY_KEY_SIZE];

typedef struct {
	u64 magic;
	u64 version;
} pfd_header_t;

typedef pfd_key_t pfd_header_key_t;

typedef struct {
	union {
		struct {
			pfd_hash_t bottom_hash;
			pfd_hash_t top_hash;
			pfd_hash_key_t hash_key;
		};
		u8 buf[PFD_SIGNATURE_SIZE];
	};
} pfd_signature_t;

typedef u64 pfd_entry_index_t;

typedef struct {
	union {
		struct {
			u64 capacity;
			u64 num_reserved;
			u64 num_used;
			pfd_entry_index_t entries[1];
		};
		u8 buf[1];
	};
} pfd_hash_table_t;

typedef struct {
	union {
		struct {
			pfd_entry_index_t additional_index;
			pfd_entry_name_t file_name;
			u8 __padding_0[7];
			pfd_entry_key_t key;
			pfd_hash_t file_hashes[4];
			u8 __padding_1[40];
			u64 file_size;
		};
		u8 buf[PFD_ENTRY_SIZE];
	};
} pfd_entry_t;

typedef struct {
	 pfd_entry_t entries[1];
} pfd_entry_table_t;

typedef struct {
	union {
		pfd_hash_t hashes[1];
		u8 buf[1];
	};
} pfd_entry_signature_table_t;

#pragma pack(pop)

struct pfd_context_s {
	pfd_config_t *config;
	
	void *user;
	pfd_enumerate_callback_pfn enumerate_callback;
	pfd_validate_callback_pfn validate_callback;
	pfd_get_secure_file_id_callback_pfn get_secure_file_id_callback;

	char directory_path[MAX_PATH];

	u8 *data;
	u8 *temp_data;
	u64 data_size;

	pfd_header_t *header;
	pfd_header_key_t *header_key;
	pfd_signature_t *signature;
	pfd_hash_table_t *hash_table;
	pfd_entry_table_t *entry_table;
	pfd_entry_signature_table_t *entry_signature_table;

	u8 real_hash_key[PFD_HASH_KEY_SIZE];

	int is_trophy;
};

#endif /* !_PFD__PFD_INTERNAL_H_ */
