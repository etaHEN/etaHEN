#include "pfd.h"
#include "util.h"

#include <polarssl/aes.h>
#include <polarssl/sha1.h>
#include <stdlib.h>
#include "pfd_internal.h"
#include "types.h"

static int pfd_encrypt_with_portability(pfd_context_t *ctx, u8 key[16], u8 *data, u32 data_size) {
	u8 iv[16];
	aes_context aes;

	if (!ctx)
		return -1;

	memset(&aes, 0, sizeof(aes_context));
	memcpy(iv, key, 16);

	aes_setkey_enc(&aes, ctx->config->syscon_manager_key, 128);
	aes_crypt_cbc(&aes, AES_ENCRYPT, data_size, iv, data, data);

	return 0;
}

static int pfd_decrypt_with_portability(pfd_context_t *ctx, u8 key[16], u8 *data, u32 data_size) {
	u8 iv[16];
	aes_context aes;

	if (!ctx)
		return -1;

	memset(&aes, 0, sizeof(aes_context));
	memcpy(iv, key, 16);

	aes_setkey_dec(&aes, ctx->config->syscon_manager_key, 128);
	aes_crypt_cbc(&aes, AES_DECRYPT, data_size, iv, data, data);

	return 0;
}

static int pfd_build_file_path(pfd_context_t *ctx, const char *file_name, char *file_path, u64 max_length) {
	if (!ctx)
		return -1;

	if (!file_name || !file_path)
		return -1;

	snprintf(file_path, max_length, "%s%s", ctx->directory_path, file_name);

	return 0;
}

static u64 pfd_calculate_hash_table_entry_index(pfd_context_t *ctx, const char *file_name) {
	u64 hash;
	u64 len;
	u64 i;

	if (!ctx)
		return -1;

	if (!file_name)
		return -1;

	len = strlen(file_name);
	hash = 0;

	for (i = 0; i < len; ++i)
		hash = (hash << 5) - hash + (u8)file_name[i];
	return hash % ES64(ctx->hash_table->capacity);
}

static pfd_entry_t * pfd_get_entry_by_index(pfd_context_t *ctx, u64 entry_index) {
	if (!ctx)
		return NULL;

	if (entry_index == -1 || entry_index >= ES64(ctx->hash_table->num_used))
		return NULL;

	return &ctx->entry_table->entries[entry_index];
}

static int pfd_get_entry_by_name(pfd_context_t *ctx, const char *file_name, u64 *entry_index) {
	pfd_entry_t *entry;
	u64 hash_table_entry_index;
	u64 additional_entry_idx;
	u64 current_entry_idx;

	if (!ctx)
		return -1;

	if (!entry_index)
		return -1;

	hash_table_entry_index = pfd_calculate_hash_table_entry_index(ctx, file_name);
	current_entry_idx = ES64(ctx->hash_table->entries[hash_table_entry_index]);

	if (current_entry_idx < ES64(ctx->hash_table->num_reserved)) {
		while (current_entry_idx < ES64(ctx->hash_table->num_reserved)) {
			entry = &ctx->entry_table->entries[current_entry_idx];
			additional_entry_idx = ES64(entry->additional_index);
			if (strncasecmp(entry->file_name, file_name, PFD_ENTRY_NAME_SIZE) == 0) {
				*entry_index = current_entry_idx;
				return 0;
			}
			current_entry_idx = additional_entry_idx;
		}
	}

	return -1;
}

static int pfd_build_entry_file_path(pfd_context_t *ctx, pfd_entry_t *entry, char *file_path, u64 max_length) {
	if (!ctx)
		return -1;

	if (!entry || !file_path)
		return -1;

	if (pfd_build_file_path(ctx, entry->file_name, file_path, max_length) < 0)
		return -1;

	return 0;
}

static int pfd_check_entry_file_name(pfd_context_t *ctx, pfd_entry_t *entry, const char *file_name) {
	if (!ctx)
		return -1;

	if (!entry || !file_name)
		return -1;

	return strncasecmp(entry->file_name, file_name, PFD_ENTRY_NAME_SIZE) == 0 ? 1 : 0;
}

static int pfd_get_entry_aligned_size(pfd_context_t *ctx, pfd_entry_t *entry, u64 *file_size) {
	if (!ctx)
		return -1;

	if (!entry || !file_size)
		return -1;

	*file_size = align_to_pow2(ES64(entry->file_size), PFD_FILE_SIZE_ALIGNMENT);

	return 0;
}

static int pfd_get_entry_size(pfd_context_t *ctx, pfd_entry_t *entry, u64 *file_size) {
	if (!ctx)
		return -1;

	if (!entry || !file_size)
		return -1;

	*file_size = ES64(entry->file_size);

	return 0;
}

static int pfd_generate_hash_key_for_secure_file_id(pfd_context_t *ctx, pfd_hash_key_t hash_key, u32 *hash_key_size, const u8 *secure_file_id) {
	int i, j;

	if (!ctx)
		return -1;

	if (!secure_file_id || !hash_key || !hash_key_size)
		return -1;

	memset(hash_key, 0, PFD_HASH_KEY_SIZE);
	memcpy(hash_key, secure_file_id, PFD_SECURE_FILE_ID_SIZE);

	for (i = 0, j = 0; i < PFD_HASH_KEY_SIZE; ++i) {
		switch (i) {
			case 1: hash_key[i] = 11; break;
			case 2: hash_key[i] = 15; break;
			case 5: hash_key[i] = 14; break;
			case 8: hash_key[i] = 10; break;
			default:
				hash_key[i] = secure_file_id[j++];
				break;
		}
	}

	*hash_key_size = PFD_HASH_KEY_SIZE;

	return 0;
}

static int pfd_generate_hash_key_for_param_sfo(pfd_context_t *ctx, pfd_hash_key_t hash_key, u32 *hash_key_size, int entry_hash_index) {
	int i, j;

	if (!ctx)
		return -1;

	if (!hash_key || !hash_key_size)
		return -1;

	if (!ctx->is_trophy) {
		if (entry_hash_index != PFD_ENTRY_HASH_FILE && entry_hash_index != PFD_ENTRY_HASH_FILE_CID && entry_hash_index != PFD_ENTRY_HASH_FILE_DHK_CID2 && entry_hash_index != PFD_ENTRY_HASH_FILE_AID_UID)
			return -1;

		switch (entry_hash_index) {
			case PFD_ENTRY_HASH_FILE:
				memset(hash_key, 0, PFD_HASH_KEY_SIZE);
				memcpy(hash_key, ctx->config->savegame_param_sfo_key, PFD_PARAM_SFO_KEY_SIZE);
				*hash_key_size = PFD_PARAM_SFO_KEY_SIZE;
				break;
			case PFD_ENTRY_HASH_FILE_CID:
				memset(hash_key, 0, PFD_HASH_KEY_SIZE);
				memcpy(hash_key, ctx->config->console_id, PFD_CONSOLE_ID_SIZE);
				*hash_key_size = PFD_CONSOLE_ID_SIZE;
				break;
			case PFD_ENTRY_HASH_FILE_DHK_CID2:
				memset(hash_key, 0, PFD_HASH_KEY_SIZE);
				memcpy(hash_key, ctx->config->disc_hash_key, PFD_DISC_HASH_KEY_SIZE);
				*hash_key_size = PFD_DISC_HASH_KEY_SIZE;
				break;
			case PFD_ENTRY_HASH_FILE_AID_UID:
				memset(hash_key, 0, PFD_HASH_KEY_SIZE);
				memcpy(hash_key, ctx->config->authentication_id, PFD_AUTHENTICATION_ID_SIZE);
				*hash_key_size = PFD_AUTHENTICATION_ID_SIZE;
				break;
			default:
				return -1;
		}
	} else {
		if (entry_hash_index != PFD_ENTRY_HASH_FILE && entry_hash_index != PFD_ENTRY_HASH_FILE_DHK_CID2 && entry_hash_index != PFD_ENTRY_HASH_FILE_AID_UID)
			return -1;

		switch (entry_hash_index) {
			case PFD_ENTRY_HASH_FILE:
				memset(hash_key, 0, PFD_HASH_KEY_SIZE);
				memcpy(hash_key, ctx->config->trophy_param_sfo_key, PFD_PARAM_SFO_KEY_SIZE);
				*hash_key_size = PFD_PARAM_SFO_KEY_SIZE;
				break;
			case PFD_ENTRY_HASH_FILE_DHK_CID2:
				memset(hash_key, 0, PFD_HASH_KEY_SIZE);
				for (i = 0, j = 0; i < PFD_HASH_KEY_SIZE; ++i) {
					switch (i) {
						case 4: hash_key[i] = 11; break;
						case 8: hash_key[i] = 10; break;
						case 9: hash_key[i] = 14; break;
						case 10: hash_key[i] = 15; break;
						default:
							hash_key[i] = ctx->config->console_id[j++];
							break;
					}
				}
				*hash_key_size = PFD_HASH_KEY_SIZE;
				break;
			case PFD_ENTRY_HASH_FILE_AID_UID:
				memset(hash_key, 0, PFD_HASH_KEY_SIZE);
				for (i = 0, j = 0; i < PFD_HASH_KEY_SIZE; ++i) {
					hash_key[i] = ctx->config->user_id[j];
					switch (i) {
						case 3: hash_key[i] = 11; break;
						case 7: hash_key[i] = 14; break;
						default:
							hash_key[i] = ctx->config->user_id[j++ % 8];
							break;
					}
				}
				*hash_key_size = PFD_HASH_KEY_SIZE;
				break;
			default:
				return -1;
		}
	}

	return 0;
}

static int pfd_get_entry_hash_key(pfd_context_t *ctx, pfd_entry_t *entry, pfd_hash_key_t hash_key, u32 *hash_key_size, int entry_hash_index) {
	u8 *key;
	u32 key_length;

	if (!ctx)
		return -1;

	if (!entry || !hash_key || !hash_key_size)
		return -1;

	 if (entry_hash_index != PFD_ENTRY_HASH_FILE && entry_hash_index != PFD_ENTRY_HASH_FILE_CID && entry_hash_index != PFD_ENTRY_HASH_FILE_DHK_CID2 && entry_hash_index != PFD_ENTRY_HASH_FILE_AID_UID)
		 return -1;

	if (strncasecmp(entry->file_name, "PARAM.SFO", PFD_ENTRY_NAME_SIZE) == 0) {
		if (pfd_generate_hash_key_for_param_sfo(ctx, hash_key, hash_key_size, entry_hash_index) < 0)
			return -1;
	} else if (strncasecmp(entry->file_name, "TROPSYS.DAT", PFD_ENTRY_NAME_SIZE) == 0) {
		memset(hash_key, 0, PFD_HASH_KEY_SIZE);
		memcpy(hash_key, ctx->config->tropsys_dat_key, PFD_TROPSYS_DAT_KEY_SIZE);
		*hash_key_size = PFD_TROPSYS_DAT_KEY_SIZE;
	} else if (strncasecmp(entry->file_name, "TROPUSR.DAT", PFD_ENTRY_NAME_SIZE) == 0) {
		memset(hash_key, 0, PFD_HASH_KEY_SIZE);
		memcpy(hash_key, ctx->config->tropusr_dat_key, PFD_TROPUSR_DAT_KEY_SIZE);
		*hash_key_size = PFD_TROPUSR_DAT_KEY_SIZE;
	} else if (strncasecmp(entry->file_name, "TROPTRNS.DAT", PFD_ENTRY_NAME_SIZE) == 0) {
		memset(hash_key, 0, PFD_HASH_KEY_SIZE);
		memcpy(hash_key, ctx->config->troptrns_dat_key, PFD_TROPTRNS_DAT_KEY_SIZE);
		*hash_key_size = PFD_TROPTRNS_DAT_KEY_SIZE;
	} else if (strncasecmp(entry->file_name, "TROPCONF.SFM", PFD_ENTRY_NAME_SIZE) == 0) {
		memset(hash_key, 0, PFD_HASH_KEY_SIZE);
		memcpy(hash_key, ctx->config->tropconf_sfm_key, PFD_TROPCONF_SFM_KEY_SIZE);
		*hash_key_size = PFD_TROPCONF_SFM_KEY_SIZE;
	} else if (ctx->get_secure_file_id_callback) {
		key = ctx->get_secure_file_id_callback(ctx->user, entry->file_name);
		key_length = PFD_SECURE_FILE_ID_SIZE;

		if (!key || !key_length)
			return -1;

		if (pfd_generate_hash_key_for_secure_file_id(ctx, hash_key, hash_key_size, key) < 0)
			return -1;
	} else {
		return -1;
	}

	return 0;
}

static int pfd_get_entry_key(pfd_context_t *ctx, pfd_entry_t *entry, pfd_entry_key_t entry_key) {
	pfd_hash_key_t hash_key;
	u32 hash_key_size;

	if (!ctx)
		return -1;

	if (!entry || !entry_key)
		return -1;

	if (pfd_get_entry_hash_key(ctx, entry, hash_key, &hash_key_size, PFD_ENTRY_HASH_FILE) < 0)
		return -1;

	memcpy(entry_key, entry->key, PFD_ENTRY_KEY_SIZE);

	if (pfd_decrypt_with_portability(ctx, hash_key, entry_key, PFD_ENTRY_KEY_SIZE) < 0)
		return -1;

	return 0;
}

static int pfd_calculate_entry_hash(pfd_context_t *ctx, pfd_entry_t *entry, u8 hash[PFD_HASH_SIZE]) {
	sha1_context sha1;
	u64 hash_table_entry_index;
	u64 current_entry_index;

	if (!ctx)
		return -1;

	if (!entry || !hash)
		return -1;

	hash_table_entry_index = pfd_calculate_hash_table_entry_index(ctx, entry->file_name);
	current_entry_index = ES64(ctx->hash_table->entries[hash_table_entry_index]);

	if (current_entry_index < ES64(ctx->hash_table->num_reserved)) {
		memset(&sha1, 0, sizeof(sha1_context));

		sha1_hmac_starts(&sha1, ctx->real_hash_key, PFD_HASH_KEY_SIZE);

		while (current_entry_index < ES64(ctx->hash_table->num_reserved)) {
			entry = &ctx->entry_table->entries[current_entry_index];
			sha1_hmac_update(&sha1, (const u8 *)entry->file_name, PFD_ENTRY_NAME_SIZE);
			sha1_hmac_update(&sha1, entry->key, PFD_ENTRY_DATA_SIZE);
			current_entry_index = ES64(entry->additional_index);
		}

		sha1_hmac_finish(&sha1, hash);

		memset(&sha1, 0, sizeof(sha1_context));

		return 0;
	}

	return -1;
}

static int pfd_calculate_top_hash(pfd_context_t *ctx, u8 hash[PFD_HASH_SIZE]) {
	if (!ctx)
		return -1;

	sha1_hmac(ctx->real_hash_key, PFD_HASH_KEY_SIZE, ctx->hash_table->buf, PFD_HASH_TABLE_SIZE(ctx->hash_table), hash);

	return 0;
}

static int pfd_calculate_bottom_hash(pfd_context_t *ctx, u8 hash[PFD_HASH_SIZE]) {
	if (!ctx)
		return -1;

	sha1_hmac(ctx->real_hash_key, PFD_HASH_KEY_SIZE, ctx->entry_signature_table->buf, PFD_ENTRY_SIGNATURE_TABLE_SIZE(ctx->hash_table), hash);

	return 0;
}

static int pfd_calculate_default_hash(pfd_context_t *ctx, u8 hash[PFD_HASH_SIZE]) {
	if (!ctx)
		return -1;

	sha1_hmac(ctx->real_hash_key, PFD_HASH_KEY_SIZE, NULL, 0, hash);

	return 0;
}

static int pfd_calculate_entry_file_hash(pfd_context_t *ctx, pfd_entry_t *entry, u8 *hash_key, u32 hash_key_size, u8 hash[PFD_HASH_SIZE]) {
	char file_path[MAX_PATH];

	if (!ctx)
		return -1;

	if (!entry || !hash_key || !hash_key_size || !hash)
		return -1;

	if (pfd_build_file_path(ctx, entry->file_name, file_path, MAX_PATH) < 0)
		return -1;

	if (calculate_file_hmac_hash(file_path, hash_key, hash_key_size, hash) < 0)
		return -1;

	return 0;
}

static int pfd_encrypt_data(pfd_context_t *ctx, u8 key[PFD_ENTRY_KEY_SIZE], u8 *data, u64 data_size) {
	u8 counter_key[16];
	aes_context aes1, aes2;
	u64 block_len, num_blocks;
	u8 *block_data;
	u64 i, j;

	if (!ctx)
		return -1;

	block_len = 16;
	num_blocks = data_size / block_len;

	aes_setkey_enc(&aes1, key, 128);
	aes_setkey_enc(&aes2, key, 128);

	for (i = 0; i < num_blocks; ++i) {
		block_data = data + i * block_len;

		*(u64 *)(counter_key + 0) = ES64(i);
		*(u64 *)(counter_key + 8) = 0;

		aes_crypt_ecb(&aes1, AES_ENCRYPT, counter_key, counter_key);

		for (j = 0; j < 16; ++j)
			block_data[j] ^= counter_key[j];

		aes_crypt_ecb(&aes2, AES_ENCRYPT, block_data, block_data);
	}

	return 0;
}

static int pfd_decrypt_data(pfd_context_t *ctx, u8 key[PFD_ENTRY_KEY_SIZE], u8 *data, u64 data_size) {
	u8 counter_key[16];
	aes_context aes1, aes2;
	u64 block_len, num_blocks;
	u8 *block_data;
	u64 i, j;

	if (!ctx)
		return -1;

	block_len = 16;
	num_blocks = data_size / block_len;

	aes_setkey_enc(&aes1, key, 128);
	aes_setkey_dec(&aes2, key, 128);

	for (i = 0; i < num_blocks; ++i) {
		block_data = data + i * block_len;

		*(u64 *)(counter_key + 0) = ES64(i);
		*(u64 *)(counter_key + 8) = 0;

		aes_crypt_ecb(&aes1, AES_ENCRYPT, counter_key, counter_key);
		aes_crypt_ecb(&aes2, AES_DECRYPT, block_data, block_data);

		for (j = 0; j < 16; ++j)
			block_data[j] ^= counter_key[j];
	}

	return 0;
}

pfd_context_t * pfd_init(pfd_config_t *config, const char *directory_path, pfd_enumerate_callback_pfn enumerate_callback, pfd_validate_callback_pfn validate_callback, pfd_get_secure_file_id_callback_pfn get_secure_file_id_callback, void *user) {
	pfd_context_t *ctx;
	u64 directory_length;
	u64 i;

	if (!config)
		return NULL;

	directory_length = strlen(directory_path);
	if (!directory_length)
		return NULL;

	ctx = (pfd_context_t *)malloc(sizeof(pfd_context_t));
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(pfd_context_t));

	ctx->data_size = PFD_MAX_FILE_SIZE;

	ctx->data = (u8 *)malloc(ctx->data_size);
	if (!ctx->data) {
		free(ctx);
		return NULL;
	}
	memset(ctx->data, 0, ctx->data_size);

	ctx->temp_data = (u8 *)malloc(ctx->data_size);
	if (!ctx->temp_data) {
		free(ctx->data);
		free(ctx);
		return NULL;
	}
	memset(ctx->temp_data, 0, ctx->data_size);

	strncpy(ctx->directory_path, directory_path, MAX_PATH);
	directory_length = strlen(ctx->directory_path);
	for (i = 0; i < directory_length; ++i) {
		if (ctx->directory_path[i] == '\\')
			ctx->directory_path[i] = '/';
	}
	if (ctx->directory_path[directory_length - 1] != '/')
		strncat(ctx->directory_path, "/", MAX_PATH);

	ctx->config = config;
	ctx->user = user;
	ctx->enumerate_callback = enumerate_callback;
	ctx->validate_callback = validate_callback;
	ctx->get_secure_file_id_callback = get_secure_file_id_callback;

	return ctx;
}

int pfd_destroy(pfd_context_t *ctx) {
	if (!ctx)
		return -1;

	if (ctx->data)
		free(ctx->data);
	if (ctx->temp_data)
		free(ctx->temp_data);

	free(ctx);

	return 0;
}

int pfd_import(pfd_context_t *ctx) {
	char file_path[MAX_PATH];
	pfd_entry_t *entry;
	u64 i;
	
	if (!ctx)
		return -1;

	if (pfd_build_file_path(ctx, "PARAM.PFD", file_path, MAX_PATH) < 0)
		return -1;

	if (read_file(file_path, ctx->data, ctx->data_size) < 0)
		return -1;

	ctx->is_trophy = 0;
	ctx->header = (pfd_header_t *)(ctx->data + PFD_HEADER_OFFSET);
	ctx->header_key = (pfd_header_key_t *)(ctx->data + PFD_HEADER_KEY_OFFSET);
	ctx->signature = (pfd_signature_t *)(ctx->data + PFD_SIGNATURE_OFFSET);
	ctx->hash_table = (pfd_hash_table_t *)(ctx->data + PFD_HASH_TABLE_OFFSET);
	ctx->entry_table = (pfd_entry_table_t *)(ctx->data + PFD_ENTRY_TABLE_OFFSET(ctx->hash_table));
	ctx->entry_signature_table = (pfd_entry_signature_table_t *)(ctx->data + PFD_ENTRY_SIGNATURE_TABLE_OFFSET(ctx->hash_table));

	if (ES64(ctx->header->magic) != PFD_MAGIC || (ES64(ctx->header->version) != PFD_VERSION_V3 && ES64(ctx->header->version) != PFD_VERSION_V4))
		return -1;

	if (pfd_decrypt_with_portability(ctx, ctx->data + PFD_HEADER_KEY_OFFSET, ctx->data + PFD_SIGNATURE_OFFSET, PFD_SIGNATURE_SIZE) < 0)
		return -1;

	if (ES64(ctx->header->version) == PFD_VERSION_V4)
		sha1_hmac(ctx->config->keygen_key, PFD_KEYGEN_KEY_SIZE, ctx->signature->hash_key, PFD_HASH_KEY_SIZE, ctx->real_hash_key);
	else
		memcpy(ctx->real_hash_key, ctx->signature->hash_key, PFD_HASH_KEY_SIZE);

	for (i = 0; i < ES64(ctx->hash_table->num_used); ++i) {
		entry = pfd_get_entry_by_index(ctx, i);
		if (!entry)
			return -1;

		if (pfd_check_entry_file_name(ctx, entry, "TROPSYS.DAT") > 0 || pfd_check_entry_file_name(ctx, entry, "TROPCONF.SFM") > 0 || pfd_check_entry_file_name(ctx, entry, "TROPUSR.DAT") > 0 || pfd_check_entry_file_name(ctx, entry, "TROPTRNS.DAT") > 0) {
			ctx->is_trophy = 1;
			break;
		}
	}

	return 0;
}

int pfd_export(pfd_context_t *ctx) {
	char file_path[MAX_PATH];
	
	if (!ctx)
		return -1;

	memcpy(ctx->temp_data, ctx->data, ctx->data_size);

	if (pfd_encrypt_with_portability(ctx, ctx->temp_data + PFD_HEADER_KEY_OFFSET, ctx->temp_data + PFD_SIGNATURE_OFFSET, PFD_SIGNATURE_SIZE) < 0)
		return -1;

	if (pfd_build_file_path(ctx, "PARAM.PFD", file_path, MAX_PATH) < 0)
		return -1;

	if (write_file(file_path, ctx->temp_data, ctx->data_size) < 0)
		return -1;
		
	return 0;
}

int pfd_get_info(pfd_context_t *ctx, pfd_info_t *info) {
	if (!ctx)
		return -1;

	if (!info)
		return -1;

	memset(info, 0, sizeof(pfd_info_t));

	info->version = ES64(ctx->header->version);
	info->capacity = ES64(ctx->hash_table->capacity);
	info->num_used_entries = ES64(ctx->hash_table->num_used);
	info->num_reserved_entries = ES64(ctx->hash_table->num_reserved);
	info->is_trophy = ctx->is_trophy;

	return 0;
}

int pfd_validate(pfd_context_t *ctx, u32 type) {
	int entry_hashes[4] = { PFD_ENTRY_HASH_FILE, PFD_ENTRY_HASH_FILE_CID, PFD_ENTRY_HASH_FILE_DHK_CID2, PFD_ENTRY_HASH_FILE_AID_UID };
	int processing_types[4] = { PFD_VALIDATE_TYPE_FILE, PFD_VALIDATE_TYPE_FILE_CID, PFD_VALIDATE_TYPE_FILE_DHK_CID2, PFD_VALIDATE_TYPE_FILE_AID_UID };

	pfd_entry_t *entry;
	pfd_hash_key_t hash_key;
	u32 hash_key_size;
	pfd_hash_t computed_hash;
	u64 hash_table_entry_index;
	pfd_validation_status_t info;
	u64 i, j;

	if (!ctx)
		return -1;

	if ((type & PFD_VALIDATE_TYPE_TOP) != 0) {
		if (pfd_calculate_top_hash(ctx, computed_hash) < 0)
			return -1;

		memset(&info, 0, sizeof(pfd_validation_status_t));
		info.status = memcmp(ctx->signature->top_hash, computed_hash, PFD_HASH_SIZE) == 0 ? PFD_VALIDATE_SUCCESS : PFD_VALIDATE_FAILURE_HASH;

		if (ctx->validate_callback)
			(*ctx->validate_callback)(ctx->user, PFD_VALIDATE_TYPE_TOP, &info);
	}

	if ((type & PFD_VALIDATE_TYPE_BOTTOM) != 0) {
		if (pfd_calculate_bottom_hash(ctx, computed_hash) < 0)
			return -1;

		memset(&info, 0, sizeof(pfd_validation_status_t));
		info.status = memcmp(ctx->signature->bottom_hash, computed_hash, PFD_HASH_SIZE) == 0 ? PFD_VALIDATE_SUCCESS : PFD_VALIDATE_FAILURE_HASH;

		if (ctx->validate_callback)
			(*ctx->validate_callback)(ctx->user, PFD_VALIDATE_TYPE_BOTTOM, &info);
	}

	if ((type & PFD_VALIDATE_TYPE_ENTRY) != 0) {
		if (pfd_calculate_default_hash(ctx, computed_hash) < 0)
			return -1;

		for (i = 0; i < ES64(ctx->hash_table->capacity); ++i) {
			if (ES64(ctx->hash_table->entries[i]) < ES64(ctx->hash_table->capacity))
				continue;

			memset(&info, 0, sizeof(pfd_validation_status_t));
			info.status = memcmp(ctx->entry_signature_table->hashes[i], computed_hash, PFD_HASH_SIZE) == 0 ? PFD_VALIDATE_SUCCESS : PFD_VALIDATE_FAILURE_HASH;
			info.entry.index = i;
			info.entry.is_occupied = 0;
			
			if (ctx->validate_callback)
				(*ctx->validate_callback)(ctx->user, PFD_VALIDATE_TYPE_ENTRY, &info);
		}

		for (i = 0; i < ES64(ctx->hash_table->num_used); ++i) {
			entry = pfd_get_entry_by_index(ctx, i);
			if (!entry)
				return -1;

			if (pfd_calculate_entry_hash(ctx, entry, computed_hash) < 0)
				return -1;

			hash_table_entry_index = pfd_calculate_hash_table_entry_index(ctx, entry->file_name);

			memset(&info, 0, sizeof(pfd_validation_status_t));
			info.status = memcmp(ctx->entry_signature_table->hashes[hash_table_entry_index], computed_hash, PFD_HASH_SIZE) == 0 ? PFD_VALIDATE_SUCCESS : PFD_VALIDATE_FAILURE_HASH;
			info.entry.index = hash_table_entry_index;
			info.entry.is_occupied = 1;
			strncpy(info.entry.file_name, entry->file_name, PFD_ENTRY_NAME_SIZE);

			if (ctx->validate_callback)
				(*ctx->validate_callback)(ctx->user, PFD_VALIDATE_TYPE_ENTRY, &info);
		}
	}

	if ((type & PFD_VALIDATE_TYPE_FILE_ALL) != 0) {
		for (i = 0; i < ES64(ctx->hash_table->num_used); ++i) {
			entry = pfd_get_entry_by_index(ctx, i);
			if (!entry)
				return -1;

			for (j = 0; j < countof(entry_hashes); ++j) {
				if (!pfd_check_entry_file_name(ctx, entry, "PARAM.SFO") && entry_hashes[j] != PFD_ENTRY_HASH_FILE)
					continue;
				if (ctx->is_trophy && entry_hashes[j] == PFD_ENTRY_HASH_FILE_CID)
					continue;
				if (!(type & processing_types[j]))
					continue;

				if (pfd_get_entry_hash_key(ctx, entry, hash_key, &hash_key_size, entry_hashes[j]) < 0) {
					memset(&info, 0, sizeof(pfd_validation_status_t));
					info.status = PFD_VALIDATE_FAILURE_NO_DATA;
					info.file.entry_index = i;
					strncpy(info.file.file_name, entry->file_name, PFD_ENTRY_NAME_SIZE);

					if (ctx->validate_callback)
						(*ctx->validate_callback)(ctx->user, processing_types[j], &info);
				} else {
					if (pfd_calculate_entry_file_hash(ctx, entry, hash_key, hash_key_size, computed_hash) == 0) {
						memset(&info, 0, sizeof(pfd_validation_status_t));
						info.status = memcmp(entry->file_hashes[entry_hashes[j]], computed_hash, PFD_HASH_SIZE) == 0 ? PFD_VALIDATE_SUCCESS : PFD_VALIDATE_FAILURE_HASH;
						info.file.entry_index = i;
						strncpy(info.file.file_name, entry->file_name, PFD_ENTRY_NAME_SIZE);

						if (ctx->validate_callback)
							(*ctx->validate_callback)(ctx->user, processing_types[j], &info);
					} else {
						memset(&info, 0, sizeof(pfd_validation_status_t));
						info.status = PFD_VALIDATE_FAILURE_FILE;
						info.file.entry_index = i;
						strncpy(info.file.file_name, entry->file_name, PFD_ENTRY_NAME_SIZE);

						if (ctx->validate_callback)
							(*ctx->validate_callback)(ctx->user, processing_types[j], &info);
					}
				}
			}
		}
	}

	return 0;
}

int pfd_update(pfd_context_t *ctx, u32 type) {
	int entry_hashes[4] = { PFD_ENTRY_HASH_FILE, PFD_ENTRY_HASH_FILE_CID, PFD_ENTRY_HASH_FILE_DHK_CID2, PFD_ENTRY_HASH_FILE_AID_UID };
	int processing_types[4] = { PFD_UPDATE_TYPE_FILE, PFD_UPDATE_TYPE_FILE_CID, PFD_UPDATE_TYPE_FILE_DHK_CID2, PFD_UPDATE_TYPE_FILE_AID_UID };

	char file_path[MAX_PATH];
	pfd_entry_t *entry;
	pfd_hash_key_t hash_key;
	u32 hash_key_size;
	pfd_hash_t computed_hash;
	u64 hash_table_entry_index;
	u64 i, j;
	int status;
	int result;

	if (!ctx)
		return -1;

	result = 0;

	if ((type & PFD_UPDATE_TYPE_ALL) != 0) {
		for (i = 0; i < ES64(ctx->hash_table->num_used); ++i) {
			entry = pfd_get_entry_by_index(ctx, i);
			if (!entry)
				return -1;

			if (pfd_build_file_path(ctx, entry->file_name, file_path, MAX_PATH) < 0)
				return -1;

			for (j = 0; j < countof(entry_hashes); ++j) {
				if (!pfd_check_entry_file_name(ctx, entry, "PARAM.SFO") && entry_hashes[j] != PFD_ENTRY_HASH_FILE)
					continue;
				if (ctx->is_trophy && entry_hashes[j] == PFD_ENTRY_HASH_FILE_CID)
					continue;
				if (!(type & processing_types[j]))
					continue;

				if (pfd_get_entry_hash_key(ctx, entry, hash_key, &hash_key_size, entry_hashes[j]) < 0) {
					status = PFD_UPDATE_FAILURE_NO_DATA;
					result |= status;
				} else {
					if (pfd_calculate_entry_file_hash(ctx, entry, hash_key, hash_key_size, computed_hash) == 0) {
						memcpy(entry->file_hashes[entry_hashes[j]], computed_hash, PFD_HASH_SIZE);
					} else {
						status = PFD_UPDATE_FAILURE_FILE;
						result |= status;
					}
				}
			}
		}
	}

	if (pfd_calculate_default_hash(ctx, computed_hash) < 0)
		return -1;

	for (i = 0; i < ES64(ctx->hash_table->capacity); ++i) {
		if (ES64(ctx->hash_table->entries[i]) < ES64(ctx->hash_table->capacity))
			continue;

		memcpy(ctx->entry_signature_table->hashes[i], computed_hash, PFD_HASH_SIZE);
	}

	for (i = 0; i < ES64(ctx->hash_table->num_used); ++i) {
		entry = pfd_get_entry_by_index(ctx, i);
		if (!entry)
			return -1;

		if (pfd_calculate_entry_hash(ctx, entry, computed_hash) < 0)
			return -1;

		hash_table_entry_index = pfd_calculate_hash_table_entry_index(ctx, entry->file_name);
		memcpy(ctx->entry_signature_table->hashes[hash_table_entry_index], computed_hash, PFD_HASH_SIZE);
	}

	if (pfd_calculate_bottom_hash(ctx, computed_hash) < 0)
		return -1;
	memcpy(ctx->signature->bottom_hash, computed_hash, PFD_HASH_SIZE);

	if (pfd_calculate_top_hash(ctx, computed_hash) < 0)
		return -1;
	memcpy(ctx->signature->top_hash, computed_hash, PFD_HASH_SIZE);

	return result;
}

int pfd_encrypt_file(pfd_context_t *ctx, const char *file_name) {
	char file_path[MAX_PATH];
	pfd_entry_t *entry;
	u64 entry_index;
	pfd_entry_key_t entry_key;
	u8 *file_data;
	u64 aligned_file_size;
	u64 file_size;

	if (!ctx)
		return -1;

	if (pfd_get_entry_by_name(ctx, file_name, &entry_index) < 0)
		return -1;

	if (!(entry = pfd_get_entry_by_index(ctx, entry_index)))
		return -1;

	if (pfd_build_entry_file_path(ctx, entry, file_path, MAX_PATH) < 0) 
		return -1;

	if (get_file_size(file_path, &file_size) < 0)
		return -1;

	aligned_file_size = align_to_pow2(file_size, PFD_FILE_SIZE_ALIGNMENT);

	memset(entry_key, 0, PFD_ENTRY_KEY_SIZE);

	if (pfd_get_entry_key(ctx, entry, entry_key) < 0)
		return -1;

	file_data = (u8 *)malloc(aligned_file_size);
	if (!file_data)
		return -1;

	memset(file_data, 0, aligned_file_size);

	if (read_file(file_path, file_data, file_size) < 0) {
		free(file_data);
		return -1;
	}

	if (pfd_encrypt_data(ctx, entry_key, file_data, aligned_file_size) < 0) {
		free(file_data);
		return -1;
	}

	if (write_file(file_path, file_data, aligned_file_size) < 0) {
		free(file_data);
		return -1;
	}

	entry->file_size = ES64(file_size);

	free(file_data);
				
	return 0;
}

int pfd_decrypt_file(pfd_context_t *ctx, const char *file_name) {
	char file_path[MAX_PATH];
	pfd_entry_t *entry;
	u64 entry_index;
	pfd_entry_key_t entry_key;
	u8 *file_data;
	u64 aligned_file_size;
	u64 file_size;

	if (!ctx)
		return -1;

	if (pfd_get_entry_by_name(ctx, file_name, &entry_index) < 0)
		return -1;

	if (!(entry = pfd_get_entry_by_index(ctx, entry_index)))
		return -1;

	if (pfd_build_entry_file_path(ctx, entry, file_path, MAX_PATH) < 0) 
		return -1;

	if (pfd_get_entry_aligned_size(ctx, entry, &aligned_file_size) < 0)
		return -1;

	if (pfd_get_entry_size(ctx, entry, &file_size) < 0)
		return -1;

	memset(entry_key, 0, PFD_ENTRY_KEY_SIZE);

	if (pfd_get_entry_key(ctx, entry, entry_key) < 0)
		return -1;

	file_data = (u8 *)malloc(aligned_file_size);
	if (!file_data)
		return -1;

	memset(file_data, 0, aligned_file_size);

	if (read_file(file_path, file_data, aligned_file_size) < 0) {
		free(file_data);
		return -1;
	}

	if (pfd_decrypt_data(ctx, entry_key, file_data, aligned_file_size) < 0) {
		free(file_data);
		return -1;
	}

	if (write_file(file_path, file_data, file_size) < 0) {
		free(file_data);
		return -1;
	}

	free(file_data);
				
	return 0;
}

int pfd_enumerate(pfd_context_t *ctx) {
	pfd_entry_info_t entry_info;
	int status;
	u64 i;

	if (!ctx)
		return -1;

	for (i = 0; i < ES64(ctx->hash_table->num_used); ++i) {
		memset(&entry_info, 0, sizeof(pfd_entry_info_t));

		entry_info.index = i;
		strncpy(entry_info.file_name, ctx->entry_table->entries[i].file_name, PFD_ENTRY_NAME_SIZE);
		entry_info.file_size = ES64(ctx->entry_table->entries[i].file_size);

		if (ctx->enumerate_callback) {
			status = (*ctx->enumerate_callback)(ctx->user, &entry_info);
			if (status != PFD_CONTINUE)
				break;
		}
	}

	return 0;
}

int pfd_get_hash_key_from_secure_file_id(pfd_context_t *ctx, const u8 *secure_file_id, u8 hash_key[PFD_HASH_KEY_SIZE], u32 *hash_key_size) {
	if (!ctx)
		return -1;

	if (!secure_file_id || !hash_key || !hash_key_size)
		return -1;

	return pfd_generate_hash_key_for_secure_file_id(ctx, hash_key, hash_key_size, secure_file_id);
}

int pfd_get_file_hash(pfd_context_t *ctx, const char *file_name, u32 type, u8 hash[PFD_HASH_SIZE]) {
	pfd_entry_t *entry;
	u64 entry_index;

	if (!ctx)
		return -1;

	if (!file_name || (type != PFD_ENTRY_HASH_FILE && type != PFD_ENTRY_HASH_FILE_CID && type != PFD_ENTRY_HASH_FILE_DHK_CID2 && type != PFD_ENTRY_HASH_FILE_AID_UID) || !hash)
		return -1;

	if (pfd_get_entry_by_name(ctx, file_name, &entry_index) < 0)
		return -1;

	if (!(entry = pfd_get_entry_by_index(ctx, entry_index)))
		return -1;

	memcpy(hash, entry->file_hashes[type], PFD_HASH_SIZE);
	
	return 0;
}

int pfd_get_file_path(pfd_context_t *ctx, const char *file_name, char *file_path, u32 max_length) {
	pfd_entry_t *entry;
	u64 entry_index;

	if (!ctx)
		return -1;

	if (!file_name || !file_path || !max_length)
		return -1;

	if (pfd_get_entry_by_name(ctx, file_name, &entry_index) < 0)
		return -1;

	if (!(entry = pfd_get_entry_by_index(ctx, entry_index)))
		return -1;

	if (pfd_build_entry_file_path(ctx, entry, file_path, max_length) < 0) 
		return -1;

	return 0;
}
