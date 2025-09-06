#include "backend.h"
#include "util.h"

extern int verbose_flag;

static int enumerate_callback(void *user, pfd_entry_info_t *entry_info) {
	backend_t *ctx;
	entry_info_t *new_entry;

	if (!user || !entry_info)
		return PFD_STOP;

	ctx = (backend_t *)user;

	new_entry = (entry_info_t *)malloc(sizeof(entry_info_t));
	if (!new_entry)
		return PFD_STOP;

	memset(new_entry, 0, sizeof(entry_info_t));
	new_entry->index = entry_info->index;
	new_entry->file_name = entry_info->file_name ? strdup(entry_info->file_name) : NULL;
	new_entry->file_size = entry_info->file_size;

	list_append(ctx->storage.list.entries, new_entry);

	return PFD_CONTINUE;
}

static int validate_callback(void *user, u32 type, pfd_validation_status_t *status) {
	backend_t *ctx;

	if (!user || !status)
		return PFD_STOP;

	ctx = (backend_t *)user;

	switch (type) {
		case PFD_VALIDATE_TYPE_TOP:
			ctx->storage.validate.structure.top = status->status;
			break;
		case PFD_VALIDATE_TYPE_BOTTOM:
			ctx->storage.validate.structure.bottom = status->status;
			break;
		case PFD_VALIDATE_TYPE_ENTRY:
			/* FIXME: did I forgot something? */
			if (status->entry.is_occupied)
				ctx->storage.validate.entries[status->entry.index].signature = status->status;
			else
				ctx->storage.validate.entries[status->entry.index].signature = status->status;
			break;
		case PFD_VALIDATE_TYPE_FILE:
		case PFD_VALIDATE_TYPE_FILE_CID:
		case PFD_VALIDATE_TYPE_FILE_DHK_CID2:
		case PFD_VALIDATE_TYPE_FILE_AID_UID:
			if (!ctx->storage.validate.files[status->file.entry_index].file_name)
				ctx->storage.validate.files[status->file.entry_index].file_name = status->file.file_name ? strdup(status->file.file_name) : NULL;
			if (type == PFD_VALIDATE_TYPE_FILE)
				ctx->storage.validate.files[status->file.entry_index].file = status->status;
			else if (type == PFD_VALIDATE_TYPE_FILE_CID)
				ctx->storage.validate.files[status->file.entry_index].cid = status->status;
			else if (type == PFD_VALIDATE_TYPE_FILE_DHK_CID2)
				ctx->storage.validate.files[status->file.entry_index].dhk_cid2 = status->status;
			else if (type == PFD_VALIDATE_TYPE_FILE_AID_UID)
				ctx->storage.validate.files[status->file.entry_index].aid_uid = status->status;
			break;
	}

	return PFD_CONTINUE;
}

static u8 * get_secure_file_id_callback(void *user, const char *file_name) {
	backend_t *ctx;
	list_node_t *node;
	u8 *secure_file_id;

	if (!user)
		return NULL;

	ctx = (backend_t *)user;

	if (!ctx->secure_file_ids)
		return NULL;

	secure_file_id = NULL;

	node = list_head(ctx->secure_file_ids);
	while (node) {
		secure_file_id = NULL;
		if (node->value) {
#if 0
			if (strncmp(file_name, ((pfd_secure_file_id_t *)node->value)->file_name, PFD_ENTRY_NAME_SIZE) == 0) {
				secure_file_id = ((pfd_secure_file_id_t *)node->value)->secure_file_id;
				break;
			}
#else /* use wildcard matching instead */
			if (wildcard_match(file_name, ((secure_file_id_t *)node->value)->file_name) != 0) {
				secure_file_id = ((secure_file_id_t *)node->value)->secure_file_id;
				break;
			}
#endif
		}
		node = node->next;
	}

	return secure_file_id;
}

backend_t * backend_initialize(pfd_config_t *config, list_t *secure_file_ids, const char *directory_path) {
	backend_t *ctx;

	ctx = (backend_t *)malloc(sizeof(backend_t));
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(backend_t));

	ctx->config = config;
	ctx->secure_file_ids = secure_file_ids;

	ctx->pfd = pfd_init(
		ctx->config,
		directory_path,
		enumerate_callback,
		validate_callback,
		get_secure_file_id_callback,
		ctx
	);

	return ctx;
}

int backend_shutdown(backend_t *ctx) {
	if (!ctx)
		return -1;

	if (ctx->pfd)
		pfd_destroy(ctx->pfd);

	free(ctx);

	return 0;
}

int backend_cmd_list(backend_t *ctx) {
	pfd_info_t info;
	list_node_t *node;
	entry_info_t *entry_info;

	if (!ctx)
		return -1;

	if (pfd_import(ctx->pfd) < 0)
		return -1;

	if (pfd_get_info(ctx->pfd, &info) < 0)
		return -1;

	memset(&ctx->storage.list, 0, sizeof(ctx->storage.list));

	ctx->storage.list.entries = list_alloc();
	if (!ctx->storage.list.entries)
		return -1;

	if (pfd_enumerate(ctx->pfd) < 0)
		return -1;

	printf("[*] Version: %llu\n", info.version);
	printf("[*] Type: %s\n", info.is_trophy ? "trophy" : "savegame");
	printf("[*]\n");
	printf("[*] Entries:\n");
	node = list_head(ctx->storage.list.entries);
	while (node) {
		entry_info = (entry_info_t *)list_get(node);
		if (entry_info) {
			printf("[*]   #%03lld:\n", entry_info->index);
			if (entry_info->file_name)
				printf("[*]     File Name: %s\n", entry_info->file_name);
			printf("[*]     File Size: %lld\n", entry_info->file_size);
		}
		node = list_next(node);
	}
	node = list_head(ctx->storage.list.entries);
	while (node) {
		entry_info = (entry_info_t *)list_get(node);
		if (entry_info) {
			if (entry_info->file_name)
				free(entry_info->file_name);
			free(entry_info);
		}
		node = list_next(node);
	}

	list_free(ctx->storage.list.entries);

	return 0;
}

int backend_cmd_check(backend_t *ctx, u32 options) {
	pfd_info_t info;
	u32 flags;
	u64 i, j;

	if (!ctx)
		return -1;

	if (pfd_import(ctx->pfd) < 0)
		return -1;

	if (pfd_get_info(ctx->pfd, &info) < 0)
		return -1;

	memset(&ctx->storage.validate, 0, sizeof(ctx->storage.validate));
	
	ctx->storage.validate.entries = (entry_status_t *)malloc(info.num_reserved_entries * sizeof(entry_status_t));
	if (!ctx->storage.validate.entries)
		return -1;
	memset(ctx->storage.validate.entries, 0, info.num_reserved_entries * sizeof(entry_status_t));

	ctx->storage.validate.files = (file_status_t *)malloc(info.num_used_entries * sizeof(file_status_t));
	if (!ctx->storage.validate.files)
		return -1;
	memset(ctx->storage.validate.files, 0, info.num_used_entries * sizeof(file_status_t));

	flags = PFD_VALIDATE_TYPE_ALL;
	if ((options & BACKEND_VALIDATE_FLAG_PARTIAL) != 0) {
		flags &= ~PFD_VALIDATE_TYPE_FILE;
		flags &= ~PFD_VALIDATE_TYPE_FILE_DHK_CID2;
	}
	if (pfd_validate(ctx->pfd, flags) < 0)
		return -1;

	printf("[*] Version: %llu\n", info.version);
	printf("[*] Type: %s\n", info.is_trophy ? "trophy" : "savegame");
	printf("[*]\n");
	printf("[*] Statuses:\n");
	printf("[*]   Structure:\n");
	printf("[*]     Top Hash:    %s\n", ctx->storage.validate.structure.top == PFD_VALIDATE_SUCCESS ? "OK" : "FAIL");
	printf("[*]     Bottom Hash: %s\n", ctx->storage.validate.structure.bottom == PFD_VALIDATE_SUCCESS ? "OK" : "FAIL");
	printf("[*]\n");
	printf("[*]   Entries:\n");
	for (i = 0; i < info.num_reserved_entries; ++i) {
		printf("[*]     #%03lld:\n", i);
		printf("[*]       Signature Hash: %s\n", ctx->storage.validate.entries[i].signature == PFD_VALIDATE_SUCCESS ? "OK" : "FAIL");
	}
	printf("[*]\n");
	printf("[*]   Files:\n");
	for (i = 0, j = 0; i < info.num_used_entries; ++i) {
		if (!ctx->storage.validate.files[i].file_name)
			continue;
		if (strncmp(ctx->storage.validate.files[i].file_name, "PARAM.SFO", PFD_ENTRY_NAME_SIZE) == 0) {
			printf("[*]     #%03lld (%s):\n", j, ctx->storage.validate.files[i].file_name);
			printf("[*]       Entry Index:             %lld\n", i);
			printf("[*]       PARAM.SFO Hash Key Hash: %s\n", ctx->storage.validate.files[i].file == PFD_VALIDATE_SUCCESS ? "OK" : "FAIL");
			if (!info.is_trophy) {
				printf("[*]       Console ID Hash:         %s\n", ctx->storage.validate.files[i].cid == PFD_VALIDATE_SUCCESS ? "OK" : "FAIL");
				printf("[*]       Disc Hash Key Hash:      %s\n", ctx->storage.validate.files[i].dhk_cid2 == PFD_VALIDATE_SUCCESS ? "OK" : "FAIL");
				printf("[*]       Authentication ID Hash:  %s\n", ctx->storage.validate.files[i].aid_uid == PFD_VALIDATE_SUCCESS ? "OK" : "FAIL");
			} else {
				printf("[*]       Console ID Hash:         %s\n", ctx->storage.validate.files[i].dhk_cid2 == PFD_VALIDATE_SUCCESS ? "OK" : "FAIL");
				printf("[*]       User ID Hash:            %s\n", ctx->storage.validate.files[i].aid_uid == PFD_VALIDATE_SUCCESS ? "OK" : "FAIL");
			}
		} else {
			printf("[*]     #%03lld (%s):\n", j, ctx->storage.validate.files[i].file_name);
			printf("[*]       Entry Index:             %lld\n", i);
			printf("[*]       File Key Hash:           %s\n", ctx->storage.validate.files[i].file == PFD_VALIDATE_SUCCESS ? "OK" : "FAIL");
		}
		++j;
	}

	free(ctx->storage.validate.entries);
	free(ctx->storage.validate.files);

	return 0;
}

int backend_cmd_update(backend_t *ctx, u32 options) {
	u32 flags;

	if (!ctx)
		return -1;

	if (pfd_import(ctx->pfd) < 0)
		return -1;

	flags = PFD_UPDATE_TYPE_ALL;
	if ((options & BACKEND_UPDATE_FLAG_PARTIAL) != 0) {
		flags &= ~PFD_UPDATE_TYPE_FILE;
		flags &= ~PFD_UPDATE_TYPE_FILE_DHK_CID2;
	}

	if (pfd_update(ctx->pfd, flags) < 0)
		return -1;

	if (pfd_export(ctx->pfd) < 0)
		return -1;

	return 0;
}

int backend_cmd_encrypt(backend_t *ctx, list_t *file_names) {
	list_node_t *node;
	const char *file_name;

	if (!ctx)
		return -1;

	if (!file_names)
		return -1;

	if (pfd_import(ctx->pfd) < 0)
		return -1;

	node = list_head(file_names);
	while (node) {
		file_name = (const char *)list_get(node);
		if (file_name) {
			if (pfd_encrypt_file(ctx->pfd, file_name) < 0)
				return -1;
		}
		node = list_next(node);
	}

	if (pfd_update(ctx->pfd, PFD_UPDATE_TYPE_ALL) < 0)
		return -1;

	if (pfd_export(ctx->pfd) < 0)
		return -1;

	return -1;
}

int backend_cmd_decrypt(backend_t *ctx, list_t *file_names) {
	list_node_t *node;
	const char *file_name;

	if (!ctx)
		return -1;

	if (!file_names)
		return -1;

	if (pfd_import(ctx->pfd) < 0)
		return -1;

	node = list_head(file_names);
	while (node) {
		file_name = (const char *)list_get(node);
		if (file_name) {
			if (pfd_decrypt_file(ctx->pfd, file_name) < 0)
				return -1;
		}
		node = list_next(node);
	}

	if (pfd_update(ctx->pfd, PFD_UPDATE_TYPE_ALL) < 0)
		return -1;

	if (pfd_export(ctx->pfd) < 0)
		return -1;

	return -1;
}

int backend_cmd_brute(backend_t *ctx, const char *file_path, u64 file_offset, s64 advance_offset, list_t *file_names) {
	u8 hash_key[PFD_HASH_KEY_SIZE];
	u32 hash_key_size;
	u8 computed_hash[20];
	u8 *data;
	u64 data_size;
	const char *file_name;
	list_t *secure_file_ids;
	list_node_t *node;
	secure_file_id_t *secure_file_id;
	u64 offset;
	int num_to_find;
	int num_found;

	if (!ctx)
		return -1;

	if (!file_path || !file_names)
		return -1;

	if (mmap_file(file_path, &data, &data_size) < 0)
		return -1;

	if (pfd_import(ctx->pfd) < 0)
		return -1;

	secure_file_ids = list_alloc();
	if (!secure_file_ids)
		return -1;

	if (advance_offset <= 0)
		advance_offset = 1;

	num_to_find = 0;
	num_found = 0;

	node = list_head(file_names);
	while (node) {
		file_name = (const char *)list_get(node);
		if (file_name) {
			secure_file_id = (secure_file_id_t *)malloc(sizeof(secure_file_id_t));
			if (!secure_file_id)
				return -1;
			memset(secure_file_id, 0, sizeof(secure_file_id_t));
			strncpy(secure_file_id->file_name, file_name, PFD_ENTRY_NAME_SIZE);
			if (pfd_get_file_path(ctx->pfd, secure_file_id->file_name, secure_file_id->file_path, MAX_PATH) < 0)
				return -1;
			if (mmap_file(secure_file_id->file_path, &secure_file_id->data, &secure_file_id->data_size) < 0)
				return -1;
			if (pfd_get_file_hash(ctx->pfd, secure_file_id->file_name, PFD_ENTRY_HASH_FILE, secure_file_id->real_hash) < 0)
				return -1;
			secure_file_id->found = 0;
			list_append(secure_file_ids, secure_file_id);
		}
		node = list_next(node);
	}

	num_to_find = list_count(secure_file_ids);
	offset = file_offset;

	printf("[*] Starting bruteforcing...\n");

	while (offset + PFD_SECURE_FILE_ID_SIZE < data_size && num_found < num_to_find) {
		if (((offset - file_offset) % (1024ULL * 128)) == 0) {
			printf("[*]   Offset: 0x%016llX\n", offset);
			fflush(stdout);
		}

		if (pfd_get_hash_key_from_secure_file_id(ctx->pfd, data + offset, hash_key, &hash_key_size) < 0)
			return -1;

		node = list_head(secure_file_ids);
		while (node) {
			secure_file_id = (secure_file_id_t *)list_get(node);
			if (secure_file_id && !secure_file_id->found && num_found < num_to_find) {
				if (calculate_hmac_hash(secure_file_id->data, secure_file_id->data_size, hash_key, hash_key_size, computed_hash) < 0)
					return -1;

				if (memcmp(secure_file_id->real_hash, computed_hash, PFD_HASH_SIZE) == 0) {
					memcpy(secure_file_id->secure_file_id, data + offset, PFD_SECURE_FILE_ID_SIZE);
					secure_file_id->found = 1;
					num_found++;
				}
			}

			node = list_next(node);
		}

		offset += advance_offset;
	}

	if (num_found > 0) {
		printf("[*]\n");
		printf("[*] %d of %d secure file IDs were bruteforced:\n", num_found, num_to_find);

		node = list_head(secure_file_ids);
		while (node) {
			secure_file_id = (secure_file_id_t *)list_get(node);
			if (secure_file_id && secure_file_id->found) {
				printf("[*]  %s: ", secure_file_id->file_name);
				dump_data(secure_file_id->secure_file_id, PFD_SECURE_FILE_ID_SIZE, stdout);
			}
			node = list_next(node);
		}
	}

	node = list_head(secure_file_ids);
	while (node) {
		secure_file_id = (secure_file_id_t *)list_get(node);
		if (secure_file_id) {
			unmmap_file(secure_file_id->data, secure_file_id->data_size);
			free(secure_file_id);
		}
		node = list_next(node);
	}
	list_free(secure_file_ids);

	if (unmmap_file(data, data_size) < 0)
		return -1;

	return 0;
}
