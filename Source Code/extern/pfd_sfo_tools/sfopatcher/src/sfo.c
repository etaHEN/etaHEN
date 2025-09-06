#include "sfo.h"
#include "list.h"
#include "util.h"

#include "my_libc.h"

// keep the author information here
// even though we never use this
#define SFOPATCHER_VERSION "0.1.0"

void show_version(void) {
	printf("sfopatcher " SFOPATCHER_VERSION " (c) 2012 by flatz\n\n");
}

void show_usage(void) {
	printf("USAGE: sfopatcher command [options]\n");
	printf("COMMANDS Parameters         Explanation\n");
	printf(" build   in tpl out         Build a new <out> using an existing <in> and <tpl> as a template\n");
	printf("   --copy-title             Copy TITLE/SUB_TITLE parameters too\n");
	printf("   --copy-detail            Copy DETAIL parameter too\n");
	printf(" patch   in out             Patch an existing <in> and save it to <out>\n");
	printf("   --remove-copy-protection Remove a copy protected flag\n");
	printf("\n");
	printf(" -h, --help                 Print this help\n");
	printf(" -v, --verbose              Enable verbose output\n");
}

sfo_context_t * sfo_alloc(void) {
	sfo_context_t *context;
	context = (sfo_context_t *)malloc(sizeof(sfo_context_t));
	if (context) {
		memset(context, 0, sizeof(sfo_context_t));
		context->params = list_alloc();
	}
	return context;
}

void sfo_free(sfo_context_t *context) {
	if (!context)
		return;

	if (context->params) {
		list_node_t *node;
		sfo_context_param_t *param;

		node = list_head(context->params);
		while (node) {
			param = (sfo_context_param_t *)node->value;
			if (param) {
				if (param->key)
					free(param->key);
				if (param->value)
					free(param->value);
				free(param);
			}
			node = node->next;
		}

		list_free(context->params);
	}

	free(context);
}

int sfo_read(sfo_context_t *context, const char *file_path) {
	int ret;
	u8 *sfo;
	size_t sfo_size;
	sfo_header_t *header;
	sfo_index_table_t *index_table;
	sfo_context_param_t *param;
	size_t i;

	ret = 0;

	if ((ret = read_buffer(file_path, &sfo, &sfo_size)) < 0)
		goto error;

	if (sfo_size < sizeof(sfo_header_t)) {
		ret = -1;
		goto error;
	}

	header = (sfo_header_t *)sfo;
	header->magic = LE32(header->magic);
	header->version = LE32(header->version);
	header->key_table_offset = LE32(header->key_table_offset);
	header->data_table_offset = LE32(header->data_table_offset);
	header->num_entries = LE32(header->num_entries);

	if (header->magic != SFO_MAGIC) {
		ret = -1;
		goto error;
	}

	for (i = 0; i < header->num_entries; ++i) {
		index_table = (sfo_index_table_t *)(sfo + sizeof(sfo_header_t) + i * sizeof(sfo_index_table_t));
		index_table->key_offset = LE16(index_table->key_offset);
		index_table->param_format = LE16(index_table->param_format);
		index_table->param_length = LE32(index_table->param_length);
		index_table->param_max_length = LE32(index_table->param_max_length);
		index_table->data_offset = LE32(index_table->data_offset);

		param = (sfo_context_param_t *)malloc(sizeof(sfo_context_param_t));
		if	(param) {
			memset(param, 0, sizeof(sfo_context_param_t));
			param->key = strdup((char *)(sfo + header->key_table_offset + index_table->key_offset));
			param->format = index_table->param_format;
			param->length = index_table->param_length;
			param->max_length = index_table->param_max_length;
			param->value = (u8 *)malloc(index_table->param_max_length);
			param->actual_length = index_table->param_max_length;
			if (param->value) {
				memcpy(param->value, (u8 *)(sfo + header->data_table_offset + index_table->data_offset), param->actual_length);
			} else {
				/* TODO */
				// assert(0);
			}
		} else {
			/* TODO */
			// assert(0);
		}

		list_append(context->params, param);
	}

error:
	return ret;
}

int sfo_write(sfo_context_t *context, const char *file_path) {
	int ret;
	list_node_t *node;
	sfo_context_param_t *param;
	u8 *sfo;
	sfo_header_t *header;
	sfo_index_table_t *index_table;
	size_t num_params;
	size_t sfo_size;
	size_t key_table_size, data_table_size;
	size_t key_offset, data_offset;
	size_t i;

	ret = 0;

	if (!context) {
		ret = -1;
		goto error;
	}
	if (!context->params) {
		ret = -1;
		goto error;
	}

	num_params = list_count(context->params);

	key_table_size = 0;
	data_table_size = 0;

	for (node = list_head(context->params); node; node = node->next) {
		param = (sfo_context_param_t *)node->value;
		// assert(param != NULL);

		key_table_size += strlen(param->key) + 1;
		data_table_size += param->actual_length;
	}
	sfo_size = sizeof(sfo_header_t) + num_params * sizeof(sfo_index_table_t) + key_table_size + data_table_size;
	key_table_size += ALIGN(sfo_size, 16) - sfo_size;
	sfo_size = ALIGN(sfo_size, 16);

	sfo = (u8 *)malloc(sfo_size);
	if (!sfo) {
		ret = -1;
		goto error;
	}

	memset(sfo, 0, sfo_size);

	header = (sfo_header_t *)sfo;
	header->magic = SFO_MAGIC;
	header->version = SFO_VERSION;
	header->key_table_offset = sizeof(sfo_header_t) + num_params * sizeof(sfo_index_table_t);
	header->data_table_offset = sizeof(sfo_header_t) + num_params * sizeof(sfo_index_table_t) + key_table_size;
	header->num_entries = num_params;

	for (node = list_head(context->params), key_offset = 0, data_offset = 0, i = 0; node; node = node->next, ++i) {
		param = (sfo_context_param_t *)node->value;
		// assert(param != NULL);

		index_table = (sfo_index_table_t *)(sfo + sizeof(sfo_header_t) + i * sizeof(sfo_index_table_t));
		index_table->key_offset = key_offset;
		index_table->param_format = param->format;
		index_table->param_length = param->length;
		index_table->param_max_length = param->max_length;
		index_table->data_offset = data_offset;

		key_offset += strlen(param->key) + 1;
		data_offset += param->actual_length;
	}

	for (node = list_head(context->params), i = 0; node; node = node->next, ++i) {
		param = (sfo_context_param_t *)node->value;
		// assert(param != NULL);

		index_table = (sfo_index_table_t *)(sfo + sizeof(sfo_header_t) + i * sizeof(sfo_index_table_t));
		memcpy(sfo + header->key_table_offset + index_table->key_offset, param->key, strlen(param->key) + 1);
		memcpy(sfo + header->data_table_offset + index_table->data_offset, param->value, param->actual_length);
	}

	for (i = 0; i < header->num_entries; ++i) {
		index_table = (sfo_index_table_t *)(sfo + sizeof(sfo_header_t) + i * sizeof(sfo_index_table_t));
		index_table->key_offset = LE16(index_table->key_offset);
		index_table->param_format = LE16(index_table->param_format);
		index_table->param_length = LE32(index_table->param_length);
		index_table->param_max_length = LE32(index_table->param_max_length);
		index_table->data_offset = LE32(index_table->data_offset);
	}

	header->magic = LE32(header->magic);
	header->version = LE32(header->version);
	header->key_table_offset = LE32(header->key_table_offset);
	header->data_table_offset = LE32(header->data_table_offset);
	header->num_entries = LE32(header->num_entries);

	if ((ret = write_buffer(file_path, sfo, sfo_size)) < 0)
		goto error;

	free(sfo);

error:
	return ret;
}

static sfo_context_param_t * sfo_context_get_param(sfo_context_t *context, const char *key) {
	list_node_t *node;
	sfo_context_param_t *param;

	if (!context || !key)
		return NULL;

	node = list_head(context->params);
	while (node) {
		param = (sfo_context_param_t *)node->value;
		if (param && strcmp(param->key, key) == 0)
			return param;
		node = node->next;
	}

	return NULL;
}

u8* sfo_get_param_value(sfo_context_t *in, const char* param) {
	sfo_context_param_t *p;

	p = sfo_context_get_param(in, param);
	if (p != NULL) {
		return (p->value);
	}

	return NULL;
}

void sfo_grab(sfo_context_t *inout, sfo_context_t *tpl, int num_keys, const sfo_key_pair_t *keys) {
	sfo_context_param_t *p1;
	sfo_context_param_t *p2;
	int i;

	for (i = 0; i < num_keys; ++i) {
		if (!keys[i].flag)
			continue;

		p1 = sfo_context_get_param(inout, keys[i].name);
		p2 = sfo_context_get_param(tpl, keys[i].name);

		if (p1 && p2) {
			if (strcmp(keys[i].name, "PARAMS") != 0) {
				if (p1->actual_length != p2->actual_length) {
					p1->value = (u8 *)realloc(p1->value, p2->actual_length);
					memset(p1->value, 0, p2->actual_length);
				}

				memcpy(p1->value, p2->value, p2->actual_length);
				p1->format = p2->format;
				p1->length = p2->length;
				p1->max_length = p2->max_length;
				p1->actual_length = p2->actual_length;
			} else {
				sfo_param_params_t *params1;
				sfo_param_params_t *params2;

				// assert(p1->actual_length == p2->actual_length);

				params1 = (sfo_param_params_t *)p1->value;
				params2 = (sfo_param_params_t *)p2->value;

				params1->user_id_1 = params2->user_id_1;
				memcpy(params1->psid, params2->psid, SFO_PSID_SIZE);
				params1->user_id_2 = params2->user_id_2;
				memcpy(params1->account_id, params2->account_id, SFO_ACCOUNT_ID_SIZE);
			}
		}
	}
}

void sfo_patch(sfo_context_t *inout, unsigned int flags) {
	sfo_context_param_t *p;

	if ((flags & SFO_PATCH_FLAG_REMOVE_COPY_PROTECTION) != 0) {
		p = sfo_context_get_param(inout, "ATTRIBUTE");
		if (p != NULL && p->actual_length == 4) {
			u32 *flag = (u32 *)p->value;
			*flag = LE32(0);
		}
	}
}
