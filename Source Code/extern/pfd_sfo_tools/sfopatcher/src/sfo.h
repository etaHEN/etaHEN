#ifndef _SFO_H_
#define _SFO_H_

#include "types.h"
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSVC)
#	pragma pack(push, 1)
#endif

#define SFO_MAGIC   0x46535000u
#define SFO_VERSION 0x0101u /* 1.1 */

#define SFO_ACCOUNT_ID_SIZE 16
#define SFO_PSID_SIZE 16

typedef struct sfo_header_s {
	u32 magic;
	u32 version;
	u32 key_table_offset;
	u32 data_table_offset;
	u32 num_entries;
} sfo_header_t;

typedef struct sfo_index_table_s {
	u16 key_offset;
	u16 param_format;
	u32 param_length;
	u32 param_max_length;
	u32 data_offset;
} sfo_index_table_t;

typedef struct sfo_param_params_s {
	u8 unk1[12];
	u32 unk2;
	u32 unk3;
	u32 unk4;
	u32 user_id_1;
	u8 psid[SFO_PSID_SIZE];
	u32 user_id_2;
	u8 account_id[SFO_ACCOUNT_ID_SIZE];
	u8 chunk[1]; // u8 chunk[0]; // sus
} sfo_param_params_t;

#if defined(_MSVC)
#	pragma pack(pop)
#endif

typedef struct sfo_context_param_s {
	char *key;
	u16 format;
	u32 length;
	u32 max_length;
	size_t actual_length;
	u8 *value;
} sfo_context_param_t;

struct sfo_context_s {
	list_t *params;
};

#define SFO_PATCH_FLAG_REMOVE_COPY_PROTECTION (1 << 0)

typedef struct sfo_context_s sfo_context_t;

typedef struct sfo_key_pair_s {
	const char *name;
	int flag;
} sfo_key_pair_t;

sfo_context_t * sfo_alloc(void);
void sfo_free(sfo_context_t *context);
int sfo_read(sfo_context_t *context, const char *file_path);
u8* sfo_get_param_value(sfo_context_t *in, const char* param);

#ifdef __cplusplus
}
#endif

#endif /* !_SFO_H_ */
