#include "util.h"

#include "my_libc.h"

#include <stdlib.h>
#include <string.h>

u64 x_to_u64(const char *hex) {
	u64 result, t;
	u32 len;
	int c;

	result = 0;
	t = 0;
	len = strlen(hex);

	while (len--) {
		c = *hex++;
		if (c >= '0' && c <= '9')
			t = c - '0';
		else if (c >= 'a' && c <= 'f')
			t = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			t = c - 'A' + 10;
		else
			t = 0;
		result |= t << (len * 4);
	}

	return result;
}

u8 * x_to_u8_buffer(const char *hex)
{
	char tmp[3] = { 0, 0, 0 };
	u8 *result;
	u8 *ptr;
	u32 len;

	len = strlen(hex);
	if (len % 2 != 0)
		return NULL;

	result = (u8 *)malloc(len);
	memset(result, 0, len);
	ptr = result;

	while (len--) {
		tmp[0] = *hex++;
		tmp[1] = *hex++;
		*ptr++ = (u8)x_to_u64(tmp);
	}

	return result;
}

int read_buffer(const char *file_path, u8 **buf, size_t *size) {
	FILE *fp;
	u8 *file_buf;
	size_t file_size;

	if ((fp = fopen(file_path, "rb")) == NULL)
		return -1;
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	file_buf = (u8 *)malloc(file_size);
	fread(file_buf, 1, file_size, fp);
	fclose(fp);

	if (buf)
		*buf = file_buf;
	else
		free(file_buf);
	if (size)
		*size = file_size;

	return 0;
}

int write_buffer(const char *file_path, u8 *buf, size_t size) {
	FILE *fp;

	if ((fp = fopen(file_path, "wb")) == NULL)
		return -1;
	fwrite(buf, 1, size, fp);
	fclose(fp);

	return 0;
}
