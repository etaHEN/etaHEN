#pragma once 
#define MD5_HASH_LENGTH (16)

typedef struct {
	int lo, hi;
	int a, b, c, d;
	unsigned char buffer[64];
	int block[16];
} MD5_CTX;
 
extern void MD5_Init(MD5_CTX *ctx);
extern void MD5_Update(MD5_CTX *ctx, const void *data, unsigned long size);
extern void MD5_Final(unsigned char *result, MD5_CTX *ctx);