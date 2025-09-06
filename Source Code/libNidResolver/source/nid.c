#include <string.h>
#include "nid.h"

// NOLINTBEGIN

#define NID_DIGEST_LENGTH 8
#define NID_SHA_LENGTH 20

extern uint64_t gen_nid_sha1(uint8_t *restrict res, const char *restrict str, const size_t length);

static const char encoder[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";

static inline void b64encode(char *restrict dest, const unsigned char *restrict src) {
	for (unsigned int i = 0, j = 0; j < NID_LENGTH;) {
		const uint32_t a = src[i++];
		const uint32_t b = src[i++];
		const uint32_t c = src[i++];

		const uint32_t abc = (a << 16) | (b << 8) | c;

		dest[j++] = encoder[(abc >> 18) & 0x3F];
		dest[j++] = encoder[(abc >> 12) & 0x3F];
		dest[j++] = encoder[(abc >> 6) & 0x3F];
		dest[j++] = encoder[abc & 0x3F];
	}
	dest[NID_LENGTH] = 0;
}

static void fillNid(void *restrict buf, const char *restrict sym, const size_t length) {
	uint8_t encodedDigest[NID_DIGEST_LENGTH + 1];
	uint8_t sha1[NID_SHA_LENGTH];

	(void)memset(encodedDigest, 0, sizeof(encodedDigest));
	(void)memset(sha1, 0, sizeof(sha1));

	*(uint64_t *)encodedDigest = gen_nid_sha1(sha1, sym, length);
	encodedDigest[NID_DIGEST_LENGTH] = 0;
	b64encode((char*)buf, encodedDigest);
}

Nid make_nid(const char *restrict sym, const size_t length) {
	Nid nid;
	fillNid(&nid, sym, length);
	return nid;
}

// NOLINTEND
