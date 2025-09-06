// NOLINTBEGIN

/* Include the GCC super header */
#if defined(__GNUC__)
# include <stdint.h>
# include <x86intrin.h>
#endif

#include <stdint.h>
#include <string.h>

/*
   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain
 */

typedef struct
{
	uint32_t state[5];
	uint32_t count[2];
	unsigned char buffer[64];
} SHA1_CTX;

/* Hash a single 512-bit block. This is the core of the algorithm. */
static inline void SHA1Transform(uint32_t *restrict state, const uint8_t *restrict data) {
	/* sha1-x86.c - Intel SHA extensions using C intrinsics    */
	/*   Written and place in public domain by Jeffrey Walton  */
	/*   Based on code from Intel, and by Sean Gulley for      */
	/*   the miTLS project.                                    */

	/* gcc -DTEST_MAIN -msse4.1 -msha sha1-x86.c -o sha1.exe   */
	__m128i ABCD, ABCD_SAVE, E0, E0_SAVE, E1;
	__m128i MSG0, MSG1, MSG2, MSG3;
	const __m128i MASK = _mm_set_epi64x(0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL);

	/* Load initial values */
	ABCD = _mm_loadu_si128((const __m128i*) state);
	E0 = _mm_set_epi32(state[4], 0, 0, 0);
	ABCD = _mm_shuffle_epi32(ABCD, 0x1B);

	/* Save current state  */
	ABCD_SAVE = ABCD;
	E0_SAVE = E0;

	/* Rounds 0-3 */
	MSG0 = _mm_loadu_si128((const __m128i*)(data + 0));
	MSG0 = _mm_shuffle_epi8(MSG0, MASK);
	E0 = _mm_add_epi32(E0, MSG0);
	E1 = ABCD;
	ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);

	/* Rounds 4-7 */
	MSG1 = _mm_loadu_si128((const __m128i*)(data + 16));
	MSG1 = _mm_shuffle_epi8(MSG1, MASK);
	E1 = _mm_sha1nexte_epu32(E1, MSG1);
	E0 = ABCD;
	ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
	MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);

	/* Rounds 8-11 */
	MSG2 = _mm_loadu_si128((const __m128i*)(data + 32));
	MSG2 = _mm_shuffle_epi8(MSG2, MASK);
	E0 = _mm_sha1nexte_epu32(E0, MSG2);
	E1 = ABCD;
	ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
	MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
	MSG0 = _mm_xor_si128(MSG0, MSG2);

	/* Rounds 12-15 */
	MSG3 = _mm_loadu_si128((const __m128i*)(data + 48));
	MSG3 = _mm_shuffle_epi8(MSG3, MASK);
	E1 = _mm_sha1nexte_epu32(E1, MSG3);
	E0 = ABCD;
	MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
	MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
	MSG1 = _mm_xor_si128(MSG1, MSG3);

	/* Rounds 16-19 */
	E0 = _mm_sha1nexte_epu32(E0, MSG0);
	E1 = ABCD;
	MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
	MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
	MSG2 = _mm_xor_si128(MSG2, MSG0);

	/* Rounds 20-23 */
	E1 = _mm_sha1nexte_epu32(E1, MSG1);
	E0 = ABCD;
	MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
	MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
	MSG3 = _mm_xor_si128(MSG3, MSG1);

	/* Rounds 24-27 */
	E0 = _mm_sha1nexte_epu32(E0, MSG2);
	E1 = ABCD;
	MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
	MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
	MSG0 = _mm_xor_si128(MSG0, MSG2);

	/* Rounds 28-31 */
	E1 = _mm_sha1nexte_epu32(E1, MSG3);
	E0 = ABCD;
	MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
	MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
	MSG1 = _mm_xor_si128(MSG1, MSG3);

	/* Rounds 32-35 */
	E0 = _mm_sha1nexte_epu32(E0, MSG0);
	E1 = ABCD;
	MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
	MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
	MSG2 = _mm_xor_si128(MSG2, MSG0);

	/* Rounds 36-39 */
	E1 = _mm_sha1nexte_epu32(E1, MSG1);
	E0 = ABCD;
	MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
	MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
	MSG3 = _mm_xor_si128(MSG3, MSG1);

	/* Rounds 40-43 */
	E0 = _mm_sha1nexte_epu32(E0, MSG2);
	E1 = ABCD;
	MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
	MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
	MSG0 = _mm_xor_si128(MSG0, MSG2);

	/* Rounds 44-47 */
	E1 = _mm_sha1nexte_epu32(E1, MSG3);
	E0 = ABCD;
	MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
	MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
	MSG1 = _mm_xor_si128(MSG1, MSG3);

	/* Rounds 48-51 */
	E0 = _mm_sha1nexte_epu32(E0, MSG0);
	E1 = ABCD;
	MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
	MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
	MSG2 = _mm_xor_si128(MSG2, MSG0);

	/* Rounds 52-55 */
	E1 = _mm_sha1nexte_epu32(E1, MSG1);
	E0 = ABCD;
	MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
	MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
	MSG3 = _mm_xor_si128(MSG3, MSG1);

	/* Rounds 56-59 */
	E0 = _mm_sha1nexte_epu32(E0, MSG2);
	E1 = ABCD;
	MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
	MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
	MSG0 = _mm_xor_si128(MSG0, MSG2);

	/* Rounds 60-63 */
	E1 = _mm_sha1nexte_epu32(E1, MSG3);
	E0 = ABCD;
	MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
	MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
	MSG1 = _mm_xor_si128(MSG1, MSG3);

	/* Rounds 64-67 */
	E0 = _mm_sha1nexte_epu32(E0, MSG0);
	E1 = ABCD;
	MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
	MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
	MSG2 = _mm_xor_si128(MSG2, MSG0);

	/* Rounds 68-71 */
	E1 = _mm_sha1nexte_epu32(E1, MSG1);
	E0 = ABCD;
	MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
	MSG3 = _mm_xor_si128(MSG3, MSG1);

	/* Rounds 72-75 */
	E0 = _mm_sha1nexte_epu32(E0, MSG2);
	E1 = ABCD;
	MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
	ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);

	/* Rounds 76-79 */
	E1 = _mm_sha1nexte_epu32(E1, MSG3);
	E0 = ABCD;
	ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);

	/* Combine state */
	E0 = _mm_sha1nexte_epu32(E0, E0_SAVE);
	ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);

	/* Save state */
	ABCD = _mm_shuffle_epi32(ABCD, 0x1B);
	_mm_storeu_si128((__m128i*) state, ABCD);
	state[4] = _mm_extract_epi32(E0, 3);
}


/* SHA1Init - Initialize new context */

static inline void SHA1Init(SHA1_CTX *restrict context) {
	/* SHA1 initialization constants */
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
	context->state[4] = 0xC3D2E1F0;
	context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */

static inline void SHA1Update(SHA1_CTX *restrict context, const uint8_t *restrict data, size_t len) {
	uint32_t i;

	uint32_t j;

	j = context->count[0];
	context->count[0] += len << 3;
	if (context->count[0] < j)
		context->count[1]++;
	context->count[1] += (len >> 29);
	j = (j >> 3) & 63;
	if ((j + len) > 63)
	{
		(void)memcpy(&context->buffer[j], data, (i = 64 - j));
		SHA1Transform(context->state, context->buffer);
		for (; i + 63 < len; i += 64)
		{
			SHA1Transform(context->state, &data[i]);
		}
		j = 0;
	}
	else
		i = 0;
	(void)memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

static inline void SHA1Final(
	unsigned char *digest,
	SHA1_CTX * context
)
{
	unsigned i;

	unsigned char finalcount[8];

	for (i = 0; i < 8; i++)
	{
		finalcount[i] = (unsigned char) ((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);      /* Endian independent */
	}
	unsigned char c = 0200;
	SHA1Update(context, &c, 1);
	while ((context->count[0] & 504) != 448)
	{
		c = 0000;
		SHA1Update(context, &c, 1);
	}
	SHA1Update(context, finalcount, 8); /* Should cause a SHA1Transform() */
	for (i = 0; i < 20; i++)
	{
		digest[i] = (unsigned char)
			((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
	}
}

static const uint8_t NID_KEY[] = {
	(uint8_t) 0x51, (uint8_t) 0x8D, (uint8_t) 0x64, (uint8_t) 0xA6,
	(uint8_t) 0x35, (uint8_t) 0xDE, (uint8_t) 0xD8, (uint8_t) 0xC1,
	(uint8_t) 0xE6, (uint8_t) 0xB0, (uint8_t) 0x39, (uint8_t) 0xB1,
	(uint8_t) 0xC3, (uint8_t) 0xE5, (uint8_t) 0x52, (uint8_t) 0x30
};

uint64_t gen_nid_sha1(uint8_t *restrict res, const char *restrict str, const size_t length) {
	SHA1_CTX ctx;
	SHA1Init(&ctx);
	SHA1Update(&ctx, (uint8_t *)str, length);
	SHA1Update(&ctx, NID_KEY, sizeof(NID_KEY));
	SHA1Final(res, &ctx);
	return __builtin_bswap64(*(uint64_t *)(res));
}

// NOLINTEND
