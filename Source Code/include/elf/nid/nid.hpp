#pragma once

#include "b64.hpp"
#include "../../nid.hpp"
#include "sha1.hpp"
#include "util.hpp"
#include <stddef.h>

static inline constexpr void fillNid(Nid &buf, const StringView &sym) {
	constexpr size_t NID_DIGEST_LENGTH = 8;
	constexpr size_t NID_SHA_LENGTH = 20;
    uint8_t encodedDigest[NID_DIGEST_LENGTH + 1]{};
	uint8_t sha1[NID_SHA_LENGTH]{};
	genSha1(sha1, sym);
	for (size_t i = 0; i < NID_DIGEST_LENGTH; i++) {
		encodedDigest[i] = sha1[NID_DIGEST_LENGTH - 1 - i]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
	}
	b64encode(buf.str, encodedDigest);
}
