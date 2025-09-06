/*
 * This code would not have been possible without the prior work and
 * suggestions of various sourced.  Special thanks to Robey for
 * all his time/help tracking down bugs and his ever-helpful advice.
 *
 * 04/09:  Fixed the "*\*" against "*a" bug (caused an endless loop)
 *
 *   Chris Fuller  (aka Fred1@IRC & Fwitz@IRC)
 *     crf@cfox.bchs.uh.edu
 *
 * I hereby release this code into the public domain
 *
 */

#include "util.h"

#define WILDCARD_ANY '*' /* matches 0 or more characters (including spaces) */
#define WILDCARD_EXACT '?' /* matches exactly one character */

#define NO_MATCH 0
#define MATCH (match + sofar)

static int wildcard_match_int(const char *data, const char *mask, int ignore_case) {
	const char *ma = mask;
	const char *na = data;
	const char *lsm = 0;
	const char *lsn = 0;
	int match = 1;
	int sofar = 0;

	/* null strings should never match */
	if ((ma == 0) || (na == 0) || (!*ma) || (!*na))
		return NO_MATCH;

	/* find the end of each string */
	while (*(++mask));
	mask--;

	while (*(++data));
	data--;

	while (data >= na) {
		/* if the mask runs out of chars before the string, fall back on a wildcard or fail */
		if (mask < ma) {
			if (lsm) {
				data = --lsn;
				mask = lsm;
				if (data < na)
					lsm = 0;
				sofar = 0;
			} else
				return NO_MATCH;
		}

		switch (*mask) {
			case WILDCARD_ANY: /* matches anything */
				do {
					mask--; /* zap redundant wilds */
				} while (mask >= ma && *mask == WILDCARD_ANY);
				lsm = mask;
				lsn = data;
				match += sofar;
				sofar = 0; /* update fallback pos */
				if (mask < ma)
					return MATCH;
				continue; /* next char, please */

			case WILDCARD_EXACT:
				mask--;
				data--;
				continue; /* '?' always matches */
		}

		if (ignore_case ? (toupper(*mask) == toupper(*data)) : (*mask == *data)) { /* if matching char */
			mask--;
			data--;
			sofar++; /* tally the match */
			continue; /* next char, please */
		}

		if (lsm) { /* to to fallback on '*' */
			data = --lsn;
			mask = lsm;
			if (data < na)
				lsm = 0; /* rewind to saved pos */
			sofar = 0;
			continue; /* next char, please */
		}
	
		return NO_MATCH; /* no fallback = no match */
	}
	
	while (mask >= ma && *mask == WILDCARD_ANY)
		mask--; /* zap leftover %s & *s */

	return mask >= ma ? NO_MATCH : MATCH; /* start of both = match */
}

int wildcard_match(const char *data, const char *mask) {
	return wildcard_match_int(data, mask, 0) != 0;
}

int wildcard_match_icase(const char *data, const char *mask) {
	return wildcard_match_int(data, mask, 1) != 0;
}
