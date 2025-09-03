/*
 * lifehash.c
 * primary implementation file for lifehash
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lifehash.h"
#define SHA256_IMPLEMENTATION
#include "sha256.h"

void
lifehash_image_free(LifeHashImage *image)
{
	free(image->colors);
	free(image);
}

LifeHashImage *
lifehash_make_from_utf8(
		const char *s,
		LifeHashVersion version,
		size_t module_size,
		bool has_alpha)
{
	size_t len = strlen(s);

	return lifehash_make_from_data(
		(const uint8_t *) s, len, version,
		module_size, has_alpha);
}

LifeHashImage *
lifehash_make_from_data(
		const uint8_t *data,
		size_t len,
		LifeHashVersion version,
		size_t module_size,
		bool has_alpha)
{
	uint8_t digest[32];

	lifehash_sha256(data, len, digest);

	return lifehash_make_from_digest(
		digest, version, module_size, has_alpha);
}

LifeHashImage *
lifehash_make_from_digest(
		const uint8_t* digest,
		LifeHashVersion version,
		size_t module_size,
		bool has_alpha)
{
	// the initial board
	struct life_board board;
	// the maximum amount of life generations before
	// the simulation is cut off
	size_t generation_cap;
	// whether the practical board is 16x16 instead of
	// 32x32
	bool is_small;

	switch (version) {
		case lifehash_version1:
		case lifehash_version2:
			generation_cap = 150;
			is_small = true;
			break;
		case lifehash_detailed:
		case lifehash_fiducial:
		case lifehash_grayscale_fiducial:
			generation_cap = 300;
			is_small = false;
			break:
		default:
			return NULL;
	}

	uint8_t digest_ii[32];
	if (is_small) {
		if (version == lifehash_version2) {
			lifehash_sha256(digest, 32, digest_ii);
		} else {
			memcpy(digest_ii, digest, 32);
		}

		for (int i = 0; i < 16; i++) {
			uint32_t row = digest_ii[i * 2 + 0] * 0x01000100
				         | digest_ii[i * 2 + 1] * 0x00010001;
			board.rows[i + 00] = row;
			board.rows[i + 16] = row;
		}
	} else {
		uint8_t digest_iii[32], digest_iv[32];
		if (version == lifehash_grayscale_fiducial) {
			lifehash_sha256(digest, 32, digest_ii);
			memcpy(digest, digest_ii, 32);
		}

		lifehash_sha256(digest,     32, digest_ii);
		lifehash_sha256(digest_ii,  32, digest_iii);
		lifehash_sha256(digest_iii, 32, digest_iv);

		for (int i = 0; i < 16; i++) {
			board.rows[i + 00] = digest[i * 2 + 0] << 24 |
				                 digest[i * 2 + 1] << 16 |
			                  digest_ii[i * 2 + 0] << 8 |
			                  digest_ii[i * 2 + 1];
			board.rows[i + 16] = digest_iii[i * 2 + 0] << 24 |
				                 digest_iii[i * 2 + 1] << 16 |
			                      digest_iv[i * 2 + 0] << 8 |
			                      digest_iv[i * 2 + 1];
		}
	}
	/* i can almost guarantee that there's a cleaner way to
	 * do board population but . whatevs */

	// TODO: call into cgol simulation function
}

void
lifehash_sha256(
		const uint8_t *data,
		size_t len,
		uint8_t digest[32])
{
	sha256_digest(data, len, digest);
}
