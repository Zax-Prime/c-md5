/**
 * Comprehensive edge case test suite for md5
 *
 * Author: Zax-Prime
 * License: MIT
 */

#include "md5.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct rfc_vector {
	const char *input;
	const char *expected;
};

static const struct rfc_vector rfc_cases[] = {
	{"",
	 "d41d8cd98f00b204e9800998ecf8427e"},
	{"a",
	 "0cc175b9c0f1b6a831c399e269772661"},
	{"abc",
	 "900150983cd24fb0d6963f7d28e17f72"},
	{"message digest",
	 "f96b697d7cb7938d525a2f31aaf161d0"},
	{"abcdefghijklmnopqrstuvwxyz",
	 "c3fcd3d76192e4007dfb496cca67e13b"},
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	 "d174ab98d277d9f5a5611c2c9f419d9f"},
	{"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	 "57edf4a22be3c955ac49da2e2107b67a"}
};

static void hash_buffer(const void *data, size_t len, char hex[33]) {
	struct md5_ctx ctx;
	md5_init(&ctx);
	md5_update(&ctx, data, len);
	uint8_t digest[16];
	md5_final(&ctx, digest);
	md5_to_hex(digest, hex);
}

static void test_rfc_vectors(void) {
	printf("testing RFC 1321 vectors... ");
	size_t count = sizeof (rfc_cases) / sizeof (rfc_cases[0]);
	for (size_t i = 0; i < count; i++) {
		char hex[33];
		hash_buffer(rfc_cases[i].input, strlen(rfc_cases[i].input), hex);
		if (strcmp(hex, rfc_cases[i].expected) != 0) {
			fprintf(stderr, "\nFAIL on RFC vector %zu: got %s, want %s\n",
			    i, hex, rfc_cases[i].expected);
			exit(1);
		}
	}
	printf("ok\n");
}

static void test_block_boundaries(void) {
	printf("testing block boundary sizes (0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128)... ");
	static const size_t sizes[] = {
		0, 1, 2, 54, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129, 255, 256
	};
	size_t n_sizes = sizeof (sizes) / sizeof (sizes[0]);

	uint8_t buf[512];
	for (size_t i = 0; i < sizeof (buf); i++)
		buf[i] = (uint8_t)(i * 31 + 7);

	for (size_t i = 0; i < n_sizes; i++) {
		size_t len = sizes[i];
		char hex_bulk[33];
		hash_buffer(buf, len, hex_bulk);

		// feed 1 byte at a time
		struct md5_ctx ctx_bytes;
		md5_init(&ctx_bytes);
		for (size_t b = 0; b < len; b++)
			md5_update(&ctx_bytes, &buf[b], 1);
		uint8_t digest[16];
		md5_final(&ctx_bytes, digest);
		char hex_bytes[33];
		md5_to_hex(digest, hex_bytes);

		if (strcmp(hex_bulk, hex_bytes) != 0) {
			fprintf(stderr, "\nFAIL on length %zu: bulk %s vs 1-byte %s\n",
			    len, hex_bulk, hex_bytes);
			exit(1);
		}
	}
	printf("ok\n");
}

static void test_chunk_streaming(void) {
	printf("testing variable chunk streaming... ");
	size_t total = 10000;
	uint8_t *data = malloc(total);
	assert(data != NULL);

	for (size_t i = 0; i < total; i++)
		data[i] = (uint8_t)(i ^ (i >> 5));

	char ref_hex[33];
	hash_buffer(data, total, ref_hex);

	static const size_t chunk_sizes[] = {1, 3, 7, 13, 31, 55, 56, 63, 64, 65, 127, 128, 500, 4096};
	size_t n_chunks = sizeof (chunk_sizes) / sizeof (chunk_sizes[0]);

	for (size_t c = 0; c < n_chunks; c++) {
		size_t chunk = chunk_sizes[c];
		struct md5_ctx ctx;
		md5_init(&ctx);

		size_t offset = 0;
		while (offset < total) {
			size_t n = total - offset;
			if (n > chunk)
				n = chunk;
			md5_update(&ctx, data + offset, n);
			offset += n;
		}

		uint8_t digest[16];
		md5_final(&ctx, digest);
		char hex[33];
		md5_to_hex(digest, hex);

		if (strcmp(hex, ref_hex) != 0) {
			fprintf(stderr, "\nFAIL on chunk size %zu: got %s, want %s\n",
			    chunk, hex, ref_hex);
			free(data);
			exit(1);
		}
	}

	free(data);
	printf("ok\n");
}

int main(void) {
	printf("=== Running Edge Case Test Suite ===\n");
	test_rfc_vectors();
	test_block_boundaries();
	test_chunk_streaming();
	printf("All edge case tests passed successfully.\n");
	return 0;
}
