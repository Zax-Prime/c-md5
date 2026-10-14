/**
 * C implementation of the md5 checksum algorithm
 *
 * Usage
 *
 *   $ ./md5 file.txt
 *   $ ./md5 < file.bin
 *   $ DEBUG=1 ./md5 < file.bin
 *
 * # Created
 * Author: Dave Eddy <ysap@daveeddy.com>
 * Date: August 24, 2026
 * License: MIT
 *
 * # Contributors
 * - Dave Eddy <ysap@daveeddy.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define DEBUG(fmt, ...) do { \
	if (g_debug) { \
		fprintf(stderr, "[%d:%s()] ", __LINE__, __func__); \
		fprintf(stderr, fmt, ##__VA_ARGS__); \
	} \
} while (false)

// read buffer size, must be a multiple of 64
#define BUF_SIZE (64 * 1024)

static bool g_debug = false;

struct md5_state {
	uint32_t a, b, c, d;
	uint64_t len;
};

// round functions, written so the newest value (x) is used as late as
// possible. G is split into two parts that don't share bits, see STEP_G.
#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define H(x, y, z) ((x) ^ ((y) ^ (z)))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// clang and gcc like to move the constant add to after the round function,
// which puts an extra add on the slow path. this empty asm stops that. other
// compilers just skip it.
#if defined(__GNUC__) || defined(__clang__)
#define KEEP(x) __asm__("" : "+r"(x))
#else
#define KEEP(x) ((void)0)
#endif

#define STEP(f, a, b, c, d, m, k, s) do { \
	(a) += (m) + (k); \
	KEEP(a); \
	(a) += f((b), (c), (d)); \
	(a) = ROTL((a), (s)) + (b); \
} while (false)

// G(b, c, d) = (b & d) | (c & ~d), the two halves never overlap so we can
// add them separately and do the c part before b is ready
#define STEP_G(a, b, c, d, m, k, s) do { \
	(a) += (m) + (k) + ((c) & ~(d)); \
	KEEP(a); \
	(a) += (b) & (d); \
	(a) = ROTL((a), (s)) + (b); \
} while (false)

// little endian load, works on any byte order and alignment. clang and gcc
// turn this into a single load on little endian targets.
static inline uint32_t load_le32(const uint8_t *p) {
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
	    (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

#define M(i) load_le32(p + (i) * 4)

// process n full 64 byte blocks starting at p
static void process_blocks(struct md5_state *st, const uint8_t *p, size_t n) {
	uint32_t a = st->a;
	uint32_t b = st->b;
	uint32_t c = st->c;
	uint32_t d = st->d;

	while (n--) {
		uint32_t A = a, B = b, C = c, D = d;

		// round 1
		STEP(F, a, b, c, d, M( 0), 0xd76aa478,  7);
		STEP(F, d, a, b, c, M( 1), 0xe8c7b756, 12);
		STEP(F, c, d, a, b, M( 2), 0x242070db, 17);
		STEP(F, b, c, d, a, M( 3), 0xc1bdceee, 22);
		STEP(F, a, b, c, d, M( 4), 0xf57c0faf,  7);
		STEP(F, d, a, b, c, M( 5), 0x4787c62a, 12);
		STEP(F, c, d, a, b, M( 6), 0xa8304613, 17);
		STEP(F, b, c, d, a, M( 7), 0xfd469501, 22);
		STEP(F, a, b, c, d, M( 8), 0x698098d8,  7);
		STEP(F, d, a, b, c, M( 9), 0x8b44f7af, 12);
		STEP(F, c, d, a, b, M(10), 0xffff5bb1, 17);
		STEP(F, b, c, d, a, M(11), 0x895cd7be, 22);
		STEP(F, a, b, c, d, M(12), 0x6b901122,  7);
		STEP(F, d, a, b, c, M(13), 0xfd987193, 12);
		STEP(F, c, d, a, b, M(14), 0xa679438e, 17);
		STEP(F, b, c, d, a, M(15), 0x49b40821, 22);

		// round 2
		STEP_G(a, b, c, d, M( 1), 0xf61e2562,  5);
		STEP_G(d, a, b, c, M( 6), 0xc040b340,  9);
		STEP_G(c, d, a, b, M(11), 0x265e5a51, 14);
		STEP_G(b, c, d, a, M( 0), 0xe9b6c7aa, 20);
		STEP_G(a, b, c, d, M( 5), 0xd62f105d,  5);
		STEP_G(d, a, b, c, M(10), 0x02441453,  9);
		STEP_G(c, d, a, b, M(15), 0xd8a1e681, 14);
		STEP_G(b, c, d, a, M( 4), 0xe7d3fbc8, 20);
		STEP_G(a, b, c, d, M( 9), 0x21e1cde6,  5);
		STEP_G(d, a, b, c, M(14), 0xc33707d6,  9);
		STEP_G(c, d, a, b, M( 3), 0xf4d50d87, 14);
		STEP_G(b, c, d, a, M( 8), 0x455a14ed, 20);
		STEP_G(a, b, c, d, M(13), 0xa9e3e905,  5);
		STEP_G(d, a, b, c, M( 2), 0xfcefa3f8,  9);
		STEP_G(c, d, a, b, M( 7), 0x676f02d9, 14);
		STEP_G(b, c, d, a, M(12), 0x8d2a4c8a, 20);

		// round 3
		STEP(H, a, b, c, d, M( 5), 0xfffa3942,  4);
		STEP(H, d, a, b, c, M( 8), 0x8771f681, 11);
		STEP(H, c, d, a, b, M(11), 0x6d9d6122, 16);
		STEP(H, b, c, d, a, M(14), 0xfde5380c, 23);
		STEP(H, a, b, c, d, M( 1), 0xa4beea44,  4);
		STEP(H, d, a, b, c, M( 4), 0x4bdecfa9, 11);
		STEP(H, c, d, a, b, M( 7), 0xf6bb4b60, 16);
		STEP(H, b, c, d, a, M(10), 0xbebfbc70, 23);
		STEP(H, a, b, c, d, M(13), 0x289b7ec6,  4);
		STEP(H, d, a, b, c, M( 0), 0xeaa127fa, 11);
		STEP(H, c, d, a, b, M( 3), 0xd4ef3085, 16);
		STEP(H, b, c, d, a, M( 6), 0x04881d05, 23);
		STEP(H, a, b, c, d, M( 9), 0xd9d4d039,  4);
		STEP(H, d, a, b, c, M(12), 0xe6db99e5, 11);
		STEP(H, c, d, a, b, M(15), 0x1fa27cf8, 16);
		STEP(H, b, c, d, a, M( 2), 0xc4ac5665, 23);

		// round 4
		STEP(I, a, b, c, d, M( 0), 0xf4292244,  6);
		STEP(I, d, a, b, c, M( 7), 0x432aff97, 10);
		STEP(I, c, d, a, b, M(14), 0xab9423a7, 15);
		STEP(I, b, c, d, a, M( 5), 0xfc93a039, 21);
		STEP(I, a, b, c, d, M(12), 0x655b59c3,  6);
		STEP(I, d, a, b, c, M( 3), 0x8f0ccc92, 10);
		STEP(I, c, d, a, b, M(10), 0xffeff47d, 15);
		STEP(I, b, c, d, a, M( 1), 0x85845dd1, 21);
		STEP(I, a, b, c, d, M( 8), 0x6fa87e4f,  6);
		STEP(I, d, a, b, c, M(15), 0xfe2ce6e0, 10);
		STEP(I, c, d, a, b, M( 6), 0xa3014314, 15);
		STEP(I, b, c, d, a, M(13), 0x4e0811a1, 21);
		STEP(I, a, b, c, d, M( 4), 0xf7537e82,  6);
		STEP(I, d, a, b, c, M(11), 0xbd3af235, 10);
		STEP(I, c, d, a, b, M( 2), 0x2ad7d2bb, 15);
		STEP(I, b, c, d, a, M( 9), 0xeb86d391, 21);

		a += A;
		b += B;
		c += C;
		d += D;

		p += 64;
	}

	st->a = a;
	st->b = b;
	st->c = c;
	st->d = d;
}

// returns 0 on success, -1 on failure
static int process_input(struct md5_state *st, int fd) {
	static uint8_t buf[BUF_SIZE];
	size_t have = 0;

	while (true) {
		ssize_t n = read(fd, buf + have, sizeof (buf) - have);

		if (n == -1) {
			if (errno == EINTR)
				continue;
			perror("read");
			return -1;
		} else if (n == 0) {
			// EOF
			break;
		}

		DEBUG("read %zd bytes\n", n);

		st->len += (uint64_t)n;
		have += (size_t)n;

		// hash every full block, keep the leftover bytes for next time
		size_t full = have & ~(size_t)63;
		process_blocks(st, buf, full / 64);
		have -= full;
		if (have > 0 && full > 0)
			memmove(buf, buf + full, have);
	}

	// pad with 0x80 then zeros until 56 mod 64, then the length in bits
	// as a 64 bit little endian int. this takes one or two blocks.
	uint8_t tail[128];
	memcpy(tail, buf, have);
	tail[have++] = 0x80;

	size_t tail_len = have <= 56 ? 64 : 128;
	memset(tail + have, 0, tail_len - 8 - have);

	uint64_t bits = st->len << 3;
	for (size_t i = 0; i < 8; i++)
		tail[tail_len - 8 + i] = (uint8_t)(bits >> (i * 8));

	DEBUG("padding into %zu final block(s)\n", tail_len / 64);
	process_blocks(st, tail, tail_len / 64);

	return 0;
}

static void print_hash(const struct md5_state *st) {
	static const char hex[] = "0123456789abcdef";
	uint32_t words[] = {st->a, st->b, st->c, st->d};
	char out[33];

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			uint8_t byte = (uint8_t)(words[i] >> (j * 8));
			out[i * 8 + j * 2] = hex[byte >> 4];
			out[i * 8 + j * 2 + 1] = hex[byte & 0xf];
		}
	}
	out[32] = '\0';

	puts(out);
}

int main(int argc, char **argv) {
	g_debug = getenv("DEBUG") != NULL;

	int fd = 0;

	// read from the file given as an argument
	if (argc > 1) {
		char *fname = argv[1];

		DEBUG("opening file: %s\n", fname);
		fd = open(fname, O_RDONLY);

		if (fd == -1) {
			perror("open");
			return 1;
		}
	}

	struct md5_state st = {
		0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0
	};

	int ret = process_input(&st, fd);

	close(fd);

	if (ret != 0)
		return 1;

	print_hash(&st);

	return 0;
}
