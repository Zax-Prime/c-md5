/**
 * C implementation of the md5 checksum algorithm
 *
 * # Created
 * Author: Dave Eddy <ysap@daveeddy.com>
 * Date: August 24, 2026
 * License: MIT
 *
 * # Contributors
 * - Dave Eddy <ysap@daveeddy.com>
 */

#include "md5.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__unix__) || defined(__APPLE__) || defined(__linux__) || \
    (defined(__POSIX_C_SOURCE) && __POSIX_C_SOURCE >= 200112L)
#include <sys/mman.h>
#define HAVE_MMAP 1
#endif

// buffer size for streaming fd reads
#define BUF_SIZE (64 * 1024)

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define ALIGN64 _Alignas(64)
#elif defined(__GNUC__) || defined(__clang__)
#define ALIGN64 __attribute__((aligned(64)))
#else
#define ALIGN64
#endif

// round functions
#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define H(x, y, z) ((x) ^ ((y) ^ (z)))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

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

// G(b, c, d) = (b & d) | (c & ~d). disjoint bits allow adding the c term
// before b is ready.
#define STEP_G(a, b, c, d, m, k, s) do { \
	(a) += (m) + (k) + ((c) & ~(d)); \
	KEEP(a); \
	(a) += (b) & (d); \
	(a) = ROTL((a), (s)) + (b); \
} while (false)

// little endian load
static inline uint32_t load_le32(const uint8_t *p) {
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
	    (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

#define M(i) load_le32(p + (i) * 4)

// process n full 64 byte blocks starting at p
static void process_blocks(struct md5_ctx *ctx, const uint8_t *p, size_t n) {
	uint32_t a = ctx->a;
	uint32_t b = ctx->b;
	uint32_t c = ctx->c;
	uint32_t d = ctx->d;

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

	ctx->a = a;
	ctx->b = b;
	ctx->c = c;
	ctx->d = d;
}

// pad with 0x80, zeros, and bit length
static void finalize_tail(struct md5_ctx *ctx, const uint8_t *rem_bytes, size_t rem) {
	uint8_t tail[128];
	if (rem > 0)
		memcpy(tail, rem_bytes, rem);
	tail[rem++] = 0x80;

	size_t tail_len = rem <= 56 ? 64 : 128;
	memset(tail + rem, 0, tail_len - 8 - rem);

	uint64_t bits = ctx->len << 3;
	for (size_t i = 0; i < 8; i++)
		tail[tail_len - 8 + i] = (uint8_t)(bits >> (i * 8));

	process_blocks(ctx, tail, tail_len / 64);
}

void md5_init(struct md5_ctx *ctx) {
	ctx->a = 0x67452301;
	ctx->b = 0xefcdab89;
	ctx->c = 0x98badcfe;
	ctx->d = 0x10325476;
	ctx->len = 0;
	ctx->buf_len = 0;
}

void md5_update(struct md5_ctx *ctx, const void *data, size_t len) {
	const uint8_t *p = (const uint8_t *)data;
	ctx->len += (uint64_t)len;

	if (ctx->buf_len > 0) {
		size_t need = 64 - ctx->buf_len;
		if (len < need) {
			memcpy(ctx->buf + ctx->buf_len, p, len);
			ctx->buf_len += len;
			return;
		}
		memcpy(ctx->buf + ctx->buf_len, p, need);
		process_blocks(ctx, ctx->buf, 1);
		p += need;
		len -= need;
		ctx->buf_len = 0;
	}

	size_t full = len & ~(size_t)63;
	if (full > 0) {
		process_blocks(ctx, p, full / 64);
		p += full;
		len -= full;
	}

	if (len > 0) {
		memcpy(ctx->buf, p, len);
		ctx->buf_len = len;
	}
}

void md5_final(struct md5_ctx *ctx, uint8_t digest[16]) {
	finalize_tail(ctx, ctx->buf, ctx->buf_len);

	uint32_t words[] = {ctx->a, ctx->b, ctx->c, ctx->d};
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++)
			digest[i * 4 + j] = (uint8_t)(words[i] >> (j * 8));
	}
}

void md5_to_hex(const uint8_t digest[16], char hex[33]) {
	static const char digits[] = "0123456789abcdef";
	for (int i = 0; i < 16; i++) {
		hex[i * 2 + 0] = digits[digest[i] >> 4];
		hex[i * 2 + 1] = digits[digest[i] & 0xf];
	}
	hex[32] = '\0';
}

int md5_fd(int fd, uint8_t digest[16]) {
	ALIGN64 static uint8_t buf[BUF_SIZE];
	struct md5_ctx ctx;
	md5_init(&ctx);

#ifdef POSIX_FADV_SEQUENTIAL
	posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

	size_t have = 0;
	while (true) {
		ssize_t n = read(fd, buf + have, sizeof (buf) - have);

		if (n == -1) {
			if (errno == EINTR)
				continue;
			perror("read");
			return -1;
		} else if (n == 0) {
			break;
		}

		ctx.len += (uint64_t)n;
		have += (size_t)n;

		size_t full = have & ~(size_t)63;
		process_blocks(&ctx, buf, full / 64);
		have -= full;
		if (have > 0 && full > 0)
			memmove(buf, buf + full, have);
	}

	finalize_tail(&ctx, buf, have);

	uint32_t words[] = {ctx.a, ctx.b, ctx.c, ctx.d};
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++)
			digest[i * 4 + j] = (uint8_t)(words[i] >> (j * 8));
	}
	return 0;
}

int md5_file(const char *path, uint8_t digest[16]) {
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		perror("open");
		return -1;
	}

#ifdef HAVE_MMAP
	struct stat sb;
	if (fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode) && sb.st_size > 0) {
		size_t len = (size_t)sb.st_size;
		void *addr = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
		if (addr != MAP_FAILED) {
#ifdef MADV_SEQUENTIAL
			madvise(addr, len, MADV_SEQUENTIAL);
#endif
			struct md5_ctx ctx;
			md5_init(&ctx);
			ctx.len = (uint64_t)len;

			size_t full = len & ~(size_t)63;
			process_blocks(&ctx, (const uint8_t *)addr, full / 64);

			size_t rem = len - full;
			uint8_t tail_bytes[64];
			if (rem > 0)
				memcpy(tail_bytes, (const uint8_t *)addr + full, rem);
			munmap(addr, len);
			close(fd);

			finalize_tail(&ctx, tail_bytes, rem);

			uint32_t words[] = {ctx.a, ctx.b, ctx.c, ctx.d};
			for (int i = 0; i < 4; i++) {
				for (int j = 0; j < 4; j++)
					digest[i * 4 + j] = (uint8_t)(words[i] >> (j * 8));
			}
			return 0;
		}
	}
#endif

	int ret = md5_fd(fd, digest);
	close(fd);
	return ret;
}
