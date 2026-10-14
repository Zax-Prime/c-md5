/**
 * MD5 checksum library interface
 *
 * Author: Zax-Prime
 * License: MIT
 *
 * Attribution:
 * Based on c-md5 originally written by Dave Eddy <ysap@daveeddy.com>.
 */

#ifndef MD5_H
#define MD5_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 128-bit md5 state
struct md5_ctx {
	uint32_t a, b, c, d;
	uint64_t len;
	uint8_t buf[64];
	size_t buf_len;
};

// initialize state
void md5_init(struct md5_ctx *ctx);

// feed data bytes
void md5_update(struct md5_ctx *ctx, const void *data, size_t len);

// finalize and write 16-byte raw digest
void md5_final(struct md5_ctx *ctx, uint8_t digest[16]);

// format 16-byte digest into 32 hex chars + null terminator
void md5_to_hex(const uint8_t digest[16], char hex[33]);

// hash an open file descriptor (returns 0 on success, -1 on error)
int md5_fd(int fd, uint8_t digest[16]);

// hash a file by path (returns 0 on success, -1 on error)
int md5_file(const char *path, uint8_t digest[16]);

#ifdef __cplusplus
}
#endif

#endif // MD5_H
