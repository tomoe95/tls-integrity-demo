#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define TS_SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buffer[64];
    size_t   buflen;
} ts_sha256_ctx;

// initialize the sha256 context & prepare ts_sha256_ctx
// -> feed data into the hash function
// -> conclude the hash process with cryptographic padding to process leftover data in buffer
// -> return 32-byte hash into digest array
void ts_sha256_init(ts_sha256_ctx *ctx);
void ts_sha256_update(ts_sha256_ctx *ctx, const uint8_t *data, size_t len);
void ts_sha256_final(ts_sha256_ctx *ctx, uint8_t digest[TS_SHA256_DIGEST_SIZE]);

// convenience: one time hashing into digest[32] (wrap init, update, final func in one call)
void ts_sha256_buffer(const uint8_t *data, size_t len, uint8_t digest[TS_SHA256_DIGEST_SIZE]);

#endif

