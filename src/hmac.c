#include "hmac.h"
#include <string.h>

#define BLOCK_SIZE 64

void hmac_sha256(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t out[HMAC_SHA256_SIZE]) {
    uint8_t key_block[BLOCK_SIZE];
    memset(key_block, 0, BLOCK_SIZE);

    // if the key size is bigger than 64 bytes -> run hash sha256 to fit 64 bytes
    if (key_len > BLOCK_SIZE) {
        ts_sha256_buffer(key, key_len, key_block);
    } else {
        memcpy(key_block, key, key_len); // if shorter, add 0 from right-side until the length is 64 bytes
    }

    // ipad for inside
    // opad for outside
    uint8_t ipad[BLOCK_SIZE], opad[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    ts_sha256_ctx ctx;
    uint8_t inner_hash[TS_SHA256_DIGEST_SIZE];

    // calc sha256 hash
    // 1. inner_hash = SHA256(ipad || data)
    ts_sha256_init(&ctx);
    ts_sha256_update(&ctx, ipad, BLOCK_SIZE);
    ts_sha256_update(&ctx, data, data_len);
    ts_sha256_final(&ctx, inner_hash);

    //2. out = SHA256(opad || inner_hash)
    //       = SHA256(opad || SHA256(ipad || data))
    ts_sha256_init(&ctx);
    ts_sha256_update(&ctx, opad, BLOCK_SIZE);
    ts_sha256_update(&ctx, inner_hash, TS_SHA256_DIGEST_SIZE);
    ts_sha256_final(&ctx, out);
}
