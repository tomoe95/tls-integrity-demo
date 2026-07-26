#ifndef HMAC_H
#define HMAC_H

#include "sha256.h"

#define HMAC_SHA256_SIZE TS_SHA256_DIGEST_SIZE

// compute HMAC-SHA256 of `data` using `key`, result written to `out`
void hmac_sha256(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t out[HMAC_SHA256_SIZE]);

#endif
