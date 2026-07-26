#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>
#include <stddef.h>

#define TCP_PORT 11111
#define MAX_PAYLOAD (1024 * 1024) // safety net for DoS

#define HMAC_KEY_PATH "certs/hmac.key"
#define HMAC_KEY_LEN 32

// load shared key from certs/hmac.key
// success: 0, fail: -1
int load_hmac_key(uint8_t out[HMAC_KEY_LEN]);

#endif
