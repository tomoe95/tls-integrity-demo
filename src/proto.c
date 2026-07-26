#include "proto.h"
#include <stdio.h>

int load_hmac_key(uint8_t out[HMAC_KEY_LEN]) {
    FILE *fp = fopen(HMAC_KEY_PATH, "rb");
    if (!fp) return -1;

    size_t n = fread(out, 1, HMAC_KEY_LEN, fp);
    fclose(fp);

    if (n != HMAC_KEY_LEN) return -1;
    return 0;
}
