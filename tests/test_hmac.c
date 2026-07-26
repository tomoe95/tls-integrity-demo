#include <stdio.h>
#include <string.h>
#include "../src/hmac.h"

static int failures = 0;

static void check_hmac(const char *label,
                        const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        const char *expected_hex) {
    uint8_t out[HMAC_SHA256_SIZE];
    char got_hex[HMAC_SHA256_SIZE * 2 + 1];

    hmac_sha256(key, key_len, data, data_len, out);

    for (size_t i = 0; i < HMAC_SHA256_SIZE; i++) {
        sprintf(got_hex + i * 2, "%02x", out[i]);
    }

    int ok = (strcmp(got_hex, expected_hex) == 0);
    printf("[%s] %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) {
        printf("       got: %s\n", got_hex);
        printf("  expected: %s\n", expected_hex);
        failures++;
    }
}

int main(void) {
    /* RFC 4231 Test Case 1: key length (20) = block size (20 < 64, no hashing needed) */
    uint8_t key1[20];
    memset(key1, 0x0b, 20);
    check_hmac("Test Case 1 (20-byte key)", key1, sizeof(key1),
        (const uint8_t *)"Hi There", 8,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    /* RFC 4231 Test Case 2: short key ("Jefe"), short data */
    const char *msg2 = "what do ya want for nothing?";
    check_hmac("Test Case 2 (short key \"Jefe\")",
        (const uint8_t *)"Jefe", 4,
        (const uint8_t *)msg2, strlen(msg2),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    // RFC 4231 Test Case 3: key = 0xaa * 20, data = 0xdd * 50
    uint8_t key3[20];
    memset(key3, 0xaa, 20);
    uint8_t data3[50];
    memset(data3, 0xdd, sizeof(data3));
    check_hmac("Test Case 3 (20-byte key, 50-byte data)", 
            key3, sizeof(key3),
            data3, sizeof(data3),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    /* RFC 4231 Test Case 6: key length (131) > block size (64)
       exercises the ts_sha256_buffer(key) branch inside hmac_sha256 */
    uint8_t key6[131];
    memset(key6, 0xaa, sizeof(key6));
    const char *msg6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    check_hmac("Test Case 6 (131-byte key > block size)",
        key6, sizeof(key6),
        (const uint8_t *)msg6, strlen(msg6),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    if (failures == 0) {
        printf("\nAll tests passed.\n");
        return 0;
    } else {
        printf("\n%d test(s) failed.\n", failures);
        return 1;
    }
}
