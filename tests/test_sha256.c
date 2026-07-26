#include <stdio.h>
#include <string.h>
#include "../src/sha256.h"

static int failures = 0;

static void print_hex(const uint8_t *d, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", d[i]); // 2 digits hexadecimal (0x05 -> 05)
}

static void check_vector(const char *label, const char *msg, size_t msg_len,
                          const char *expected_hex) {
    ts_sha256_ctx ctx;
    uint8_t digest[TS_SHA256_DIGEST_SIZE]; // result of calc (32 bytes raw)
    char got_hex[TS_SHA256_DIGEST_SIZE * 2 + 1];

    // run the hash: (init -> update -> final)
    ts_sha256_init(&ctx);
    ts_sha256_update(&ctx, (const uint8_t *)msg, msg_len);
    ts_sha256_final(&ctx, digest);

    // each byte -> 2 digits hex (got_hex[i..i+1])
    for (size_t i = 0; i < TS_SHA256_DIGEST_SIZE; i++) {
        sprintf(got_hex + i * 2, "%02x", digest[i]);
    }

    // if got_hex == expected_hex -> ok = 1
    int ok = (strcmp(got_hex, expected_hex) == 0);

    printf("[%s] %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) {
        printf("       got: "); print_hex(digest, TS_SHA256_DIGEST_SIZE); printf("\n");
        printf("  expected: %s\n", expected_hex);
        failures++;
    }
}


// combined all processes in one func (using ts_sha256_buffer func)
static void check_vector_buffer(const char *label, const char *msg, size_t msg_len,
                                 const char *expected_hex) {
    uint8_t digest[TS_SHA256_DIGEST_SIZE];
    char got_hex[TS_SHA256_DIGEST_SIZE * 2 + 1];

    ts_sha256_buffer((const uint8_t *)msg, msg_len, digest);

    for (size_t i = 0; i < TS_SHA256_DIGEST_SIZE; i++) {
        sprintf(got_hex + i * 2, "%02x", digest[i]);
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
    // generate correct sha256 with: echo -n "string" | sha256sum

    /* FIPS 180-4 test vectors */
    check_vector("empty string", "", 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    check_vector("\"abc\" (1 block)", "abc", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    /* 56 bytes: spans two 64-byte blocks after padding, exercises the
       while-loop in ts_sha256_update across multiple blocks */
    const char *two_block_msg =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    check_vector("56-byte message (2 blocks)", two_block_msg, strlen(two_block_msg),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    
    const char *four_block_msg = 
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    check_vector("4 blocks message", four_block_msg, strlen(four_block_msg),
            "59f109d9533b2b70e7c3b814a2bd218f78ea5d3714455bc67987cf0d664399cf");

    // use buffer func
    check_vector_buffer("ts_sha256_buffer one-shot \"abc\"", "abc", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    if (failures == 0) {
        printf("\nAll tests passed.\n");
        return 0;
    } else {
        printf("\n%d test(s) failed.\n", failures);
        return 1;
    }
}
