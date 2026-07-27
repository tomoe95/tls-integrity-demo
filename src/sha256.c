#include "sha256.h"
#include <string.h>

// the fractional parts of cube roots of first 64 prime numbers
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};


// bitwise right rotation 32-bit integer x by n positions
static uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32-n));
}


static void ts_sha256_transform(ts_sha256_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;

    // build w[0..15]: pack 4 bytes into one 32-bit word, big-endian
    // "abcd" -> 0x61 0x62 0x63 0x64 -> 0x61626364
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }

    // rotr: rotate right, bits that fall off the right wrap around to the left (no data lost)
    // >>  : shift right, bits that fall off the right are discarded (zero-filled on the left)
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    
    // initialize hash variable (32bits * 8)
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
 
    // rewriting hash variables
    // Ch(e,f,g): look at "e" for each bit -> if it is 1 -> pick the bit of "f"
    //                                        if it is 0 -> pick the bit of "g"
    // Maj(a,b,c): if more than 1 out of 3 is "1" -> "1"
    //             otherwise                      -> "0"                           
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g); 
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        
        // shifting the variable with t1 & t2
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    // add the value in the original state
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

// fractional part of square roots of first 8 prime numbers (2, 3, 5, 7, 11, 13, 17, 19)
void ts_sha256_init(ts_sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->bitlen = 0;
    ctx->buflen = 0;
}


// every 64 bytes, call ts_sha256_transform
void ts_sha256_update(ts_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    // track total message length in bits (used later for padding in ts_sha256_final)
    ctx->bitlen += (uint64_t)len * 8;

    while (len > 0) {
        // how many byte left in the buffer
        size_t n = 64 - ctx->buflen;
        if (n > len) n = len;
        // copy n right after from current empty position
        memcpy(ctx->buffer + ctx->buflen, data, n);
        ctx->buflen += n; // how many buffer
        data += n;        // go forward the pointer to the data that is not copied yet
        len -= n;         // reduce the amount of length that is not copied yet

        // call ts_sha256_transform every 64 bytes & reset buffer
        if (ctx->buflen == 64) {
            ts_sha256_transform(ctx, ctx->buffer);
            ctx->buflen = 0;
        }
    }
}

// for the last leftover buffer
void ts_sha256_final(ts_sha256_ctx *ctx, uint8_t digest[TS_SHA256_DIGEST_SIZE]) {
    uint64_t bitlen = ctx->bitlen;
    uint8_t pad = 0x80; // == 10000000
    ts_sha256_update(ctx, &pad, 1); // add the flag number (pad) in the last of the data
    uint8_t zero = 0x00;
    while (ctx->buflen != 56) { // 56 = 64 - 8(reserve 8 bytes for the length field, written later)
        ts_sha256_update(ctx, &zero, 1);
    }

    // transform bitlen(64 bits) -> 8 bytes big-endian
    uint8_t lenbytes[8];
    for (int i = 0; i < 8; i++) {
        lenbytes[i] = (uint8_t)(bitlen >> (56 - 8 * i));
    }

    // store the 8 bytes big-endian from 56 bytes-th
    memcpy(ctx->buffer + ctx->buflen, lenbytes, 8);
    ctx->buflen += 8;
    ts_sha256_transform(ctx, ctx->buffer);

    // 8 * 32bits -> 32 bytes big-endian
    for (int i = 0; i < 8; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}


// combine the hash processes in one function
void ts_sha256_buffer(const uint8_t *data, size_t len, uint8_t digest[TS_SHA256_DIGEST_SIZE]) {
    ts_sha256_ctx ctx;
    ts_sha256_init(&ctx);
    ts_sha256_update(&ctx, data, len);
    ts_sha256_final(&ctx, digest);
}
