#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "hmac.h"
#include "proto.h"


// wolfSSL_read may return fewer bytes than requested, just like wolfSSL_write on the server side;
// loop until `len` bytes are received <-> send_all in tls_server.c
static void recv_all(WOLFSSL *ssl, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        int n = wolfSSL_read(ssl, buf + got, (int)(len - got));
        if (n <= 0) {
            fprintf(stderr, "wolfSSL_read error: %d\n",
                    wolfSSL_get_error(ssl, n));
            exit(1);
        }
        got += (size_t)n;
    }
}
 
// prevent timing attacks (an adversary could otherwise guess the correct tag byte-by-byte
//by measuring how long the comparison takes)
static int consttime_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    // a[i] ^ b[i] is 0 only when the bytes match; OR-ing into diff means diff stays 0 only if EVERY bytes matched
    return diff == 0;
}

// user can set the specific host server or default
int main(int argc, char *argv[]) {
    const char *host = (argc >= 2) ? argv[1] : "127.0.0.1";

    // load certs/hmac.key (symmetric key)
    uint8_t hmac_key[HMAC_KEY_LEN];
    if (load_hmac_key(hmac_key) != 0) {
        fprintf(stderr, "HMAC鍵の読み込みに失敗しました(certs/hmac.keyを確認してください)\n");
        return 1;
    }

    wolfSSL_Init();

    // set up for client side to use TLS 1.3
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) { fprintf(stderr, "CTX_new failed\n"); return 1; }

    // register the CA certificate(s) this client will trust when verifying the server
    // (using server.crt directly since it's self-signed; normally a real CA cert)
    if (wolfSSL_CTX_load_verify_locations(ctx, "certs/server.crt", NULL) != WOLFSSL_SUCCESS) { // NULL = not directory, only one file
        fprintf(stderr, "CA証明書の読み込みに失敗しました\n");
        return 1;
    }
    
    // create a TCP socket (IPv4)
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    // information of connection (set the IP address to WHERE?)
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));           // clear struct
    addr.sin_family = AF_INET;                // IPv4
    addr.sin_port = htons(TCP_PORT);          // port number to the connection
    inet_pton(AF_INET, host, &addr.sin_addr); // transfer IP address from strings("127.0.0.1") -> binary
    
    // connect (attempt to connect to the specific IP address, port) <-> server: waiting to accept (bind -> listen -> accept)
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); return 1;
    }

    // create a per-connection TLS object and associate it with the TCP socket
    WOLFSSL *ssl = wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, fd);

    // start TLS handshake from client <-> server: wolfSSL_accept (accept handshake)
    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_connect error: %d\n",
                wolfSSL_get_error(ssl, 0));
        return 1;
    }
    printf("[client] TLSハンドシェイク完了 (cipher: %s)\n",
           wolfSSL_get_cipher(ssl));

    // convert length from network byte order to host byte order (ntohl) <-> server used htonl
    uint32_t len_be;
    recv_all(ssl, (uint8_t *)&len_be, sizeof(len_be)); // 1. receive the length of 4 bytes
    uint32_t payload_len = ntohl(len_be);              // 2. network style to host style
 
    // prevent from DoS
    if (payload_len > MAX_PAYLOAD) {
        fprintf(stderr, "payload too large (%u bytes)\n", payload_len);
        return 1;
    }
 
    // allocate the memory for the payload, receive it
    uint8_t *payload = malloc(payload_len);
    if (!payload) { fprintf(stderr, "malloc failed\n"); return 1; }
    recv_all(ssl, payload, payload_len);
 
    // receive 32 bytes HMAC tag
    uint8_t recv_tag[HMAC_SHA256_SIZE];
    recv_all(ssl, recv_tag, HMAC_SHA256_SIZE);
 
    // calc HMAC tag from payload
    uint8_t calc_tag[HMAC_SHA256_SIZE];
    hmac_sha256(hmac_key, HMAC_KEY_LEN, payload, payload_len, calc_tag);
 
    printf("[client] %u bytes受信、HMAC検証を実行します\n", payload_len);
 
    if (consttime_eq(recv_tag, calc_tag, HMAC_SHA256_SIZE)) {
        printf("[OK] integrity verified — データは改ざんされていません\n");
    } else {
        printf("[NG] tampering detected — データが改ざんされています\n");
    }

    free(payload);
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(fd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}
