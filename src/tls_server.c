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

#define TCP_PORT 11111

// the receiver of TCP connection
static int make_listen_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); // AF_INET=IPv4, SOCK_STREAM=TCP
    if (fd < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); // SOL_SOCKET=any socket type
                                                                 // SO_REUSEADDR=no need to wait for next socket

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;          // IPv4
    addr.sin_addr.s_addr = INADDR_ANY;  // any network interface (0.0.0.0)
    addr.sin_port = htons(port);        // setting port number -> htons: change the order from host's bytes to networks'bytes

    // bind the socket to the address+port (fails e.g. if the port is already in use)
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }
    // waiting for connections from clients (1: max number of pending/unaccepted connections at once)
    if (listen(fd, 1) < 0) { perror("listen"); exit(1); }
    
    // return the file descriptor of the receiver socket
    return fd;
}

// looping to send bytes while recording the left bytes until 0
static void send_all(WOLFSSL *ssl, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        // wolfSSL_write not always sends given bytes. (e.g., given bytes 1000 -> send 600 bytes)
        int n = wolfSSL_write(ssl, buf + sent, (int)(len - sent));
        if (n <= 0) {
            fprintf(stderr, "wolfSSL_write error: %d\n",
                    wolfSSL_get_error(ssl, n));
            exit(1);
        }
        sent += (size_t)n;
    }
}

// get the file path in the second command line argument when it runs
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file to serve> [tamper]\n", argv[0]);
        return 1;
    }

    // tamper = 1 if a second argument "tamper" was given, otherwise 0
    int tamper = (argc >= 3 && strcmp(argv[2], "tamper") == 0);

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror("fopen"); return 1; }
    uint8_t payload[MAX_PAYLOAD];                            // max 1MB
    size_t payload_len = fread(payload, 1, MAX_PAYLOAD, fp); // bytes actially read (truncated at MAX_PAYLOAD if the file is larger)
    fclose(fp);
 
    // read hmac key 
    uint8_t hmac_key[HMAC_KEY_LEN];
    if (load_hmac_key(hmac_key) != 0) {
        fprintf(stderr, "HMAC鍵の読み込みに失敗しました(certs/hmac.keyを確認してください)\n");
        return 1;
    }

    // compute the HMAC tag for the payload (the client will verify this to detect tampering)
    uint8_t tag[HMAC_SHA256_SIZE];
    hmac_sha256(hmac_key, HMAC_KEY_LEN, payload, payload_len, tag);

    // (destroy the process below happens after the tag was already computed on the
    //  original data, so the sent tag will no longer match the tampered payload)
    if (tamper) {
        printf("[server] --tamper指定: 送信直前にペイロードを１バイト破壊します。\n");
    }

    // initialize the wolfSSL library
    wolfSSL_Init();
    
    // for the TLS setting (use TLS1.3)
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!ctx) { fprintf(stderr, "CTX_new failed\n"); return 1; }

    // check if the certificate and key can be used (PEM style text file)
    if (wolfSSL_CTX_use_certificate_file(ctx, "certs/server.crt", WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(ctx, "certs/server.key", WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "証明書/鍵の読み込みに失敗しました\n");
        return 1;
    }

    // make the receiver socket & show log
    int listen_fd = make_listen_socket(TCP_PORT);
    printf("[server] listening on port %d\n", TCP_PORT);

    // stop processing and wait until it is connected
    int conn_fd = accept(listen_fd, NULL, NULL);
    if (conn_fd < 0) { perror("accept"); return 1; }

    // object for one connection based on TLS setting (ctx)
    WOLFSSL *ssl = wolfSSL_new(ctx);
    // associate this SSL object with the accepted TCP socket
    wolfSSL_set_fd(ssl, conn_fd);

    // TLS handshake (check key, certificate, cryptography method etc)
    if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_accept error: %d\n",
                wolfSSL_get_error(ssl, 0));
        return 1;
    }

    printf("[server] TLSハンドシェイク完了 (cipher: %s)\n",
           wolfSSL_get_cipher(ssl));

    // destroy 1 byte of payload; the tag above was computed before this, so it will
    // no longer match once the client recomputes it
payload[0] ^= 0xFF;
    if (tamper && payload_len > 0) {
        payload[0] ^= 0xFF;          // flip every bit of the first byte (0xFF XOR anything inverts all 8 bits)
    }

    // execute send_all func 
    uint32_t len_be = htonl((uint32_t)payload_len);
    send_all(ssl, (uint8_t *)&len_be, sizeof(len_be)); // send payload length (big-endian), so the receiver knows how many bytes to expect
    send_all(ssl, payload, payload_len);               // send payload (file contents)
    send_all(ssl, tag, HMAC_SHA256_SIZE);              // send HMAC tag
 
    printf("[server] %zu bytes + HMACタグを送信しました\n", payload_len);

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(conn_fd);
    close(listen_fd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}
