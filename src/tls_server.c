#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

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


int main(void) {
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

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(conn_fd);
    close(listen_fd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}
