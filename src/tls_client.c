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

// user can set the specific host server or default
int main(int argc, char *argv[]) {
    const char *host = (argc >= 2) ? argv[1] : "127.0.0.1";

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

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(fd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}
