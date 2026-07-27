#!/bin/sh
set -e   # どこかで失敗したら即座に停止する

WSSL=wolfssl-install

if [ "$(uname)" = "Darwin" ]; then
    EXTRA_LIBS="-framework CoreFoundation -framework Security"
else
    EXTRA_LIBS=""
fi


echo "=== building test_sha256 ==="
gcc -Wall -Wextra -std=c11 -o tests/test_sha256 tests/test_sha256.c src/sha256.c
./tests/test_sha256

echo "=== building test_hmac ==="
gcc -Wall -Wextra -std=c11 -Isrc -o tests/test_hmac tests/test_hmac.c src/hmac.c src/sha256.c
./tests/test_hmac

echo "=== building test_proto ==="
gcc -Wall -Wextra -std=c11 -o tests/test_proto tests/test_proto.c src/proto.c
./tests/test_proto

echo "=== building tls_server ==="
gcc -Wall -Wextra -std=c11 -I$WSSL/include -Isrc \
  -o src/tls_server src/tls_server.c src/hmac.c src/sha256.c src/proto.c \
  $WSSL/lib/libwolfssl.a $EXTRA_LIBS -lm

echo "=== building tls_client ==="
gcc -Wall -Wextra -std=c11 -I$WSSL/include -Isrc \
  -o src/tls_client src/tls_client.c src/hmac.c src/sha256.c src/proto.c \
  $WSSL/lib/libwolfssl.a $EXTRA_LIBS -lm

echo ""
echo "=== 全てのビルド・テストが成功しました ==="
