# tls-integrity-demo
![CI](https://github.com/tomoe95/tls-integrity-demo/actions/workflows/ci.yml/badge.svg)

wolfSSLを用いたTLS通信の上に、アプリケーション層でのデータ完全性検証を
組み合わせたクライアント/サーバーのデモプロジェクトです。
 
## 全体アーキテクチャ
 
```
┌──────────────────────────┐        ┌──────────────────────────┐
│   送信側 (tls_server)      │        │   受信側 (tls_client)     │
└──────────────────────────┘        └──────────────────────────┘
 
  1. ファイルを読み込む
             │
  2. HMACタグを計算
     (この時点の元データに対して)
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│                TLS 1.3 ハンドシェイク (wolfSSL)                     │
│        通信経路そのものを暗号化・認証する(盗聴・改ざん対策)                  │
└─────────────────────────────────────────────────────────────────┘
             │                                        │
             ▼                                        ▼
  3. [長さ] を送信   ─────────────────────▶   [長さ] を受信
                                                      │
                                                 上限チェック
                                                (DoS対策 / MAX_PAYLOAD)
             │                                        │
             ▼                                        ▼
  4. [payload] を送信 ────────────────────▶   [payload] を受信
             │                                        │
             ▼                                        ▼
  5. [tag] を送信     ─────────────────────▶   [recv_tag] を受信
 
                                                      │
                                                      ▼
                                          自前で HMAC を再計算
                                            (受信した payload から)
                                                → [calc_tag]
                                                      │
                                                      ▼
                                        定数時間比較 (consttime_eq)
                                          recv_tag vs calc_tag
                                                      │
                                     ┌────────────────┴────────────────┐
                                     ▼                                 ▼
                                  一致 → [OK]                    不一致 → [NG]
                              integrity verified            tampering detected
```
 
**役割分担**
 
| 層 | 役割 |
|---|---|
| TLS層(wolfSSL) | 通信経路そのものを暗号化・認証する |
| HMAC層(自作) | 受信したデータの中身自体が、送信者の意図通りかを検証する |
 
この2層構造で、多層防御(defense-in-depth)を実現しています。

## 動機

現在、大学の卒業研究で、機械学習データセットに対するデータポイズニング
攻撃への対策として、コンテンツをMinHashで指紋化し、Ed25519で署名し、
Merkleツリーで集約するという検証パイプラインを研究しています。

この研究を進める中で、「データの完全性を保証する」という考え方は、
データセットの検証だけでなく、ネットワーク越しの通信にも同じように
当てはまるのではないかと考えるようになりました。

TLSは通信経路そのものを暗号化・認証しますが、以下のようなケースでは
経路の保護だけでは不十分です。

- TLSを終端するプロキシやロードバランサを経由する構成
- 受信後にファイルとして保存し、後で別プロセスがそのデータを使う場合
  (その時点でTLSセッションはすでに終了している)

そこで、TLSによる経路保護と、アプリケーション層でのHMACによる
コンテンツ自体の完全性検証を組み合わせた、多層防御(defense-in-depth)の
構成を実際に手を動かして作ってみることにしました。

ライブラリを使うだけでなく、その土台となるハッシュ関数やHMACを
自分の手で実装することで、暗号プリミティブが実際にどう組み合わさって
安全性を作っているかを理解したいと考えています。

## 目標

- [x] SHA-256をゼロから実装し、既知のテストベクタで正しさを検証する
- [x] RFC 2104に基づくHMAC-SHA256を実装し、RFC 4231のテストベクタで検証する
- [x] wolfSSLを実際にビルド・リンクし、TLS 1.3でのハンドシェイクを行う
- [x] TLS通信の上に、自作HMACによるコンテンツ完全性検証を統合する
- [x] データが改ざんされた場合に検知できることを実際に確認する
- [x] GitHub Actionsで自動ビルド・自動テストを行うCIを整備する

## 進め方

各要素を単体で動作確認してから次に進む、という積み上げ方式で開発しています。

| 順番 | 要素 | 確認方法 |
|---|---|---|
| 1 | SHA-256 (`sha256.c`) | FIPS 180-4テストベクタと一致するか |
| 2 | HMAC-SHA256 (`hmac.c`) | RFC 4231テストベクタと一致するか |
| 3 | wolfSSLでのTLS疎通 | ハンドシェイクが成立し、cipher suiteが取得できるか |
| 4 | TLS + HMAC統合 | 正常系で `[OK] integrity verified`、改ざん時に `[NG] tampering detected` が出るか |
| 5 | CI (GitHub Actions) | pushのたびに上記すべてが自動実行されるか |

**方針**
- 前の要素が動作確認できてから、次の要素に進む(いきなり統合しない)
- 各ステップの実装・検証結果はコミット履歴としてそのまま残す(詳細は commit log を参照)

## sha256モジュール

`src/sha256.h` / `src/sha256.c` に、FIPS 180-4準拠のSHA-256を外部ライブラリなしで実装しています。

### ビルドとテスト

```bash
gcc -Wall -Wextra -std=c11 -o tests/test_sha256 tests/test_sha256.c src/sha256.c
./tests/test_sha256
```

FIPS 180-4のテストベクタ(空文字列、1ブロックのメッセージ、複数ブロックにまたがるメッセージ)と一致することを確認しています。

### 使い方

データを少しずつ渡したい場合(ストリーミング処理)は、`init` → `update` → `final`の順に呼び出します。

```c
#include "sha256.h"

sha256_ctx ctx;
uint8_t digest[SHA256_DIGEST_SIZE];

sha256_init(&ctx);
sha256_update(&ctx, chunk1, chunk1_len);
sha256_update(&ctx, chunk2, chunk2_len);   // 何回でも呼べる
sha256_final(&ctx, digest);
```

手元にデータが全部揃っている場合は、`sha256_buffer`で1回にまとめられます。

```c
uint8_t digest[SHA256_DIGEST_SIZE];
sha256_buffer(data, data_len, digest);
```

### 設計メモ

- 初期状態(`state[0..7]`)は最初の8個の素数の平方根、ラウンド定数(`K[0..63]`)は最初の64個の素数の立方根の、それぞれ小数部分から導出しています(規格通りの、恣意的な細工の余地がない値=nothing-up-my-sleeve numbers)
- `sha256_transform`はブロック単体の圧縮処理、`sha256_update`はそれを64バイトごとに呼び出すバッファリング層、という2層構造にしています

## hmacモジュール

`src/hmac.h` / `src/hmac.c` に、RFC 2104準拠のHMAC-SHA256を実装しています。
内部では前段で実装した`sha256モジュール`をそのまま利用しています。

### ビルドとテスト

```bash
gcc -Wall -Wextra -std=c11 -o tests/test_hmac tests/test_hmac.c src/hmac.c src/sha256.c
./tests/test_hmac
```

RFC 4231のテストベクタ(短い鍵、短いデータ、繰り返しデータ、ブロックサイズ(64バイト)より
長い鍵、の4パターン)と一致することを確認しています。特に「鍵が64バイトを超える場合は
SHA-256でハッシュ化してから使う」という分岐は、131バイトの鍵を使うテストケースで
明示的に検証しています。

### 使い方

```c
#include "hmac.h"

uint8_t out[HMAC_SHA256_SIZE];
hmac_sha256(key, key_len, data, data_len, out);
```

### TLSの上にHMACによる完全性検証を重ねる理由

TLSは通信経路そのものを暗号化・認証しますが、
以下のようなケースでは経路の保護だけでは不十分です。

- TLSを終端するプロキシやロードバランサを経由する構成
  (プロキシから先はTLSで保護されていない可能性がある)
- 受信後にファイルとして保存し、後で別プロセスがそのデータを使う場合
  (その時点でTLSセッションはすでに終了しており、保存されたファイル自体の
  完全性はTLSの保護対象外)

そこで、TLSによる経路保護に加えて、受信したデータ本体に対して
アプリケーション層でHMACによる完全性検証を行う、多層防御
(defense-in-depth)の構成にしています。イメージとしては、
```
TLS         : 「通信の途中で盗聴・改ざんされていないか」を保証する層
HMAC(本実装): 「受け取ったデータの中身が、送信者が意図した通りのものか」を保証する層
```
という役割分担です。TLSが「経路」を、HMACが「中身」を、それぞれ別の
観点から保証することで、片方が破られても(あるいは対象外のケースでも)
もう片方でカバーできるようにしています。

## wolfSSLのビルド

TLSクライアント/サーバー部分では、wolfSSLライブラリを実際にビルドして
静的リンクします。

### Step 0: autotoolsが必要

`./autogen.sh`は内部で`autoreconf`を使うため、autoconf/automake/libtoolが
インストールされている必要があります。未インストールの場合、以下のような
エラーになります。

```
./autogen.sh: line 52: autoreconf: command not found
```

OSに応じて事前にインストールしてください。

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y autoconf automake libtool make gcc

# macOS (Homebrew)
brew install autoconf automake libtool

# Fedora / RHEL
sudo dnf install -y autoconf automake libtool make gcc
```

### ビルド手順

```bash
git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --prefix=$PWD/../wolfssl-install --enable-static --disable-shared
make -j$(nproc)
make install
cd ..
```

成功すると、以下が生成されます。

- `wolfssl-install/include/`  … ヘッダファイル一式
- `wolfssl-install/lib/libwolfssl.a` … 静的ライブラリ

以降、TLSクライアント/サーバーをビルドする際は、`-I wolfssl-install/include`と
`wolfssl-install/lib/libwolfssl.a`をコンパイルコマンドに含めます。

wolfSSLのヘッダを使う際は、自分のソースファイルの一番最初
(他のwolfSSLヘッダより前)に以下を書く必要があります。

```c
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
```

### .gitignore

`wolfssl/`(クローンしたソース)と`wolfssl-install/`(ビルド成果物)は、
上記の手順を実行すれば誰でも再現できるため、リポジトリには含めません。

```
wolfssl/
wolfssl-install/
```

## デモ用証明書

`certs/server.crt` はデモ用の自己署名証明書です。対になる秘密鍵
(`certs/server.key`)は公開しないため、リポジトリには含めていません。
以下のコマンドで自分の環境用に生成してください。

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/server.key -out certs/server.crt -days 365 \
  -subj "/CN=localhost"
```

| オプション | 意味 |
|---|---|
| `-x509` | CAに送らず、自分自身で署名した証明書をその場で作る(自己署名) |
| `-newkey rsa:2048` | 2048bitのRSA鍵ペア(公開鍵・秘密鍵)を新規生成 |
| `-nodes` | 秘密鍵にパスワードを掛けない(デモ用。起動のたびの手入力を省略) |
| `-keyout` / `-out` | それぞれ秘密鍵・証明書の保存先 |
| `-days 365` | 証明書の有効期限(365日間) |
| `-subj "/CN=localhost"` | 証明書のSubject。`CN=localhost`のみ指定 |

`CN`(Common Name)は「この証明書がどのホスト向けか」を表す項目で、
TLSクライアントは接続先ホスト名と証明書のCN(またはSAN)が一致するかを
検証します。ローカルでの動作確認が目的のため、`CN=localhost`のみで
十分です(国・組織名などのその他のSubject項目は省略可能で、動作には
影響しません)。

## tlsモジュール(サーバー/クライアント)

`src/tls_server.c` / `src/tls_client.c` に、wolfSSLを使った最小構成の
TLSサーバー・クライアントを実装しています。この段階ではファイル送信や
HMACによる完全性検証はまだ行わず、**TLSハンドシェイクが成立することの
確認のみ**を目的としています。

### ビルド

```bash
WSSL=wolfssl-install

# Linux
gcc -Wall -Wextra -std=c11 -I$WSSL/include \
  -o src/tls_server src/tls_server.c $WSSL/lib/libwolfssl.a -lm
gcc -Wall -Wextra -std=c11 -I$WSSL/include \
  -o src/tls_client src/tls_client.c $WSSL/lib/libwolfssl.a -lm

# macOS (CoreFoundation/Securityフレームワークが追加で必要。後述)
gcc -Wall -Wextra -std=c11 -I$WSSL/include \
  -o src/tls_server src/tls_server.c $WSSL/lib/libwolfssl.a \
  -framework CoreFoundation -framework Security -lm
gcc -Wall -Wextra -std=c11 -I$WSSL/include \
  -o src/tls_client src/tls_client.c $WSSL/lib/libwolfssl.a \
  -framework CoreFoundation -framework Security -lm
```

### 実行

リポジトリのトップ(`certs/`と`src/`が両方見える階層)で実行します。

```bash
./src/tls_server &
./src/tls_client 127.0.0.1
```

正常に動作すると、サーバー・クライアント双方に以下のようなログが出ます。

```
[server] TLSハンドシェイク完了 (cipher: TLS_AES_256_GCM_SHA384)
[client] TLSハンドシェイク完了 (cipher: TLS_AES_256_GCM_SHA384)
```

### トラブルシューティング

#### `autoreconf: command not found`

`./autogen.sh`の実行に必要なautotools(autoconf/automake/libtool)が
インストールされていません。「wolfSSLのビルド」セクションの
「前提: autotoolsが必要」を参照してください。

#### macOSでのリンクエラー(`_CFArrayAppendValue`など)

```
Undefined symbols for architecture arm64:
  "_CFArrayAppendValue", referenced from: ...
  "_SecCertificateCopyData", referenced from: ...
ld: symbol(s) not found for architecture arm64
```

macOS版のwolfSSLは、証明書検証にmacOS標準のCoreFoundation/Securityフレームワーク
(Keychainなど)を利用するコードを含んでいます。ビルドコマンドに
`-framework CoreFoundation -framework Security` を追加することで解決します
(上記の「ビルド」セクションのmacOS向けコマンドを参照)。Linux環境では不要です。

#### `CA証明書の読み込みに失敗しました` / `証明書/鍵の読み込みに失敗しました`

原因は主に2つ考えられます。

1. **証明書ファイルの拡張子違い**:コードは`certs/server.crt`(`.crt`)を
   探しています。`.cert`など別の拡張子で生成していないか確認してください。
2. **秘密鍵が存在しない**:`certs/server.key`は`.gitignore`対象のためリポジトリに
   含まれていません。「デモ用証明書」セクションのコマンドで自分の環境用に
   生成してください。
3. **実行場所が違う**:相対パス`"certs/server.crt"`はプログラムを実行した場所
   からの相対パスとして解釈されます。`src/`フォルダの中などから実行すると
   見つかりません。リポジトリのトップで実行してください。

   ### HMAC共有鍵

`certs/hmac.key` はサーバー・クライアント間で共有するHMAC用の鍵です。
`certs/server.key`と同様、リポジトリには含めていません。以下のコマンドで
生成してください。

```bash
openssl rand -out certs/hmac.key 32
```

## 動作確認結果
 
### 正常系
 
```
$ ./src/tls_server payload.txt &
$ ./src/tls_client 127.0.0.1
[client] TLSハンドシェイク完了 (cipher: TLS_AES_256_GCM_SHA384)
[client] 29 bytes受信、HMAC検証を実行します
[OK] integrity verified — データは改ざんされていません
```
 
### 改ざん検知
 
```
$ ./src/tls_server payload.txt tamper &
$ ./src/tls_client 127.0.0.1
[client] TLSハンドシェイク完了 (cipher: TLS_AES_256_GCM_SHA384)
[client] 29 bytes受信、HMAC検証を実行します
[NG] tampering detected — データが改ざんされています
```
### CI
 
GitHub Actions上で、上記の正常系・改ざん系を含む全テスト(SHA-256単体テスト、HMAC単体テスト、鍵読み込みテスト、TLS統合テスト)を自動実行し、pushのたびに検証しています。
