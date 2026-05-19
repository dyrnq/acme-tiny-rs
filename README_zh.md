# acme-tiny-rs

Rust 重写 [acme-tiny](https://github.com/diafygi/acme-tiny)，兼容全部 CLI 参数和 ACME 流程。

## 与 acme-tiny 的关系

`acme-tiny-rs` 是 `acme-tiny`（Python）的功能等价 Rust 实现：

| 方面     | acme-tiny (Python)                      | acme-tiny-rs (Rust)                                |
| :------- | :-------------------------------------- | :------------------------------------------------- |
| 语言     | Python 2/3                              | Rust                                               |
| 依赖     | Python + OpenSSL CLI                    | 零系统依赖（静态链接）                             |
| 启动开销 | ~50ms 解释器启动                        | < 1ms                                              |
| 体积     | 依赖 Python 运行时                      | ~2.7MB 单文件                                      |
| 密钥解析 | `openssl rsa` / `openssl req` 子进程    | 纯 Rust (`rsa` / `p256` / `p384` / `x509-parser`)  |
| HTTP/TLS | `urllib` + 系统 CA                      | `reqwest` + `rustls`（内置根证书）                 |
| 跨平台   | 需安装 Python + OpenSSL                 | 单二进制，无运行时依赖                             |

## 优势

- **单文件部署**：`scp` 一个二进制到服务器即可，不需要 Python/OpenSSL
- **密钥类型**：RSA + ECDSA P-256/P-384 + Ed25519 账户密钥（PEM 自动识别）
  - **⚠️ Let's Encrypt 不支持 Ed25519 和 IP 证书** — Ed25519 仅可用于账户密钥。域名密钥须使用 RSA 或 ECDSA。IP 证书需支持 RFC 8738 的 CA
- **验证方式**：http-01、dns-01、tls-alpn-01、dns-persist-01、dns-account-01
- **DNS 服务商**：Cloudflare、阿里云、腾讯云、AWS Route53、Azure、GoDaddy、Google Cloud、DigitalOcean、OVH 等
- **Standalone 模式**：内置 HTTP 服务器（`--standalone`）和 TLS-ALPN 服务器（`--challenge-type tls-alpn-01`）
- **Hooks**：兼容 acme.sh 的 pre/post/renew/deploy/notify 钩子
- **子命令**：`revoke`、`inspect`、`dump`、`ari`、`version`
- **DNS CNAME 委托**：自动跟随 `_acme-challenge` CNAME 链（无需手动指定 `--challenge-alias`）
- **ARI 续期（RFC 9773）**：`--ari` + `--cert` 实现 CA 调度的智能续期；`ari` 子命令用于手动检查
- **ACME Profiles**：`-P`/`--profile` 选择证书类型（classic、shortlived、tlsserver）
- **静态链接**：`x86_64-unknown-linux-musl` 构建不依赖任何 `.so`，可在任意 Linux 内核上运行

## 安装

### 预编译二进制

从 [Releases](https://github.com/dyrnq/acme-tiny-rs/releases) 下载对应平台的二进制：

```sh
VER=$(curl -s https://api.github.com/repos/dyrnq/acme-tiny-rs/releases/latest | grep tag_name | cut -d'"' -f4) && \
curl -L -o acme-tiny-rs "https://github.com/dyrnq/acme-tiny-rs/releases/download/${VER}/acme-tiny-rs-${VER}-x86_64-unknown-linux-musl"
chmod +x acme-tiny-rs
```

### 从源码编译

```sh
git clone https://github.com/dyrnq/acme-tiny-rs.git
cd acme-tiny-rs
cargo build --release
# 二进制在 ./target/release/acme-tiny-rs
```

静态链接构建 (musl):

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## 使用

### 1. 创建 Let's Encrypt 账户私钥

```sh
# RSA
openssl genrsa 4096 > account.key

# ECDSA P-256
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 > account.key

# ECDSA P-384
openssl ecparam -genkey -name secp384r1 > account.key
```

### 2. 创建 CSR

```sh
# 生成域名私钥
openssl genrsa 4096 > domain.key

# 单域名
openssl req -new -sha256 -key domain.key -subj "/CN=yoursite.com" > domain.csr

# 多域名
openssl req -new -sha256 -key domain.key -subj "/" \
    -addext "subjectAltName = DNS:yoursite.com, DNS:www.yoursite.com" > domain.csr

# 多域名 (openssl < 1.1.1)
openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN \
    -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com")) \
    > domain.csr
```

### 3. 配置 challenge 目录

```sh
mkdir -p /var/www/challenges/
```

```nginx
# nginx 示例
server {
    listen 80;
    server_name yoursite.com www.yoursite.com;

    location /.well-known/acme-challenge/ {
        alias /var/www/challenges/;
        try_files $uri =404;
    }
}
```

### 4. 签发证书

```sh
acme-tiny-rs \
    --account-key ./account.key \
    --csr ./domain.csr \
    --acme-dir /var/www/challenges/ \
    > signed_chain.crt
```

测试环境 (staging):

```sh
# 使用预设名称
acme-tiny-rs \
    --server letsencrypt-staging \
    --account-key ./account.key \
    --csr ./domain.csr \
    --acme-dir /var/www/challenges/ \
    > signed_chain.crt

# 或直接使用完整 URL
acme-tiny-rs \
    --directory-url https://acme-staging-v02.api.letsencrypt.org/directory \
    --account-key ./account.key \
    --csr ./domain.csr \
    --acme-dir /var/www/challenges/ \
    > signed_chain.crt
```

查看所有可用的 CA 预设:

```sh
acme-tiny-rs --list-ca
```

### 5. 安装证书

```nginx
server {
    listen 443 ssl;
    server_name yoursite.com www.yoursite.com;

    ssl_certificate /path/to/signed_chain.crt;
    ssl_certificate_key /path/to/domain.key;
}
```

### 6. 自动续期 cron

```sh
#!/bin/sh
# renew_cert.sh
acme-tiny-rs \
    --account-key /path/to/account.key \
    --csr /path/to/domain.csr \
    --acme-dir /var/www/challenges/ \
    > /path/to/signed_chain.crt.tmp \
    || exit
mv /path/to/signed_chain.crt.tmp /path/to/signed_chain.crt
service nginx reload
```

```sh
# crontab (每月执行一次)
0 0 1 * * /path/to/renew_cert.sh 2>> /var/log/acme_tiny.log
```

## CLI 参数

```
--account-key <PATH>       账户私钥路径（RSA、ECDSA P-256/P-384、Ed25519）
--csr <PATH>               CSR 文件路径
--acme-dir <PATH>          .well-known/acme-challenge/ 目录路径（http-01）
--quiet                    仅输出错误
--disable-check            跳过 challenge 文件自检（http-01）
--directory-url <URL>      CA directory URL (overrides --server)
--server <NAME|URL>        CA server preset name or URL [default: letsencrypt]
                           Presets: letsencrypt, letsencrypt-staging, zerossl,
                           buypass, sslcom, google, step, pebble, pebble-eab
--ca <URL>                 DEPRECATED, use --server or --directory-url instead
--contact <CONTACT>...     账户联系方式（如 mailto:admin@example.com）
--check-port <PORT>        自检时使用的端口 [默认: 80]
--challenge-type <TYPE>    http-01（默认）、dns-01、tls-alpn-01、dns-persist-01、dns-account-01
--dns-provider <NAME>      DNS 提供商名称 [默认: manual]
--standalone               使用内置 HTTP 服务器（端口 80），不写磁盘文件
--agree-tos                同意 CA 服务条款 [默认: true]
--eab-kid <KID>            EAB Key Identifier（需要 EAB 的 CA）
--eab-hmac-key <KEY>       EAB HMAC Key（base64url 编码）
--output, -o <PATH>        将证书输出到文件（默认 stdout）
--pre-hook <CMD>           证书签发前执行的命令/脚本
--post-hook <CMD>          签发后执行（无论成败）
--renew-hook <CMD>         续期成功后执行
--deploy-hook <CMD>        证书签发后部署命令/脚本
--notify-hook <CMD>        通知命令/脚本
--ca-bundle <PATH>         额外 CA 证书包路径

子命令：
  version                   输出版本号、git hash、编译时间
  ari --cert <PATH>         查询 ARI 续期信息（RFC 9773），输出 JSON
  revoke --cert <PATH>      吊销证书（RFC 8555 §7.6）
  inspect -d <DOMAIN>       检查 TLS 证书信息（表格或 --json）
  dump <DOMAIN>             导出 TLS 证书链
  list-ca                   列出已知 CA 预设（--json、--no-header）
  inspect-ca --server <ID>  获取并格式化 CA 目录 JSON
  thumbprint --account-key  输出 JWK 指纹（RFC 7638）
```

详情见 [ARI.md](ARI.md) 了解 ARI 续期、[DNS.md](DNS.md) 了解 DNS 提供商、[EAB.md](EAB.md) 了解外部账户绑定。

## License

MIT — 与 acme-tiny 保持一致.
