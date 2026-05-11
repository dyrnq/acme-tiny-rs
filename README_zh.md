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
- **密钥类型**：支持 RSA + ECDSA P-256/P-384 账户密钥（自动检测 PEM 格式）
- **静态链接**：`x86_64-unknown-linux-musl` 构建不依赖任何 `.so`，可在任意 Linux 内核上运行
- **Drop-in 兼容**：CLI 参数与 `acme-tiny` 完全一致

## 安装

### 预编译二进制

从 [Releases](https://github.com/dyrnq/acme-tiny-rs/releases) 下载对应平台的二进制：

```sh
curl -L -o acme-tiny-rs https://github.com/dyrnq/acme-tiny-rs/releases/latest/download/acme-tiny-rs-x86_64-unknown-linux-musl
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
acme-tiny-rs \
    --account-key ./account.key \
    --csr ./domain.csr \
    --acme-dir /var/www/challenges/ \
    --directory-url https://acme-staging-v02.api.letsencrypt.org/directory \
    > signed_chain.crt
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
--account-key <PATH>       账户私钥路径（RSA 或 ECDSA P-256/P-384）
--csr <PATH>               CSR 文件路径
--acme-dir <PATH>          .well-known/acme-challenge/ 目录路径
--quiet                    仅输出错误
--disable-check            跳过 challenge 文件自检
--directory-url <URL>      CA directory URL [默认: Let's Encrypt 生产环境]
--ca <URL>                 已废弃，请使用 --directory-url
--contact <CONTACT>...     账户联系方式（如 mailto:admin@example.com）
--check-port <PORT>        自检时使用的端口 [默认: 80]
```

## License

MIT — 与 acme-tiny 保持一致.
