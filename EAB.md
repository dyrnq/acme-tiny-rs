# External Account Binding (EAB)

Some Certificate Authorities require **External Account Binding** (RFC 8555 §7.3.4) — proof that you have an existing relationship with the CA before creating an ACME account. EAB is needed **only once**, at first registration. Renewals use the already-bound ACME account.

## Do I need EAB?

| CA            | EAB Required? | `--directory-url`                                |
| ------------- | ------------- | ------------------------------------------------ |
| Let's Encrypt | ❌ No         | `https://acme-v02.api.letsencrypt.org/directory` |
| ZeroSSL       | ✅ Yes        | `https://acme.zerossl.com/v2/DV90`               |
| Google Trust  | ✅ Yes        | `https://dv.acme-v02.api.pki.goog/directory`     |
| Buypass       | ✅ Yes        | `https://api.buypass.com/acme/directory`         |
| SSL.com       | ✅ Yes        | `https://acme.ssl.com/sslcom-dv-rsa`             |

## Step 1: Get EAB credentials from your CA

Log in to your CA's management console and generate ACME EAB credentials:

- **ZeroSSL**: [Dashboard → Developer → Generate](https://app.zerossl.com/developer)
- **Google Trust**: [Google Cloud Console → Certificate Manager](https://console.cloud.google.com/security/certificate-manager)
- **Buypass**: [Buypass ACME Dashboard](https://api.buypass.com/)
- **SSL.com**: [SSL.com ACME Dashboard](https://account.ssl.com/)

You will receive two values:

```
EAB KID:       abc123...       # Key Identifier
EAB HMAC Key:  dGhpcyBpcyBh... # base64url-encoded HMAC key
```

## Step 2: Generate an ACME account key

```sh
# RSA (recommended)
openssl genrsa 4096 > account.key

# ECDSA P-256
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 > account.key

# ECDSA P-384
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 > account.key
```

## Step 3: First registration with EAB

```sh
acme-tiny-rs \
    --account-key account.key \
    --csr domain.csr \
    --acme-dir /var/www/challenges/ \
    --directory-url https://acme.zerossl.com/v2/DV90 \
    --eab-kid "abc123..." \
    --eab-hmac-key "dGhpcyBpcyBh..."
```

## Step 4: Renewals (no EAB needed)

After the first registration, your ACME account is bound to the CA. Subsequent renewals do **not** need EAB:

```sh
acme-tiny-rs \
    --account-key account.key \
    --csr domain.csr \
    --acme-dir /var/www/challenges/ \
    --directory-url https://acme.zerossl.com/v2/DV90
```

## How EAB works

```
1. CA issues you: kid + HMAC key (one-time use)
2. Client computes EAB-JWS:
   protected = {"alg":"HS256", "kid": kid, "url": newAccountUrl}
   payload   = base64url(jwk of account key)
   signature = HMAC-SHA256(HMAC-key, protected.payload)

3. Client includes externalAccountBinding in newAccount request
4. CA verifies the HMAC → binds external account → returns ACME account
```

Your `account.key` signs all subsequent ACME protocol requests (JWS RS256/ES256/ES384). The EAB HMAC key is used **only once** during registration and never needed again.

## CLI Reference

```
--eab-kid <KID>           EAB Key Identifier from CA
--eab-hmac-key <KEY>      EAB HMAC Key from CA (base64url-encoded)
--directory-url <URL>     CA directory URL
```