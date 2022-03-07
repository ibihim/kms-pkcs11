# intermediate-kms

Encrypts data with individual keys (128 bit) with AES GCM. The "main key" needs
to be encrypted. The options should be a KMS-provider, a PKCS #11 HMS or a
passphrase.

## Why

The goal is to **call a KMS-provider once** and spawn sub-keys. As every call to
a KMS-provider generates costs. The costs could be monetary or by running into
throttling.

## Details

```mermaid
graph TD
    rk[root key] --> KEK
    KEK --> DEK_1
    KEK --> DEK_2
    KEK --> DEK_n
```

Data is encrypted with an individual key, called data encryption key (DEK). The
DEKs are encrypted with a key encryption key (KEK). The KEK is encrypted with a
root key that comes from the KMS-provider, HMS or passphrase.

The encrypted DEK is stored alongside the encrypted data.

The encrypted KEK is stored is stored, where configured.

### Encryption

The encryption algorithm is AES, in GCM mode with a 128 bit key.

The KEK rotates when necessary automatically to keep the data safe.

