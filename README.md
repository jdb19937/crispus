# crispus

**A full TLS 1.2 HTTPS client in under 3,700 lines of C, with every cryptographic primitive implemented from scratch. SHA-256. HMAC. AES-128-GCM. ECDHE over P-256. RSA. X.509. Zero external dependencies.**

## Why crispus Exists

Every other HTTP client in the C ecosystem depends on OpenSSL, or libcurl, or both — hundreds of thousands of lines of code written by other people, carrying decades of accumulated CVEs, configuration complexity, and build system archaeology. You link against them, you hope they work, and you pray that the next vulnerability disclosure doesn't have your name on it.

crispus takes a different position: if you understand the RFC, you can implement the RFC. Every byte of the TLS handshake, every field of the X.509 certificate, every round of AES, every point multiplication on the P-256 curve — all of it is right here, in readable C, with no external dependencies beyond libc and POSIX sockets. You can audit the entire cryptographic stack during a lunch break.

## Cryptographic Suite

| Primitive | Implementation |
|---|---|
| **SHA-256** | Full implementation, HMAC-SHA-256 |
| **AES-128-GCM** | Encrypt and decrypt with authenticated encryption |
| **ECDHE P-256** | Elliptic curve Diffie-Hellman with custom bignum arithmetic |
| **RSA** | Signature verification for certificate chain validation |
| **X.509 / ASN.1** | Certificate parsing, chain validation, hostname matching |
| **TLS 1.2** | Full handshake: `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` |

## Building

```bash
make omnia
```

## Usage

```c
#include "crispus.h"

crispus_orbis_initia(CRISPUS_GLOBAL_DEFAULT);

CRISPUS *c = crispus_facilis_initia();
crispus_facilis_pone(c, CRISPUSOPT_URL, "https://example.com/api");
crispus_facilis_pone(c, CRISPUSOPT_FUNCTIO_SCRIBENDI, mea_functio);
crispus_facilis_pone(c, CRISPUSOPT_DATA_SCRIBENDI, &mea_data);
crispus_facilis_pone(c, CRISPUSOPT_TEMPUS, 30L);

CRISPUScode rc = crispus_facilis_age(c);

long codex;
crispus_facilis_info(c, CRISPUSINFO_CODEX_RESPONSI, &codex);

crispus_facilis_fini(c);
crispus_orbis_fini();
```

## Parallel Requests

The multi-handle interface runs requests in parallel using `fork()` and `pipe()` — pure POSIX concurrency with no threads, no event loops, no external concurrency libraries:

```c
CRISPUSM *m = crispus_multi_initia();
crispus_multi_adde(m, c1);
crispus_multi_adde(m, c2);

int currentes;
do {
    crispus_multi_age(m, &currentes);
    CRISPUSMsg *msg;
    int residua;
    while ((msg = crispus_multi_lege(m, &residua)) != NULL) {
        /* msg->easy_handle, msg->data.result */
    }
} while (currentes > 0);

crispus_multi_fini(m);
```

## crispe — Command Line Tool

A fully featured HTTPS command line client built on libcrispus:

```bash
./crispe https://example.com
./crispe -v -H "Authorization: Bearer TOKEN" https://api.example.com/data
./crispe -d '{"key":"value"}' -H "Content-Type: application/json" https://api.example.com
./crispe -s -o output.html https://example.com/page
```

## The Rust Port

A complete, faithful Rust translation lives in `cancer/`. Zero external dependencies. Full API parity with the C implementation, including the entire cryptographic stack.

## License

Free. Public domain. Use however you like.
