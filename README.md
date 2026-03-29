# crispus

**A modern, zero-dependency HTTPS client library for C.**

## Why crispus?

In today's software landscape, making a simple HTTPS request from a C application shouldn't require pulling in a sprawling dependency tree. Yet for decades, that's exactly what developers have accepted — linking against massive libraries with hundreds of thousands of lines of code, complex build systems, and transitive dependencies that cascade through your project like uninvited guests at a dinner party.

crispus takes a fundamentally different approach. Every single byte of functionality — from the cryptographic primitives to the TLS handshake to the HTTP protocol handling — is implemented from scratch in clean, readable C. There is no OpenSSL. There is no libcurl. There is no nghttp2, no zlib, no libidn. There is only crispus, your C compiler, and a POSIX libc. That's it.

This means your builds are fast, your binaries are small, your supply chain is auditable in an afternoon, and your deployment story is as simple as copying a single static archive.

## What It Does

crispus provides a straightforward interface for making HTTPS requests. You set a URL, optionally configure headers and POST data, and execute the request. You get back a response code and the body. It supports both a simple single-request interface for common use cases and a multiplexed interface that can execute many requests concurrently.

The library handles TLS 1.2 negotiation transparently. Your application never needs to think about cipher suites, certificate parsing, key exchange, or record layer framing. You point it at a URL and it does the right thing.

## Who should use crispus?

crispus is purpose-built for environments where minimizing external dependencies is not a preference but a requirement.

**Embedded systems and firmware.** When you're building for a constrained target where cross-compiling OpenSSL is a week-long ordeal, crispus compiles cleanly with any C11 compiler and produces a static archive you can link directly into your firmware image. If your device needs to phone home, pull configuration from an API, or post telemetry to a collection endpoint, crispus gives you that capability without the baggage.

**Security-critical and auditable systems.** If your organization requires full source auditing of every dependency — common in defense, aerospace, medical devices, and financial infrastructure — crispus is small enough that a single engineer can read and understand the entire implementation. There are no layers of abstraction hiding behind layers of abstraction. The code that runs is the code you read.

**Minimal containers and static binaries.** If you're building statically-linked microservices or tools destined for `scratch` or `distroless` container images, crispus eliminates the need to bundle shared libraries for TLS. Your binary is your binary. Nothing else required.

**Build system simplicity.** crispus builds with make. Not CMake, not Meson, not Autotools, not Bazel. A single Makefile produces the library. Integration into your existing project is a matter of adding a few source files or linking against the archive. There is no `./configure` step. There is no pkg-config file to chase down. There is no Find module to write.

**Rapid prototyping and education.** If you're learning how HTTPS actually works — not at the API level, but at the level of TLS record framing, ECDHE key exchange, and AES-GCM authenticated encryption — crispus is one of the most approachable implementations in existence. Every function is named for what it does. The code reads top to bottom. There are no callbacks dispatching through five layers of indirection.

## Getting Started

Building the library requires only a C compiler and make:

```bash
make
```

This produces `libcrispus.a` and `crispe`, a curl-like command line tool that demonstrates the library. To clean build artifacts:

```bash
make purga
```

A test suite is included and can be built and run with:

```bash
make proba
./proba
```

Linking against crispus in your own project is straightforward:

```bash
cc -o myapp myapp.c -L/path/to/crispus -lcrispus
```

## crispe

crispe is a command line HTTP client built entirely on libcrispus. It exists for the same reason the library does: because sometimes you want to fetch a URL from a machine that has nothing on it but a C compiler, and you'd rather not install curl and its transitive dependency graph just to pull down a configuration file or poke an API endpoint.

Every byte that leaves your machine when you run crispe was constructed by code you can read in this repository. The TLS handshake, the key exchange, the symmetric encryption, the HTTP framing — all of it flows through the same compact, auditable implementation that libcrispus provides. There is no shelling out to OpenSSL. There is no dynamically linked libcurl hiding behind a convenient interface. When crispe opens a socket and negotiates a TLS 1.2 session, it does so using the cryptographic primitives defined right here in the source tree: ECDHE over P-256 for key agreement, RSA for server authentication, AES-128-GCM for confidentiality and integrity, SHA-256 for hashing. If you want to know exactly what your tool is doing on the wire, you can read it in an afternoon.

crispe is deliberately minimal. It does not attempt to replicate the full surface area of curl — that would defeat the purpose. Instead, it covers the operations that matter for the vast majority of scripting and automation tasks: fetching pages, posting data to APIs, setting custom headers, and saving responses to disk. If you need multipart form uploads, cookie jars, or HTTP/2 multiplexing, you need a bigger tool. If you need to hit an HTTPS endpoint and get the response, crispe does that with zero external dependencies and a binary small enough to embed in a firmware image.

The verbose mode is particularly useful for debugging and education. It prints the outgoing request method, URL, headers, and POST body to stderr, followed by the response code and body size, giving you a clear picture of exactly what happened on the wire without needing to reach for a packet capture tool.

```text
./crispe [options] <url>

  -s            silent mode (suppress error messages)
  -v            verbose mode (show request and response details)
  -d <data>     request body (implies POST)
  -H <header>   add HTTP header (repeatable)
  -o <file>     write response to file
  -X <method>   HTTP method (GET, POST)
  -t <seconds>  timeout
  -h            help
```

Examples:

```bash
./crispe https://www.fordcountychronicle.com/articles/featured/naked-gunman-70-still-not-located/
./crispe -o page.html https://www.fordcountychronicle.com/articles/featured/naked-gunman-70-still-not-located/
```

## The Rust Port

crispus is also available as a complete, from-scratch Rust port, located in the `cancer/` directory. This is not a wrapper, not a binding, and not a partial sketch — it is a full, faithful, line-by-line translation of every module in the C library into idiomatic, safe Rust. Every cryptographic primitive, every protocol state machine, every byte of the TLS handshake has been carried over with the same care and attention to correctness that went into the original.

The Rust port achieves **complete feature parity** with the C implementation. The SHA-256 and HMAC-SHA-256 produce identical digests. The AES-128-GCM encryption and decryption pass the same NIST test vectors. The bignum arithmetic, the elliptic curve operations over P-256, the RSA signature verification, the ASN.1 certificate parsing, the TLS 1.2 handshake, the HTTP request framing, the chunked transfer-encoding decoder, the multi-request interface — all of it is there, all of it works, and all of it has been verified against the same test suite that validates the C library, including live HTTPS connections to real-world servers.

Like its C counterpart, the Rust port has **zero external dependencies**. No openssl-sys, no rustls, no ring, no hyper, no tokio, no reqwest. The only thing it links against is the Rust standard library. `cargo build` produces a static library and two binaries — `crispe` (the command-line HTTPS client) and `proba` (the test suite) — with nothing else required. If you can run `rustc`, you can build it.

The Rust port is actively maintained and is the recommended implementation for new projects. It benefits from Rust's memory safety guarantees, its expressive type system, and its tooling ecosystem — `cargo test` runs the full cryptographic and protocol test suite out of the box, with network-dependent HTTPS tests available via `cargo test -- --ignored`.

```bash
cd cancer
cargo build
cargo test
cargo test -- --ignored   # HTTPS tests (requires network)
cargo run --bin crispe -- https://example.com/
```

## A Note on Scope

crispus is not a replacement for every use of libcurl in every project. It implements the subset of HTTPS functionality that covers the overwhelming majority of real-world API client use cases: GET and POST over TLS 1.2 with modern cipher suites. If you need HTTP/2, SOCKS proxies, FTP, or client certificate authentication, you need a different tool.

What crispus offers is the freedom to make HTTPS requests from C without signing up for a dependency graph. For a surprising number of applications, that's exactly enough.

## License

Public domain.
