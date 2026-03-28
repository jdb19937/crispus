# crispus

**A modern, zero-dependency HTTPS client library for C.**

## Why crispus?

In today's software landscape, making a simple HTTPS request from a C application shouldn't require pulling in a sprawling dependency tree. Yet for decades, that's exactly what developers have accepted — linking against massive libraries with hundreds of thousands of lines of code, complex build systems, and transitive dependencies that cascade through your project like uninvited guests at a dinner party.

crispus takes a fundamentally different approach. Every single byte of functionality — from the cryptographic primitives to the TLS handshake to the HTTP protocol handling — is implemented from scratch in clean, readable C. There is no OpenSSL. There is no libcurl. There is no nghttp2, no zlib, no libidn. There is only crispus, your C compiler, and a POSIX libc. That's it.

This means your builds are fast, your binaries are small, your supply chain is auditable in an afternoon, and your deployment story is as simple as copying a single static archive.

## What it does

crispus provides a straightforward interface for making HTTPS requests. You set a URL, optionally configure headers and POST data, and execute the request. You get back a response code and the body. It supports both a simple single-request interface for common use cases and a multiplexed interface that can execute many requests concurrently.

The library handles TLS 1.2 negotiation transparently. Your application never needs to think about cipher suites, certificate parsing, key exchange, or record layer framing. You point it at a URL and it does the right thing.

## Who should use crispus?

crispus is purpose-built for environments where minimizing external dependencies is not a preference but a requirement.

**Embedded systems and firmware.** When you're building for a constrained target where cross-compiling OpenSSL is a week-long ordeal, crispus compiles cleanly with any C11 compiler and produces a static archive you can link directly into your firmware image. If your device needs to phone home, pull configuration from an API, or post telemetry to a collection endpoint, crispus gives you that capability without the baggage.

**Security-critical and auditable systems.** If your organization requires full source auditing of every dependency — common in defense, aerospace, medical devices, and financial infrastructure — crispus is small enough that a single engineer can read and understand the entire implementation. There are no layers of abstraction hiding behind layers of abstraction. The code that runs is the code you read.

**Minimal containers and static binaries.** If you're building statically-linked microservices or tools destined for `scratch` or `distroless` container images, crispus eliminates the need to bundle shared libraries for TLS. Your binary is your binary. Nothing else required.

**Build system simplicity.** crispus builds with make. Not CMake, not Meson, not Autotools, not Bazel. A single Makefile produces the library. Integration into your existing project is a matter of adding a few source files or linking against the archive. There is no `./configure` step. There is no pkg-config file to chase down. There is no Find module to write.

**Rapid prototyping and education.** If you're learning how HTTPS actually works — not at the API level, but at the level of TLS record framing, ECDHE key exchange, and AES-GCM authenticated encryption — crispus is one of the most approachable implementations in existence. Every function is named for what it does. The code reads top to bottom. There are no callbacks dispatching through five layers of indirection.

## Getting started

Building the library requires only a C compiler and make:

```
make
```

This produces `libcrispus.a`, a static archive you can link into your application. To clean build artifacts:

```
make clean
```

A test suite is included and can be built and run with:

```
make test
./test
```

Linking against crispus in your own project is straightforward:

```
cc -o myapp myapp.c -L/path/to/crispus -lcrispus
```

## A note on scope

crispus is not a replacement for every use of libcurl in every project. It implements the subset of HTTPS functionality that covers the overwhelming majority of real-world API client use cases: GET and POST over TLS 1.2 with modern cipher suites. If you need HTTP/2, SOCKS proxies, FTP, or client certificate authentication, you need a different tool.

What crispus offers is the freedom to make HTTPS requests from C without signing up for a dependency graph. For a surprising number of applications, that's exactly enough.

## License

Public domain.
