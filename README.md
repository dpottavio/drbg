# DRBG
Rust implementation of the secure random number generator `CTR_DRBG` as
defined by NIST [800-90A Rev.1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final).

[![crates-badge][crates-badge]][crates-url]
[![docs-badge][docs-badge]][docs-url]
[![mit-badge][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/crates/v/drbg
[crates-url]: https://crates.io/crates/drbg
[docs-badge]: https://docs.rs/drbg/badge.svg
[docs-url]: https://docs.rs/drbg
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/dpottavio/drbg/blob/main/LICENSE

`CTR_DRBG` is a cryptography secure pseudo-random number generator
(CSPRNG) based on the AES block cipher. It may be used to generate
encryption keys, nonces, or salts. By default, it is seeded with
entropy from the operating system, but other entropy sources may be
defined using the `Entropy` trait. The goal of this package is to
create a CSPRNG that is secure by default, lightweight, and easy to use.
