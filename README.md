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
create a CSPRNG that is secure by default, lightweight, and easy to
use.

## Performance

The performance of `CTR_DRBG` is dominated by AES encryption
operations. Platforms that have AES instruction sets (e.g., AES-NI)
should see significant performance gains. Passing additional info to
the `fill_bytes` function does incur additional overhead as the info
is input to the AES derivation function.

### Benchmarks

The following benchmark measurements where taken on an Intel Ultra 5
225H using AES-NI.

The measurements below are the average latency for reading random
data. The sizes 16 and 32 bytes are used because they are typical for
generating symmetric encryption keys. The 1 MiB test represents
collecting bulk random data.

The first set of measurements are taken without passing *additional
info* to `fill_bytes`. While the second set of measurements are taken
with 8 bytes of *additional info* to the call. *Additional info* is an
optional parameter that adds additional input to the random number
generation process. However, the info is passed through a derivation
function that maps the info to an AES-block-sized message
digest. Computing the digest does add additional overhead, but it is a
one-time cost per call of `fill_bytes`.

#### Without additional info

|Random Data |Latency           |
|------------|------------------|
|16 (bytes)  |118 (ns)          |
|32 (bytes)  |133 (ns)          |
|1  (MiB)    |996 (µs) ~1 GiB/s |

#### With 8 bytes of additional info

|Random Data |Latency           |
|------------|------------------|
|16 (bytes)  |483 (ns)          |
|32 (bytes)  |500 (ns)          |
|1  (MiB)    |  1 (ms) ~1 GiB/s |

Overall the performance of this implementation of `CTR_DRBG` should be
sufficient for most use-cases. Although passing additional info has a
performance implications, it is an optional parameter. For bulk random
data, the overhead of additional data is marginal compared to the
random number generation process.

To run the above benchmarks run the following command. Depending on
your environment, you may need to force enablement of AES-NI. See the
[aes](https://crates.io/crates/aes) crate for more details.

```bash
cargo bench
```
