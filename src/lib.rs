// SPDX-License-Identifier: MIT

//! An implementation of the crypographic random number generator
//! CTR_DRBG as defined by NIST [SP 800-90A
//! Rev. 1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final).
//!
//! CTR_DRBG is a Cryptographically Secure Pseudorandom Number
//! Generator (CSPRNG) that may be used for generating sensitive data
//! such as encryption keys. The implementation uses the AES-256 block
//! cipher and derivation function to generate random bytes.
//!
//! # Quick Example
//!
//! A simple way to obtain crypographic random random data is to use
//! the
//! [`LocalCtrDrbg::default()`](crate::thread::LocalCtrDrbg::default())
//! function. This returns a handle to a thread-local instance of
//! [`CtrDrbg`](ctr::CtrDrbg) pre-allocated to use entropy supplied by
//! the OS. The `std` feature is required for this approach.
//!
//! ```
//! # #[cfg(feature = "std")]
//! use drbg::thread::LocalCtrDrbg;
//!
//! # use drbg::entropy::Error;
//! #
//! # fn main() -> Result<(),Error> {
//! #
//! # #[cfg(feature = "std")]
//! let drbg = LocalCtrDrbg::default();
//! let mut random_data = [0u8; 32];
//! # #[cfg(feature = "std")]
//! drbg.fill_bytes(&mut random_data, None)?;
//! #
//! # Ok(())
//! # }
//! ```
//!
//! Otherwise an instance may be constructed by hand using the
//! [`CtrBuilder`](ctr::CtrBuilder) class. This approach doesn't
//! require the `std` feature. It also allows the caller to configure
//! the instance with different input parameters.
//!
//!
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod ctr;
pub mod entropy;

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod thread;
