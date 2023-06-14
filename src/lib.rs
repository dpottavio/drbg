//
// Copyright (c) 2023 Daniel Ottavio
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE
//
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
//! the [`LocalCtrDrbg::default()`](crate::thread::LocalCtrDrbg::default())
//! function. This returns a handle to a thread-local instance of
//! [`CtrDrbg`](ctr::CtrDrbg) pre-allocated to use entropy supplied by the OS.
//!
//! ```
//! use drbg::thread::LocalCtrDrbg;
//!
//! # use drbg::entropy::Error;
//! #
//! # fn main() -> Result<(),Error> {
//! #
//! let drbg = LocalCtrDrbg::default();
//! let mut random_data = [0u8; 32];
//! drbg.fill_bytes(&mut random_data, None)?;
//! #
//! # Ok(())
//! # }
//! ```
//!
//! Otherwise an instance may be constructed by hand using the
//! [`CtrBuilder`](ctr::CtrBuilder) class. This approach allows the
//! caller to configure the instance with different input parameters.
//!
//!
pub mod ctr;
pub mod entropy;
pub mod thread;
