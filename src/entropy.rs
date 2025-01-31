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
//! Traits and types for defining entropy sources.
use alloc::string::{String, ToString};
use core::{
    fmt,
    fmt::{Debug, Display, Formatter},
};

/// Error type for entropy source failures.
#[derive(Debug)]
pub struct Error {
    inner: String,
}

/// Represents a source of cryptograplicly secure random data. It's
/// primary use-case is to seed random number generators.
pub trait Entropy {
    /// Fill `bytes` with random data from the entropy source.
    ///
    /// # Error
    ///
    /// Returns an error if there is a problem with the underlying
    /// entropy source.
    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Error>;
}

impl Error {
    /// Create a new error by wrapping an underlying entropy source
    /// error.
    ///
    /// # Example
    /// ```
    /// use drbg::entropy::Error;
    ///
    /// fn fill_bytes(bytes: &mut [u8]) -> Result<(), Error> {
    ///    getrandom::getrandom(bytes).map_err(Error::new)
    /// }
    /// ```
    pub fn new<E>(error: E) -> Self
    where
        E: Display + Debug,
    {
        Self {
            inner: error.to_string(),
        }
    }
}

impl core::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "entropy error: {}", self.inner)
    }
}

/// An entropy source that draws random data from the host operating
/// system.
///
/// ```
/// use drbg::entropy::{OsEntropy, Entropy};
///
/// # use drbg::entropy::Error;
/// #
/// # fn main() -> Result<(),Error> {
/// #
/// let mut entropy = OsEntropy::default();
/// let mut random_data = [0u8; 32];
/// entropy.fill_bytes(&mut random_data)?;
/// #
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct OsEntropy {}

impl OsEntropy {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Entropy for OsEntropy {
    /// Fill `bytes` with random data from the operating system using
    /// [`getrandom`](getrandom::getrandom).
    ///
    /// # Error
    ///
    /// Returns any error from `getrandom`.
    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        getrandom::getrandom(bytes).map_err(Error::new)
    }
}
