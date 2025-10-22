// SPDX-License-Identifier: MIT

//! A thread-local interface for the CTR_DRBG algorithm.
use crate::{
    ctr::{CtrBuilder, CtrDrbg},
    entropy::{Error, OsEntropy},
};

use std::{
    cell::RefCell,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    thread_local,
};

#[cfg(feature = "rand_core")]
use rand_core::{TryCryptoRng, TryRngCore};

/// A thread-local instance of CTR_DRBG.
///
/// A call to [`LocalCtrDrbg::default()`] returns a handle to a
/// pre-allocated thread-local instance. Each instance is
/// automatically configured with the following configuration:
///
/// - [`OsEntropy`] as entropy source.
///
/// - 32 bytes of initial entropy.
///
/// - Reseed interval of 2^14.
///
/// - 8 byte unique ID as personalization information.
///
/// # Example
///
/// ```
/// # use drbg::entropy::Error;
/// use drbg::thread::LocalCtrDrbg;
///
/// # fn main() -> Result<(),Error> {
/// let drbg = LocalCtrDrbg::default();
/// let mut random_data = [0u8; 32];
/// drbg.fill_bytes(&mut random_data, None)?;
/// # Ok(())
/// # }
/// ```
pub struct LocalCtrDrbg {
    rng: Rc<RefCell<CtrDrbg<OsEntropy>>>,
}

const RESEED_INTERVAL: u64 = 1 << 14;

static NEXT_LOCAL_ID: AtomicU64 = AtomicU64::new(0);

thread_local!(
    static LOCAL_RNG: Rc<RefCell<CtrDrbg<OsEntropy>>> = {
        let entropy = OsEntropy::default();
        let id = NEXT_LOCAL_ID.fetch_add(1, Ordering::Relaxed);
        let drbg = CtrBuilder::new(entropy)
            .personal(&id.to_be_bytes())
            .reseed_interval(RESEED_INTERVAL)
            .build().expect("DrbgBuilder failure");

        Rc::new(RefCell::new(drbg))
    }
);

impl Default for LocalCtrDrbg {
    fn default() -> Self {
        Self {
            rng: LOCAL_RNG.with(|v| v.clone()),
        }
    }
}

impl LocalCtrDrbg {
    /// See [`fill_bytes`](crate::ctr::CtrDrbg::fill_bytes) for details.
    pub fn fill_bytes(&self, bytes: &mut [u8], additional: Option<&[u8]>) -> Result<(), Error> {
        self.rng.borrow_mut().fill_bytes(bytes, additional)
    }

    /// See [`reseed`](crate::ctr::CtrDrbg::reseed) for details.
    pub fn reseed(&self, additional: Option<&[u8]>) -> Result<(), Error> {
        self.rng.borrow_mut().reseed(additional)
    }
}

#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
impl TryCryptoRng for LocalCtrDrbg where LocalCtrDrbg: TryRngCore {}

#[cfg(feature = "rand_core")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
impl TryRngCore for LocalCtrDrbg {
    type Error = Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.rng.borrow_mut().try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.rng.borrow_mut().try_next_u64()
    }

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.rng.borrow_mut().try_fill_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use crate::{entropy::Error, thread::LocalCtrDrbg};
    use std::{thread, vec::Vec};

    #[test]
    fn single_thread() -> Result<(), Error> {
        let rng = LocalCtrDrbg::default();
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf, None)?;
        assert_ne!([0u8; 8], buf);
        Ok(())
    }

    #[test]
    fn multi_thread() {
        let num_threads = 32;
        let mut handles = Vec::with_capacity(num_threads);
        for _ in 0..num_threads {
            let h = thread::spawn(move || {
                let rng = LocalCtrDrbg::default();
                let mut buf = [0u8; 8];
                rng.fill_bytes(&mut buf, None).unwrap();
                assert_ne!([0u8; 8], buf);
            });
            handles.push(h)
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}
