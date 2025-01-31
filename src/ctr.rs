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
//! A module to facilitate the CTR_DRBG algorithm.
//!
//! The CTR_DRBG algorithm is implemented via the [`CtrDrbg`]
//! type. This type may be instantiated using the builder class
//! [`CtrBuilder`].
//!
use crate::entropy::{Entropy, Error};

use aes::{
    cipher::{
        generic_array::GenericArray, typenum::consts::U48, BlockEncrypt, KeyInit, KeySizeUser,
    },
    Aes256Enc, Block,
};
use alloc::vec::Vec;
use core::iter::zip;

type SeedData = GenericArray<u8, U48>;
type Key = GenericArray<u8, <Aes256Enc as KeySizeUser>::KeySize>;

const MAX_BYTE_REQUEST: usize = 1 << 16;
const MAX_INPUT_LEN: usize = 1 << 32;
const MAX_RESEED_INTERVAL: u64 = 1 << 48;
const MIN_NONCE_LEN: usize = 16;

//
// derivation function consts
//
const DF_BLK_LEN: usize = 16;
const DF_KEY_LEN: usize = 32;
const DF_BUF_LEN: usize = DF_BLK_LEN + DF_KEY_LEN;

/// Implementation of CTR_DRBG using AES-256 and the derivation
/// function outlined by [SP 800-90A
/// Rev. 1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final). Instantiation
/// of this type is performed using the builder class [`CtrBuilder`].
///
/// # Example
///
/// ```
/// use drbg::{ctr::CtrBuilder, entropy::OsEntropy};
///
/// # use drbg::entropy::Error;
/// #
/// # fn main() -> Result<(), Error> {
/// #
/// // Build a new instance
/// let mut drbg = CtrBuilder::new(OsEntropy::default()).build()?;
///
/// // Generate random data
/// let mut random_data = [0u8; 32];
/// drbg.fill_bytes(&mut random_data, None)?;
///
/// // Reseed the instance
/// drbg.reseed(None)?;
/// #
/// # Ok(())
/// # }
/// ```
pub struct CtrDrbg<E> {
    v_blk: Block,
    tmp_blk: Block,
    key: Key,
    tmp_buf: SeedData,
    reseed_itr: u64,
    reseed_ctr: u64,
    entropy: E,
}

/// Builder class for allocating `CtrDrbg` instances.
///
/// Unless an entropy source other than
/// [`OsEntropy`](crate::entropy::OsEntropy) is required, it is
/// recommended to use the thread-local instance provided by
/// [`LocalCtrDrbg`](crate::thread::LocalCtrDrbg), rather than allocate this
/// type by hand.
///
/// The security strength for new instances are 256 bit by default.
///
/// # Example
/// ```
/// use drbg::{ctr::CtrBuilder, entropy::OsEntropy};
///
/// # use drbg::entropy::Error;
/// #
/// # fn main() -> Result<(), Error> {
/// #
/// let my_info = 0u32;
/// let mut drbg = CtrBuilder::new(OsEntropy::default())
///     .personal(&my_info.to_be_bytes())
///     .reseed_interval(1 << 14)
///     .build()?;
/// #
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct CtrBuilder<'a, E> {
    personal: Option<&'a [u8]>,
    nonce: Option<&'a [u8]>,
    reseed_itr: u64,
    entropy: E,
}

/// Increment a slice of bytes by 1 in big-endian order.
fn inc_bytes(block: &mut [u8]) {
    for bit in block.iter_mut().rev() {
        if *bit == 0xff {
            *bit = 0;
        } else {
            *bit += 1;
            break;
        }
    }
}

/// Cipher derivation function.
fn cipher_df(input: &[u8]) -> SeedData {
    let mut output = SeedData::default();
    let l: u32 = input.len() as u32;
    let n: u32 = output.len() as u32;
    // Build the S buffer which is a concatenation of the IV and input
    // values. Make sure the length is DF_BLK_LEN aligned.
    let len = ((DF_BLK_LEN + 8 + input.len() + 1) / DF_BLK_LEN) * DF_BLK_LEN;
    let mut s = Vec::with_capacity(len);
    // padding for the IV
    s.resize(DF_BLK_LEN, 0);
    s.extend_from_slice(&l.to_be_bytes());
    s.extend_from_slice(&n.to_be_bytes());
    s.extend_from_slice(input);
    s.push(0x80);
    // pad to block len
    while s.len() % DF_BLK_LEN != 0 {
        s.push(0);
    }
    let k = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
              \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
    let key = Key::from_slice(k);
    //
    // Build the initial buffer that contains the derived K and X
    // values.
    //
    let cipher = Aes256Enc::new(key);
    let mut tmp_buf = [0u8; DF_BUF_LEN];
    for blk in tmp_buf.chunks_mut(DF_BLK_LEN) {
        cipher_bcc(&cipher, &s, Block::from_mut_slice(blk));
        // increment the IV
        inc_bytes(&mut s[0..4]);
    }
    // K
    let key = Key::from_slice(&tmp_buf[0..DF_KEY_LEN]);
    // X
    let cipher = Aes256Enc::new(key);
    let x_blk = Block::from_mut_slice(&mut tmp_buf[DF_KEY_LEN..DF_BUF_LEN]);
    for blk in output.chunks_mut(DF_BLK_LEN) {
        cipher.encrypt_block(x_blk);
        blk.copy_from_slice(&x_blk[0..blk.len()]);
    }
    output
}

/// Block chaining function used by derivation function.
fn cipher_bcc(cipher: &Aes256Enc, input: &[u8], output: &mut Block) {
    debug_assert_eq!(input.len() % DF_BLK_LEN, 0);
    let mut tmp_blk = Block::default();
    for blk in input.chunks(DF_BLK_LEN) {
        for i in 0..DF_BLK_LEN {
            tmp_blk[i] = output[i] ^ blk[i];
        }
        output.copy_from_slice(&tmp_blk);
        cipher.encrypt_block(output);
    }
}

impl<'a, E> CtrBuilder<'a, E>
where
    E: Entropy,
{
    pub fn new(entropy: E) -> Self {
        Self {
            personal: None,
            nonce: None,
            reseed_itr: MAX_RESEED_INTERVAL,
            entropy,
        }
    }

    /// Specify the nonce used to initialize the CTR_DRBG instance.
    ///
    /// The nonce should have a minimum length of 16 bytes and no more
    /// than 2^32
    ///
    /// By default, this value is 16 bytes read from the `Entropy`
    /// source.
    ///
    /// # Panics
    ///
    /// This function panics if the the length of `nonce` is not `16 <=
    /// nonce <= 2^32`.
    pub fn nonce(mut self, nonce: &'a [u8]) -> CtrBuilder<'a, E> {
        if nonce.len() > MAX_INPUT_LEN {
            panic!("CtrDbrbg: nonce exceeds max input length")
        }
        if nonce.len() < MIN_NONCE_LEN {
            panic!("CtrDbrbg: nonce is less than min length")
        }
        self.nonce = Some(nonce);
        self
    }

    /// Specify the reseed interval for the CTR_DRBG instance.
    ///
    /// This interval represents the number of calls to the underlying
    /// generation function before new entropy must be added. This
    /// happens automatically. Lowering this value increases security
    /// at the cost of more frequent calls to the entropy source.
    ///
    /// By default, this value is 2^48.
    ///
    /// # Panics
    ///
    /// The reseed interval cannot exceed 2^48. This function panics
    /// if the max threshold is exceeded.
    pub fn reseed_interval(mut self, reseed_itr: u64) -> CtrBuilder<'a, E> {
        if reseed_itr > MAX_RESEED_INTERVAL {
            panic!("CtrDbrbg: reseed interval exceeds max interval")
        }
        self.reseed_itr = reseed_itr;
        self
    }

    /// Specify the personalization info used to initialize the
    /// CTR_DRBG instance.
    ///
    /// By default, this value is empty.
    ///
    /// # Panics
    ///
    /// The max length for the personalized info is 2^32. This
    /// function panics if that threshold is exceeded.
    pub fn personal(mut self, personal: &'a [u8]) -> CtrBuilder<'a, E> {
        if personal.len() > MAX_INPUT_LEN {
            panic!("CtrDbrbg: penalization exceeds max input length")
        }
        self.personal = Some(personal);
        self
    }

    /// Build and return a new [`CtrDrbg`] instance.
    ///
    /// The new instance is initialized with 32 bytes from the
    /// `Entropy` source in addition to the `nonce`, `personalization`
    /// info.
    ///
    /// # Error
    ///
    /// Returns an error when there is an problem reading from the
    /// entropy source.
    pub fn build(mut self) -> Result<CtrDrbg<E>, Error> {
        let personal = self.personal.unwrap_or(&[]);

        let c = match self.nonce {
            Some(nonce) => CtrDrbg::new(self.entropy, nonce, personal, self.reseed_itr)?,
            None => {
                let mut nonce = [0u8; 16];
                self.entropy.fill_bytes(&mut nonce)?;
                CtrDrbg::new(self.entropy, &nonce, personal, self.reseed_itr)?
            }
        };
        Ok(c)
    }
}

impl<E> Drop for CtrDrbg<E> {
    fn drop(&mut self) {
        self.v_blk.iter_mut().for_each(|v| *v = 0);
        self.tmp_blk.iter_mut().for_each(|v| *v = 0);
        self.key.iter_mut().for_each(|v| *v = 0);
        self.tmp_buf.iter_mut().for_each(|v| *v = 0);
    }
}

impl<E> CtrDrbg<E>
where
    E: Entropy,
{
    /// Fill the slice `bytes` with random data. Optional `additional`
    /// data may be provide, which is passed to the underlying
    /// derivation function as input.
    ///
    /// This function automatically reseeds `self` once the reseed
    /// interval has been met.
    ///
    /// There is no limit to the length of `bytes`. The standard does
    /// specify a limit of 2^16 bytes per request. However, the
    /// function pass `bytes` in chunks no larger than the limit to
    /// the underlying generate function.
    ///
    /// # Error
    ///
    /// Returns an error when there is an problem reading from the
    /// entropy source.
    ///
    /// # Panics
    ///
    /// If `additional` exceeds the max input length of 2^32, this
    /// function panics.
    pub fn fill_bytes(&mut self, bytes: &mut [u8], additional: Option<&[u8]>) -> Result<(), Error> {
        if let Some(buf) = additional {
            if buf.len() > MAX_INPUT_LEN {
                panic!("CtrDbrbg: additional info exceeds max input length")
            }
        }

        for blk in bytes.chunks_mut(MAX_BYTE_REQUEST) {
            while self.generate(blk, additional) {
                self.reseed(additional)?;
            }
        }
        Ok(())
    }

    /// Reseed with 32 bytes of new entropy. Optional `additional`
    /// data may be provide, which is passed to the underlying
    /// derivation function as input.
    ///
    /// # Error
    ///
    /// Returns an error when there is an problem reading from the
    /// entropy source.
    ///
    /// # Panics
    ///
    /// If `additional` exceeds the max input length of 2^32, this
    /// function panics.
    pub fn reseed(&mut self, additional: Option<&[u8]>) -> Result<(), Error> {
        if let Some(buf) = additional {
            if buf.len() > MAX_INPUT_LEN {
                panic!("CtrDbrbg: additional info exceeds max input length")
            }
        }

        let add_bytes = additional.unwrap_or(&[]);
        let mut entropy = [0u8; 32];
        self.entropy.fill_bytes(&mut entropy)?;
        let mut seed_input = Vec::with_capacity(entropy.len() + add_bytes.len());
        seed_input.extend_from_slice(&entropy);
        seed_input.extend_from_slice(add_bytes);
        let seed = cipher_df(&seed_input);

        self.update(&seed);
        self.reseed_ctr = 0;
        Ok(())
    }

    fn new(mut entropy: E, nonce: &[u8], personal: &[u8], reseed_itr: u64) -> Result<Self, Error> {
        let mut seed = [0u8; 32];
        entropy.fill_bytes(&mut seed)?;

        let mut seed_input = Vec::with_capacity(seed.len() + nonce.len() + personal.len());
        seed_input.extend_from_slice(&seed);
        seed_input.extend_from_slice(nonce);
        seed_input.extend_from_slice(personal);
        let seed = cipher_df(&seed_input);

        let mut c = Self {
            v_blk: Block::default(),
            key: Key::default(),
            reseed_ctr: 0,
            tmp_buf: SeedData::default(),
            tmp_blk: Block::default(),
            reseed_itr,
            entropy,
        };
        c.update(&seed);
        Ok(c)
    }

    fn generate(&mut self, bytes: &mut [u8], additional: Option<&[u8]>) -> bool {
        if self.reseed_ctr == self.reseed_itr {
            return true;
        }
        assert!(bytes.len() <= MAX_BYTE_REQUEST);

        let add_bytes = additional.unwrap_or(&[]);
        let seed = match add_bytes.len() {
            0 => SeedData::default(),
            _ => {
                let seed = cipher_df(add_bytes);
                self.update(&seed);
                seed
            }
        };
        let cipher = Aes256Enc::new(&self.key);
        for blk in bytes.chunks_mut(self.tmp_blk.len()) {
            inc_bytes(&mut self.v_blk);
            self.tmp_blk.copy_from_slice(&self.v_blk);
            cipher.encrypt_block(&mut self.tmp_blk);
            blk.copy_from_slice(&self.tmp_blk[0..blk.len()]);
        }
        self.update_with_cipher(&cipher, &seed);
        self.reseed_ctr += 1;
        false
    }

    fn update(&mut self, data: &SeedData) {
        self.update_with_cipher(&Aes256Enc::new(&self.key), data);
    }

    fn update_with_cipher(&mut self, cipher: &Aes256Enc, data: &SeedData) {
        let block_len = self.v_blk.len();
        for (data_blk, tmp_blk) in zip(data.chunks(block_len), self.tmp_buf.chunks_mut(block_len)) {
            inc_bytes(&mut self.v_blk);
            tmp_blk.copy_from_slice(&self.v_blk);
            cipher.encrypt_block(GenericArray::from_mut_slice(tmp_blk));
            for (i, j) in zip(tmp_blk, data_blk) {
                *i ^= *j
            }
        }
        let keylen = self.key.len();
        self.key.copy_from_slice(&self.tmp_buf[0..keylen]);
        self.v_blk.copy_from_slice(&self.tmp_buf[keylen..]);
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ctr::CtrBuilder,
        entropy::{Entropy, Error, OsEntropy},
    };
    use alloc::{vec, vec::Vec};
    use hex;

    #[cfg(test)]
    #[derive(Default)]
    struct TestCfg {
        entropy: &'static str,
        nonce: &'static str,
        reseed: &'static str,
        output: &'static str,
        add_0: &'static str,
        add_1: &'static str,
        add_2: &'static str,
        personal: &'static str,
    }

    #[cfg(test)]
    #[derive(Default)]
    struct MockEntropy {
        bytes: Vec<Vec<u8>>,
        pos: usize,
    }

    #[cfg(test)]
    impl Entropy for MockEntropy {
        fn fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
            let entropy = &self.bytes[self.pos];
            bytes.copy_from_slice(entropy);
            self.pos += 1;
            Ok(())
        }
    }

    #[cfg(test)]
    fn run_ctr_cavs_test(cfg: TestCfg) -> Result<(), Error> {
        let entropy = hex::decode(cfg.entropy).unwrap();
        let nonce = hex::decode(cfg.nonce).unwrap();
        let reseed = hex::decode(cfg.reseed).unwrap();
        let output = hex::decode(cfg.output).unwrap();
        let add_0 = hex::decode(cfg.add_0).unwrap();
        let add_1 = hex::decode(cfg.add_1).unwrap();
        let add_2 = hex::decode(cfg.add_2).unwrap();
        let personal = hex::decode(cfg.personal).unwrap();

        let mut src = MockEntropy::default();
        src.bytes.push(entropy);
        src.bytes.push(reseed);

        let mut drbg = CtrBuilder::new(src)
            .nonce(&nonce)
            .personal(&personal)
            .build()?;

        drbg.reseed(Some(&add_0))?;
        let mut bytes = [0u8; 64];
        drbg.generate(&mut bytes, Some(&add_1));
        drbg.generate(&mut bytes, Some(&add_2));
        assert_eq!(output, bytes);
        Ok(())
    }

    //
    // Test vectors from CAVS 14.3
    //

    #[test]
    fn ctr_drbg_256_df_0() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "2d4c9f46b981c6a0b2b5d8c69391e569ff13851437ebc0fc00d616340252fed5",
            nonce: "0bf814b411f65ec4866be1abb59d3c32",
            reseed: "93500fae4fa32b86033b7a7bac9d37e710dcc67ca266bc8607d665937766d207",
            output:  "322dd28670e75c0ea638f3cb68d6a9d6e50ddfd052b772a7b1d78263a7b8978b6740c2b65a9550c3a76325866fa97e16d74006bc96f26249b9f0a90d076f08e5",
            add_0: "",
            add_1: "",
            add_2: "",
            personal: "",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_1() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "200f096b76e3bf2f40133ae6649221084f0afb11f96fe86a4987ae7b1159d032",
            nonce: "3be56f6c0ae289dfc636f96cff5daaa1",
            reseed: "895133f4f2d1be25ec929d42e904dbc7749939ad7022a90360a743fd2c3f483c",
            output: "bf12bf4d8eb6bbbd9f91a2ef48c6bc6524a133dde3c8d4f13d4b5cdae3b9e041b98c8650ada9e1f2b5df01d875470b220cacad0ee887080c271929f695204b66",
            add_0: "",
            add_1: "",
            add_2: "",
            personal: "",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_2() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "1cc5a086831fac6ba046b7f56c4ea5ba7bcf9d851b5051254c4683bfed7a26f9",
            nonce: "a8d42ca3b08c9c974fa2c2eceb5a71e7",
            reseed: "e8c174c621af92c5012fc4caca8d1fb72ea7998f5f78a6cd5f3f250f330f0c74",
            output: "6654d831403693591476213bee7bea644c5058f93454e89ea5b348bc5354e2d8abac00d53b3879e2c89bc8f490969e42d738ba37432822df859d631cfc86cd40",
            add_0: "",
            add_1: "",
            add_2: "",
            personal: "",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_3() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "6ba5e815274e5cf4b2467743a8333c5c5292329a96f0aea4fdc9a1808b312c62",
            nonce: "2abe3c2f11c90ec9b684e1cb3fb0bde6",
            reseed: "bc7257f625cc1095366d7eddb793ea75ad2c5a475514d53056659423e54cd001",
            output: "b95f8d6258515a67c51f96f8201c0b5445142cde38dab3cff2b527a4e5dca5eee15f79cf073345f3438b1cd507b2fe6ce1569707fe0c288b76bf85e1bf1a0419",
            add_0: "",
            add_1: "",
            add_2: "",
            personal: "",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_4() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "14598d23e61d003bf321a2b4816f0a7ea3ef6de1ad6983f93f26b1c1630d588b",
            nonce: "2fcefe8c6a93cef35a925eb023179f02",
            reseed: "42edae478f8ba6d45e97a43906aa2a623ab60403f5f60a4c40548f0dededba4b",
            output: "766ae36c6e9c482c6fa2e7fc1e251dc35b2e2ae645a79c2b8d5c0bd7f520b0f4de1b68419c4dcea07516e255e6cbe96007a25396f93f781b36c9d2ca32361433",
            add_0: "",
            add_1: "",
            add_2: "",
            personal: "",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_add_0() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "6f60f0f9d486bc23e1223b934e61c0c78ae9232fa2e9a87c6dacd447c3f10e9e",
            nonce: "401e3f87762fa8a14ab232ccb8480a2f",
            reseed: "350be52552a65a804a106543ebb7dd046cffae104e4e8b2f18936d564d3c1950",
            add_0: "7a3688adb1cfb6c03264e2762ece96bfe4daf9558fabf74d7fff203c08b4dd9f",
            add_1: "67cf4a56d081c53670f257c25557014cd5e8b0e919aa58f23d6861b10b00ea80",
            add_2: "648d4a229198b43f33dd7dd8426650be11c5656adcdf913bb3ee5eb49a2a3892",
            output: "2d819fb9fee38bfc3f15a07ef0e183ff36db5d3184cea1d24e796ba103687415abe6d9f2c59a11931439a3d14f45fc3f4345f331a0675a3477eaf7cd89107e37",
            personal: "",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_add_1() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "fce31ff0d84b134959c8a3631668dd8126eb2ff9f40a0d1d74a371b1d2bc523e",
            nonce: "2e18419b16aa23d2230ef878371981b9",
            reseed: "75fe1b33ea930b2573c491fa892c15e09911e3479e127cd6f86ecb89568e6ddd",
            add_0: "ae1552906d13a34fadd1e3daccc1e9075dae64bfe80dcbf6921c96df8897929c",
            add_1: "c9bddd01237a8c4610c61622ec28a80b811c288c2dbfbab496b49ac15e2e540f",
            add_2: "899fd8d36215cb4ecba7df3337ce5060fefd63fb7d6381cd0db7fb9ad49293cd",
            output: "88fb20e47ee63865fa9ee19a7d4f8c1b48948af176b5783a28541eba3ac67c58b933b5937e486e1fc1827e27e36bd8f86f22adaed794cc571cf625442f82a89b",
            personal: "",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_add_2() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "944df34ca49cadbe78d507ad48ddead903a43f6c2b7fd7f76980754458ef9121",
            nonce: "55c02c461be38ac2919f96f31142ec61",
            reseed: "689a4f4d06e249db862399e58af510d80967fa7c07bf1bce0dbc786306273b57",
            add_0: "90caddd0c97fea34ed6dd9676771c918053d88b1809d5634d5c5cb8935b4075e",
            add_1: "a4f05fdb448d8c2ab7e4c165a315351086aeb194833808b20eaffd55d119a2d2",
            add_2: "b18355c75f0dd40920a04ddc229140abe22181d12c8661948153e9c69281da58",
            output: "3d7ea8046f78493ca776537755451e5e7f063fcb4d53f6a622764048c25bc48f05c39f8c8d79338cf93ead21b455cfa59c9b1bdd81eea23d75cfd63ca1fda9bf",
            personal: "",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_add_3() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "3bb3b5112e2fa8c37b22e499ad910d2a7cfece4ec114ada1e52ee545be0ce0bb",
            nonce: "54b5d6431b84aa207b550acdbaf4e0f1",
            reseed: "0da082edb7d7ee0349c90ed3f4d4cd5975fa38a1e795dbef9a92af71118cc867",
            add_0: "4496e579c086e6590ae5e086331fc5b8d6854feb94b649bbf8e212ddf1cfc527",
            add_1: "58522d812241563fc16796d793586b1f7fdcbcbe2d807865df4a20e9f50430ea",
            add_2: "848a24b8452fd6792378df382217bf72392e9435375d27b3e70e88c79c9050c9",
            output: "3c644fdd0764250c7dc7e8f02d559bbcbef8e7f5391626d563054e6c0cdc11408cca6dbc06e573e6d5719ea77a19913ae12753c28ffce872b13f484377e2339c",
            personal: "",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_add_4() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "1d602aec1601e2ff65f16628bddeac6697713d2f5d4335c7013507885b0d50c9",
            nonce: "03a5bca1bfd385ac0e14f1dc9da417bd",
            reseed: "7c5ed5898a5ff49b36f7aa8d38600d33109035750384fab2be26adc85909402d",
            add_0: "3f1164df7265fd56e701d51ef1fb3996d2cfc7c355873653d127b9e2dccc1da3",
            add_1: "02a7d68d2e6f4de2a35c97e7aadf25a2f14a9b4076940050ffe64482e62718a7",
            add_2: "40b4ff19609f6266e450e1cdb184f1aa0b551a05b912a1251b9caf7ee15a7184",
            output: "5bc4e4c09a19d5f394ee6003437843974dfe4430684d394d6c7cc8eb4d7a722c615707d0ede88ef1fbba81e45fdd93d2096632cf21b630dd933f52a052aa9be4",
            personal: "",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_per_0() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "5bb14bec3a2e435acab8b891f075107df387902cb2cd996021b1a1245d4ea2b5",
            nonce: "12ac7f444e247f770d2f4d0a65fdab4e",
            personal: "2e957d53cba5a6b9b8a2ce4369bb885c0931788015b9fe5ac3c01a7ec5eacd70",
            reseed: "19f30c84f6dbf1caf68cbec3d4bb90e5e8f5716eae8c1bbadaba99a2a2bd4eb2",
            output: "b7dd8ac2c5eaa97c779fe46cc793b9b1e7b940c318d3b531744b42856f298264e45f9a0aca5da93e7f34f0ebc0ed0ea32c009e3e03cf01320c9a839807575405",
            add_0: "",
            add_1: "",
            add_2: "",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_per_1() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "5e1a564a70f593c1c0b07c9906455bd9f5ce7ad92eb344a9cceb12f5576d7d9c",
            nonce: "45e093e587341f6cb8f3deffddc4dc4d",
            personal: "b61714ba7ed339a24635c0bd4f4db496b74631ebbcd14f648de71bd6d7c197ff",
            reseed: "4fcf7ab9daa808ae81eaf728dc74bdf4c123a1e2444e5118c8040142fea50a0b",
            output: "4d56fa065a3b98f9ce21701c00c833bcd439276fc70aaa14185b39f34d80232565c992e2f0fbd9519175751b4057c21ea69d4c553e30e3dc5533d4abd97ab19f",
            add_0: "",
            add_1: "",
            add_2: "",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_per_2() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "c32238773de8dfdf3bc319a64631c3caf67ab0716e8946eee2fff1fdda96d2ff",
            nonce: "ae2b3a16b031c784b80b94b45c8cfaea",
            personal: "b29400e49e0fe24c6418c4da38417f857d53ed61070d467e34049f613568978f",
            reseed: "91c36b0c87587b663583f636a26303f308b7a5dc235cb18086d4e350bd3fb631",
            output: "a1d5a059e6f3c25a1b10613efbfc483095cc257fd98ed2914379bcd8a2ffca2b3d745c32dffdb721ae7a9dea85e0b7a993dbdfec01acaf1097dd9f52ee223a0d",
            add_0: "",
            add_1: "",
            add_2: "",
        };
        run_ctr_cavs_test(cfg)
    }
    #[test]
    fn ctr_drbg_256_df_per_3() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "ce80e5656090e097bafc210370213d46f358f77903fcdfb877a0e57f453b4f7a",
            nonce: "4515c86448eda28ee63817f36a282ba3",
            personal: "c7875ccf1e5ef1f6d7594296024a71caca6cf53cc86e4e02f86fbb03506fa9a8",
            reseed: "8ce6f56cd5b26de59e01ea11509a23e598aff809dfe07df7e4994c99885eb94f",
            output: "41cc565ec349c978bf7c4af28a6ca9b1a59924b23a581a7f3b43ae089690d6ac262c024fc16d56d1b436c8004522f87f5e8ec3851903ea1ec874505a206d1659",
            add_0: "",
            add_1: "",
            add_2: "",
        };
        run_ctr_cavs_test(cfg)
    }
    #[test]
    fn ctr_drbg_256_df_per_4() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "417b1a5aa4694acc25ae2fb18ebee5055d691f8908888e608862c831b9936eae",
            nonce: "53a227b0468602f6d5ed623b6b552f48",
            personal: "ecbe55cde21a7d74f03408e5fc8b4c162ee06651552fd32a6d40e06c667f95e2",
            reseed: "d1a00e5bf56519c127a17ffca848a2276b02604eb01b9283de5857fa8d19b437",
            output: "ad11375cd7db354fd67302d7065c9ef36dea373f744114ceafeafe6b91479837ec6fd9cdfc29220e84608fb8c1a59bde7022a8f1e31bef034895cf06a8085188",
            add_0: "",
            add_1: "",
            add_2: "",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_per_add_0() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "174b46250051a9e3d80c56ae7163dafe7e54481a56cafd3b8625f99bbb29c442",
            nonce: "98ffd99c466e0e94a45da7e0e82dbc6b",
            personal: "7095268e99938b3e042734b9176c9aa051f00a5f8d2a89ada214b89beef18ebf",
            reseed: "e88be1967c5503f65d23867bbc891bd679db03b4878663f6c877592df25f0d9a",
            add_0: "cdf6ad549e45b6aa5cd67d024931c33cd133d52d5ae500c3015020beb30da063",
            add_1: "c7228e90c62f896a09e11684530102f926ec90a3255f6c21b857883c75800143",
            add_2: "76a94f224178fe4cbf9e2b8acc53c9dc3e50bb613aac8936601453cda3293b17",
            output: "1a6d8dbd642076d13916e5e23038b60b26061f13dd4e006277e0268698ffb2c87e453bae1251631ac90c701a9849d933995e8b0221fe9aca1985c546c2079027",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_per_add_1() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "4a92748137f999160a6a75a2a14bc87863f7d27aef0d535c72c7f6c2e96da245",
            nonce: "3f1af8a23af9e13095a0ada3a96218db",
            personal: "f7fcfc356cda3a71c4c4729a2ca63a0be6b7178612e643ead78a44efa35d1100",
            reseed: "efa6fda84b4d01b116b39dc514baef49ff51f01841b1949e94fdee2ec746bdd4",
            add_0: "5d20bf1e3a06193ab9e1e025c30059149030b1996b727ce65d07649b62fa1bc7",
            add_1: "b53f780806a9ad5903acdd1f851f0b0fe72a3390663b40682075b25ac92c0fd5",
            add_2: "46e84839a10ebb41694e55fd06424e494be580c5e18e4744df8a6463ff734a40",
            output: "dc676285e8dcfccffbb1c2bf414f4b20fecd3e99e7a9f4d90bc86506054dbd444a7c740f48e71f12931e864ee63c690374b14d1820eaefc1bf5f0d8b57150b5b",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_per_add_2() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "0ab7995cb7936f22fea03240fd87866ed39075eed94bbfc6be785ad052552ab4",
            nonce: "5f1b0e417d867a38ee0994f96ed6e8e1",
            personal: "4305a7e01f931e2dd76830cfc38bd166b235934d250584884f9b6a4d7837838f",
            reseed: "5cc48cd4c19e8c17cd9fccf67fb4aa8008a745f922f3e7e51fd29cc1c1490ae7",
            add_0: "89632c6a52e92573214f50289ac743165ec7b22e6c9ef95be8ee4a8d3ad968ab",
            add_1: "9bad67ae472d901d3eb044c5394e4968b2c2bfed1fa65103aa35b121d7eadaf1",
            add_2: "af715eb5889f22fb63d004b3d7ed485c60b0342d4af737ac32e07ca5546e74a3",
            output: "9237d5a404f7eba157f1d9b8bc82f6ed1f829925c2c690f905b1030ff4b3a592f5e221e99d76c1421a41e8f74bc1f78ab4a77001e39d87d42f4260cbaf4a40c1",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_per_add_3() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "5f04399165a2392f61c588fe646e9d8cdc9b2c356f7b00502716dc433ecf913d",
            nonce: "d3c9b9336bcdef76be6da42d67b77c73",
            personal: "f31cb8ec30e087c6f932500877b9d7b3c47566cd919e79d187340baa4d389ced",
            reseed: "7362fd81355adb2d4221fd66a85ecd20e949b912c4aef9c12851b7916d441867",
            add_0: "f811563823d046625642e052aadb89bd6414673be1419d342a7e3dc3bb1add17",
            add_1: "6a06f30779569b7d561ee16bd52eb8fa7ce60d236e8192f8018310d901adb654",
            add_2: "9bf489bd45e4dd75207dbe7339b9e0466f5371822f8e90dccaa2a31b3c788a2b",
            output: "00d88e7fa528f830be3ead61ddba1298dcad366c0ab1a4e90f49f13587b9326932d8e1972c4e7b335ceedd2fb17d334647ef6f406e3082a1c33ff4de986a5557",
        };
        run_ctr_cavs_test(cfg)
    }

    #[test]
    fn ctr_drbg_256_df_per_add_4() -> Result<(), Error> {
        let cfg = TestCfg {
            entropy: "a7a05361d428af23a0d4f132768a4b24fbd78e1f42fb46205d7b52891b2297a8",
            nonce: "8177600cb1ffea161277a839ad5d05fa",
            personal: "79ce51a1c295c9a38d11db5023c349fba347e193961c90af9e2e7326420d9028",
            reseed: "664038f3e8bfd6b0ba6552e83698b3f4945f182c400bffab74b46f07ad42764e",
            add_0: "a582b450eff21dc5c0bbde225cf902a4858891ff42b2cdc5208091106448582e",
            add_1: "1fa8be0676ba5b09b84d43ac44c78432858efa4bda7b4aad8d6a7e64d155cc89",
            add_2: "b7368a0e32ea9e176163679219580fd050f7566a318f1b6c5faf1e84e2e9070f",
            output: "56ebc22bd25e87233e27448f3d78d027fd9ab606f00ad17d9c427c7ad88a297b940f044a7e6dc548a9ec12074ac9cb87148b6b2d48d70b24cfd6e20344e7b85b",
        };
        run_ctr_cavs_test(cfg)
    }

    //
    // Argument validation tests
    //

    #[test]
    #[should_panic]
    fn drbg_builder_invalid_nonce_0() {
        let entropy = OsEntropy::default();
        let bad_nonce = vec![0u8; (1 << 32) + 1];
        let _ = CtrBuilder::new(entropy).nonce(&bad_nonce);
    }

    #[test]
    #[should_panic]
    fn drbg_builder_invalid_nonce_1() {
        let entropy = OsEntropy::default();
        let bad_nonce = vec![0u8; 1];
        let _ = CtrBuilder::new(entropy).nonce(&bad_nonce);
    }

    #[test]
    #[should_panic]
    fn drbg_builder_invalid_personal() {
        let entropy = OsEntropy::default();
        let bad_nonce = vec![0u8; (1 << 32) + 1];
        let _ = CtrBuilder::new(entropy).personal(&bad_nonce);
    }

    #[test]
    #[should_panic]
    fn drbg_builder_invalid_reseed() {
        let entropy = OsEntropy::default();
        let _ = CtrBuilder::new(entropy).reseed_interval((1 << 48) + 1);
    }

    #[test]
    #[should_panic]
    fn drbg_builder_invalid_aditional_0() {
        let entropy = OsEntropy::default();
        let mut buf = [0u8; 32];
        let bad_adata = vec![0u8; (1 << 32) + 1];
        let mut drbg = CtrBuilder::new(entropy).build().unwrap();

        drbg.fill_bytes(&mut buf, Some(&bad_adata)).unwrap();
    }

    #[test]
    #[should_panic]
    fn drbg_builder_invalid_aditional_1() {
        let entropy = OsEntropy::default();
        let bad_adata = vec![0u8; (1 << 32) + 1];
        let mut drbg = CtrBuilder::new(entropy).build().unwrap();

        drbg.reseed(Some(&bad_adata)).unwrap();
    }
}
