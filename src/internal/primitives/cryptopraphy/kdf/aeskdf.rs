use super::{
    Kdf,
    GenericArray,
    typenum,
};

use crate::{
    internal::primitives::cryptopraphy::hash::sha256,
    errors::{
        CryptoError,
        DatabaseIntegrityError,
        Error,
    },
    results::Result,
};

use aes::Aes256;

use block_modes::{
    block_padding::ZeroPadding, // for KDF ZeroPadding is used
    BlockMode,
    Ecb,
};

use futures::{
    executor::block_on,
    join
};

type Mode = Ecb<Aes256, ZeroPadding>;

pub struct AesKdf {
    seed: Vec<u8>,
    rounds: u64,
}

impl AesKdf {
    const IV: [u8; 16] = [0u8; 16];

    pub fn new(
        seed: &[u8],
        rounds: u64,
    ) -> Self {
        AesKdf {
            seed: seed.to_vec(),
            rounds,
        }
    }

    #[inline(always)]
    async fn transform_key_raw(
        &self,
        raw_key: &[u8],
    ) -> Result<Vec<u8>> {
        let mut key = Vec::from(raw_key);
        let mut key_len = raw_key.len();

        let cipher =
            Mode::new_var(
                self.seed.as_ref(),
                Self::IV.as_ref(),
            ).map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

        for _ in 0..self.rounds {
            let res = cipher
                .clone()
                .encrypt(
                    &mut key,
                    key_len
                );
            if  res.is_err() {
                res.map_err(|e| Error::from(
                    DatabaseIntegrityError::from(CryptoError::from(e))
                ))?;
            }
        }

        Ok(key.clone())
    }
}

impl Kdf for AesKdf {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, typenum::U32>,
    ) -> Result<GenericArray<u8, typenum::U32>> {
        let (_left, _right) = composite_key.split_at(composite_key.len() / 2);

        let future_key_left = self.transform_key_raw(_left);
        let future_key_right = self.transform_key_raw(_right);

        let (key_left, key_right) = block_on(async { futures::join!(future_key_left, future_key_right) });

        sha256(&[&key_left?, &key_right?])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use extfmt::Hexlify;
    use spectral::prelude::*;

    #[test]
    fn test_transform_key() {
        let result = _test_transform_key_impl(100);

        assert_that(&result).is_ok()
            .matches(|r|
                Hexlify(r.as_slice()).to_string() == "96e80e07b7b8e04eb472f3c1d3a87db9bdb3dc4907cffc9bbf62f126e3b861cd"
            );
    }

    #[test]
    fn test_transform_key_10000() {
        let result = _test_transform_key_impl(10000);

        assert_that(&result).is_ok()
            .matches(|r|
                Hexlify(r.as_slice()).to_string() != "96e80e07b7b8e04eb472f3c1d3a87db9bdb3dc4907cffc9bbf62f126e3b861cd"
            );
    }

    #[test]
    fn test_transform_key_100000() {
        let result = _test_transform_key_impl(100000);

        assert_that(&result).is_ok()
            .matches(|r|
                Hexlify(r.as_slice()).to_string() != "96e80e07b7b8e04eb472f3c1d3a87db9bdb3dc4907cffc9bbf62f126e3b861cd"
            );
    }

    #[test]
    fn test_transform_key_1000000() {
        let result = _test_transform_key_impl(1000000);

        assert_that(&result).is_ok()
            .matches(|r|
                Hexlify(r.as_slice()).to_string() != "96e80e07b7b8e04eb472f3c1d3a87db9bdb3dc4907cffc9bbf62f126e3b861cd"
            );
    }

    #[test]
    fn test_transform_key_2500000() {
        let result = _test_transform_key_impl(2500000);

        assert_that(&result).is_ok()
            .matches(|r|
                Hexlify(r.as_slice()).to_string() != "96e80e07b7b8e04eb472f3c1d3a87db9bdb3dc4907cffc9bbf62f126e3b861cd"
            );
    }

    #[test]
    fn test_transform_key_5000000() {
        let result = _test_transform_key_impl(5000000);

        assert_that(&result).is_ok()
            .matches(|r|
                Hexlify(r.as_slice()).to_string() != "96e80e07b7b8e04eb472f3c1d3a87db9bdb3dc4907cffc9bbf62f126e3b861cd"
            );
    }

    #[test]
    fn test_transform_key_7500000() {
        let result = _test_transform_key_impl(7500000);

        assert_that(&result).is_ok()
            .matches(|r|
                Hexlify(r.as_slice()).to_string() != "96e80e07b7b8e04eb472f3c1d3a87db9bdb3dc4907cffc9bbf62f126e3b861cd"
            );
    }

    #[test]
    fn test_transform_key_10000000() {
        let result = _test_transform_key_impl(10000000);

        assert_that(&result).is_ok()
            .matches(|r|
                Hexlify(r.as_slice()).to_string() != "96e80e07b7b8e04eb472f3c1d3a87db9bdb3dc4907cffc9bbf62f126e3b861cd"
            );
    }

    fn _test_transform_key_impl(rounds: u64) -> Result<GenericArray<u8, typenum::U32>> {
        let mut key = [1u8; 32].to_vec();

        let sample_key = GenericArray::from_slice(&key);

        let algo = AesKdf::new(
            [2u8; 32].as_ref(),
            rounds,
        );

        algo.transform_key(sample_key)
    }
}

