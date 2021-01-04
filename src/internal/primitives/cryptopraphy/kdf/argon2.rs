use super::{
    Kdf,
    super::{
        GenericArray,
        typenum
    }
};

use crate::{
    errors::{
        CryptoError,
        DatabaseIntegrityError,
        Error,
    },
    results::Result,
};

use argon2;

pub struct Argon2Kdf {
    pub memory: u64,
    pub salt: Vec<u8>,
    pub iterations: u64,
    pub parallelism: u32,
    pub version: argon2::Version,
}

impl Kdf for Argon2Kdf {

    #[inline(always)]
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, typenum::U32>,
    ) -> Result<GenericArray<u8, typenum::U32>> {

        let mut _thread_mode = argon2::ThreadMode::Sequential;
        if self.parallelism > 1 {
          _thread_mode = argon2::ThreadMode::Parallel;
        }

        let config = argon2::Config {
            ad: &[],
            hash_length: 32,
            lanes: self.parallelism,
            mem_cost: (self.memory / 1024) as u32,
            secret: &[],
            thread_mode: _thread_mode,
            time_cost: self.iterations as u32,
            variant: argon2::Variant::Argon2d,
            version: self.version,
        };

        let key = argon2::hash_raw(composite_key, &self.salt, &config)
            .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

        Ok(*GenericArray::from_slice(&key))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_transform_key() {
        let result = _test_transform_key_impl(1024, 1);
        assert_that(&result).is_ok();
    }

    #[test]
    fn test_transform_key_1000() {
        let result = _test_transform_key_impl(1000, 1);
        assert_that(&result).is_ok();
    }

    #[test]
    fn test_transform_key_2000() {
        let result = _test_transform_key_impl(2000, 1);
        assert_that(&result).is_ok();
    }

    #[test]
    fn test_transform_key_5000() {
        let result = _test_transform_key_impl(5000, 1);
        assert_that(&result).is_ok();
    }

    #[test]
    fn test_transform_key_10000() {
        let result = _test_transform_key_impl(10000, 1);
        assert_that(&result).is_ok();
    }

    #[test]
    fn test_transform_key_20000() {
        let result = _test_transform_key_impl(20000, 1);
        assert_that(&result).is_ok();
    }

    fn _test_transform_key_impl(rounds: u64, parallel: u32) -> Result<GenericArray<u8, typenum::U32>> {
        let key: [u8;32] = [0u8; 32];

        let sample_key = GenericArray::from_slice(&key);

        let algo = Argon2Kdf {
            memory: 128_000,
            salt: Vec::from([1u8;16]),
            iterations: rounds,
            parallelism: parallel,
            version: argon2::Version::Version13
        };

        algo.transform_key(sample_key)
    }
}
