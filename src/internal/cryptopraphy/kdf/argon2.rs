use super::{
    Kdf,
    GenericArray,
    typenum
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
    pub lanes: u32,
    pub version: argon2::Version,
}

impl Kdf for Argon2Kdf {

    #[inline(always)]
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, typenum::U32>,
    ) -> Result<GenericArray<u8, typenum::U32>> {

        let config = argon2::Config {
            ad: &[],
            hash_length: 32,
            lanes: self.lanes,
            mem_cost: (self.memory / 1024) as u32,
            secret: &[],
            thread_mode: argon2::ThreadMode::from_threads(self.lanes),
            time_cost: self.iterations as u32,
            variant: argon2::Variant::Argon2d,
            version: self.version,
        };

        let key = argon2::hash_raw(
            composite_key,
            &self.salt,
            &config
        )
            .map_err(|e| Error::from(
                DatabaseIntegrityError::from(
                    CryptoError::from(e)
                )
            ))?;

        Ok(*GenericArray::from_slice(&key))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    const LANES: u32 = 1u32;

    #[test]
    fn test_transform_key_1000() {
        let result = _run_transform_key(1000, LANES);
        assert_that(&result).is_ok();
    }

    #[test]
    fn test_transform_key_2000() {
        let result = _run_transform_key(2000, LANES);
        assert_that(&result).is_ok();
    }

    #[test]
    fn test_transform_key_5000() {
        let result = _run_transform_key(5000, LANES);
        assert_that(&result).is_ok();
    }

    #[test]
    fn test_transform_key_10000() {
        let result = _run_transform_key(10000, LANES);
        assert_that(&result).is_ok();
    }

    #[test]
    fn test_transform_key_20000() {
        let result = _run_transform_key(20000, LANES);
        assert_that(&result).is_ok();
    }

    #[inline(always)]
    fn _run_transform_key(
        iterations: u64,
        lanes: u32
    ) -> Result<GenericArray<u8, typenum::U32>>
    {
        let key: [u8; 32] = [0u8; 32];

        let sample_key = GenericArray::from_slice(&key);

        let algo = Argon2Kdf {
            memory: 1024 * 1024,
            salt: Vec::from([1u8; 16]),
            iterations,
            lanes,
            version: argon2::Version::Version13
        };

        algo.transform_key(sample_key)
    }
}

#[cfg(bench)]
mod benches {
    use super::*;
    use test::Bencher;

    #[bench]
    fn benchmark_transform_key_1000_lanes_1(b: &mut Bencher) {
        let algo = _setup_transform_key(1000, 1);

        b.iter(|_| {
            algo.transform_key(sample_key);
        });
    }

    #[bench]
    fn benchmark_transform_key_2000_lanes_1(b: &mut Bencher) {
        let algo = _setup_transform_key(2000, 1);

        b.iter(|_| {
            algo.transform_key(sample_key);
        });
    }

    #[bench]
    fn benchmark_transform_key_5000_lanes_1(b: &mut Bencher) {
        let algo = _setup_transform_key(5000, 1);

        b.iter(|_| {
            algo.transform_key(sample_key);
        });
    }

    #[bench]
    fn benchmark_transform_key_10000_lanes_1(b: &mut Bencher) {
        let algo = _setup_transform_key(10000, 1);

        b.iter(|_| {
            algo.transform_key(sample_key);
        });
    }

    #[bench]
    fn benchmark_transform_key_1000_lanes_2(b: &mut Bencher) {
        let algo = _setup_transform_key(1000, 2);

        b.iter(|_| {
            algo.transform_key(sample_key);
        });
    }

    #[bench]
    fn benchmark_transform_key_2000_lanes_2(b: &mut Bencher) {
        let algo = _setup_transform_key(2000, 2);

        b.iter(|_| {
            algo.transform_key(sample_key);
        });
    }

    #[bench]
    fn benchmark_transform_key_5000_lanes_2(b: &mut Bencher) {
        let algo = _setup_transform_key(5000, 2);

        b.iter(|_| {
            algo.transform_key(sample_key);
        });
    }

    #[bench]
    fn benchmark_transform_key_10000_lanes_2(b: &mut Bencher) {
        let algo = _setup_transform_key(10000, 2);

        b.iter(|_| {
            algo.transform_key(sample_key);
        });
    }

    #[bench]
    fn benchmark_transform_key_20000_lanes_2(b: &mut Bencher) {
        let algo = _setup_transform_key(20000, 2);

        b.iter(|_| {
            algo.transform_key(sample_key);
        });
    }

    #[bench]
    fn benchmark_transform_key_1000_lanes_4(b: &mut Bencher) {
        let algo = _setup_transform_key(1000, 4);

        b.iter(|_| {
            algo.transform_key(sample_key);
        });
    }

    #[bench]
    fn benchmark_transform_key_2000_lanes_4(b: &mut Bencher) {
        let algo = _setup_transform_key(2000, 4);

        b.iter(|_| {
            algo.transform_key(sample_key);
        });
    }

    #[bench]
    fn benchmark_transform_key_5000_lanes_4(b: &mut Bencher) {
        let algo = _setup_transform_key(5000, 4);

        b.iter(|_| {
            algo.transform_key(sample_key);
        });
    }

    #[bench]
    fn benchmark_transform_key_10000_lanes_4(b: &mut Bencher) {
        let algo = _setup_transform_key(10000, 4);

        b.iter(|_| {
            algo.transform_key(sample_key);
        });
    }

    #[bench]
    fn benchmark_transform_key_20000_lanes_4(b: &mut Bencher) {
        let algo = _setup_transform_key(20000, 4);

        b.iter(|_| {
            algo.transform_key(sample_key);
        });
    }

    #[inline(always)]
    fn _setup_transform_key(
        iterations: u64,
        lanes: u32
    ) -> Argon2Kdf
    {
        let key: [u8;32] = [0u8; 32];

        let sample_key = GenericArray::from_slice(&key);

        Argon2Kdf {
            memory: 1024*1024,
            salt: Vec::from([1u8;16]),
            iterations,
            lanes,
            version: argon2::Version::Version13
        }
    }
}
