use rand::{
    thread_rng,
    Rng,
    distributions::Alphanumeric,
};

pub(crate) fn generate_random_bytes(length: usize) -> Vec<u8> {
    thread_rng()
        .sample_iter(Alphanumeric)
        .take(length)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_generate_random_bytes_16() {
        let result = generate_random_bytes(16);
        assert_that(&result)
            .has_length(16);
    }

    #[test]
    fn test_generate_random_bytes_24() {
        let result = generate_random_bytes(24);
        assert_that(&result)
            .has_length(24);
    }

    #[test]
    fn test_generate_random_bytes_32() {
        let result = generate_random_bytes(32);
        assert_that(&result)
            .has_length(32);
    }

    #[test]
    fn test_generate_random_bytes_48() {
        let result = generate_random_bytes(48);
        assert_that(&result)
            .has_length(48);
    }

    #[test]
    fn test_generate_random_bytes_64() {
        let result = generate_random_bytes(64);
        assert_that(&result)
            .has_length(64);
    }

    #[test]
    fn test_generate_random_bytes_128() {
        let result = generate_random_bytes(128);
        assert_that(&result)
            .has_length(128);
    }

    #[test]
    fn test_generate_random_bytes_256() {
        let result = generate_random_bytes(256);
        assert_that(&result)
            .has_length(256);
    }
}
