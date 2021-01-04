use crate::results::Result;

use generic_array::{
    typenum::{
        U32,
        U64,
    },
    GenericArray,
};

use sha2::{
    Digest,
    Sha256,
    Sha512,
};

#[inline(always)]
pub fn sha256(elements: &[&[u8]]) -> Result<GenericArray<u8, U32>> {
    let mut digest = Sha256::new();

    for element in elements {
        digest.update(element);
    }

    Ok(digest.finalize())
}

#[inline(always)]
pub fn sha512(elements: &[&[u8]]) -> Result<GenericArray<u8, U64>> {
    let mut digest = Sha512::new();

    for element in elements {
        digest.update(element);
    }

    Ok(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;
    use spectral::prelude::*;

    #[test]
    fn test_sha256() {
        let elements = [
            [0u8; 32].as_ref()
        ];

        let result = sha256(elements.as_ref());

        let hashed = assert_that(&result)
            .is_ok()
            .subject
            .as_ref();

        assert_that(&hashed)
            .is_equal_to(
                decode(
                    "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
                ).unwrap().as_slice()
            );
    }

    #[test]
    fn test_sha256_input_differ() {
        let elements1 = [
            [0u8; 32].as_ref()
        ];
        let elements2 = [
            [1u8; 32].as_ref()
        ];

        let result1 = sha256(elements1.as_ref());
        let result2 = sha256(elements2.as_ref());

        let subject1 = assert_that(&result1)
            .is_ok().subject;
        let subject2 = assert_that(&result2)
            .is_ok().subject;
        assert_that(&subject1)
            .is_not_equal_to(subject2);
    }

    #[test]
    fn test_sha512() {
        let elements = [
            [0u8; 32].as_ref()
        ];

        let result = sha512(elements.as_ref());

        let hashed = assert_that(&result)
            .is_ok()
            .subject
            .as_ref();

        assert_that(&hashed)
            .is_equal_to(
                decode(
                    "5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f1960a6a85eaa642dac835424b5d7c8d637c00408c7a73da672b7f498521420b6dd3"
                ).unwrap().as_slice()
            );
    }

    #[test]
    fn test_sha512_input_differ() {
        let elements1 = [
            [0u8; 32].as_ref()
        ];
        let elements2 = [
            [1u8; 32].as_ref()
        ];

        let result1 = sha512(elements1.as_ref());
        let result2 = sha512(elements2.as_ref());

        let subject1 = assert_that(&result1)
            .is_ok().subject;
        let subject2 = assert_that(&result2)
            .is_ok().subject;
        assert_that(&subject1)
            .is_not_equal_to(subject2);
    }
}
