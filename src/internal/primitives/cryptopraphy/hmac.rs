use crate::{
    errors::{
        CryptoError,
        DatabaseIntegrityError,
        Error,
    },
    results::Result,
};

use aes::cipher::generic_array::{
    typenum::U32,
    GenericArray,
};

use hmac::{
    Hmac,
    Mac,
    NewMac,
};

use sha2::Sha256;

#[inline(always)]
pub fn hmac(elements: &[&[u8]], key: &[u8]) -> Result<GenericArray<u8, U32>> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_varkey(key)
        .map_err(|e|
            Error::from(DatabaseIntegrityError::from(CryptoError::from(e)))
        )?;

    for element in elements {
        mac.update(element);
    }

    let result = mac.finalize();
    Ok(result.into_bytes())
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use spectral::prelude::*;

    #[test]
    fn test_hmac() {
        let input = &[
            [0u8; 8].as_ref(),
            [0u8; 4].as_ref(),
            [0u8; 32].as_ref()
        ];

        let key = GenericArray::from([0u8; 8]);

        let result = hmac(input, &key);

        let verified_result = assert_that(
            &result
        )
            .is_ok()
            .subject;

        assert_that(&verified_result.as_slice())
            .is_equal_to(
                hex::decode(
                    "b745a38d1cc62fcf233ad8030ac6c3103cd22d226323e634617a2f72d4ebab53"
                )
                    .unwrap()
                    .as_slice()
            );
    }

    #[test]
    fn test_hmac_input_differ() {
        let input1 = &[
            [1u8; 8].as_ref(),
            [2u8; 4].as_ref(),
            [3u8; 32].as_ref()
        ];
        let input2 = &[
            [4u8; 8].as_ref(),
            [5u8; 4].as_ref(),
            [6u8; 32].as_ref()
        ];

        let key = GenericArray::from([0u8; 8]);

        let result1 = hmac(input1, &key);
        let verified_result1 = assert_that(
            &result1
        )
            .is_ok()
            .subject;

        let result2 = hmac(input2, &key);
        let verified_result2 = assert_that(
            &result2
        )
            .is_ok()
            .subject;

        assert_that(&verified_result1)
            .is_not_equal_to(verified_result2);
    }

    #[test]
    fn test_hmac_key_differ() {
        let input = &[
            [1u8; 8].as_ref(),
            [2u8; 4].as_ref(),
            [3u8; 32].as_ref()
        ];

        let key1 = GenericArray::from([0u8; 8]);
        let key2 = GenericArray::from([1u8; 8]);

        let result1 = hmac(input, &key1);
        let verified_result1 = assert_that(
            &result1
        )
            .is_ok()
            .subject;

        let result2 = hmac(input, &key2);
        let verified_result2 = assert_that(
            &result2
        )
            .is_ok()
            .subject;

        assert_that(&verified_result1)
            .is_not_equal_to(verified_result2);
    }
}
