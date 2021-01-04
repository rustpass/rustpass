use crate::{
    api::suites::InnerCipherSuite,
    errors::{
        DatabaseIntegrityError,
        Error
    },
    results::Result,
    internal::primitives::cryptopraphy,
};

use std::convert::TryFrom;

impl InnerCipherSuite {
    pub(crate) fn get_cipher(&self, key: &[u8]) -> Result<Box<dyn cryptopraphy::cipher::Cipher>> {
        match self {
            InnerCipherSuite::Plain => Ok(
                Box::new(
                    cryptopraphy::cipher::PlainCipher::with_key(key)?
                )
            ),
            InnerCipherSuite::Salsa20 => Ok(
                Box::new(
                    cryptopraphy::cipher::Salsa20Cipher::with_key(key)?
                )
            ),
            InnerCipherSuite::ChaCha20 => Ok(
                Box::new(cryptopraphy::cipher::ChaCha20Cipher::with_key(key)?
                )
            ),
        }
    }
}

impl TryFrom<u32> for InnerCipherSuite {
    type Error = Error;

    fn try_from(v: u32) -> Result<InnerCipherSuite> {
        match v {
            0 => Ok(InnerCipherSuite::Plain),
            2 => Ok(InnerCipherSuite::Salsa20),
            3 => Ok(InnerCipherSuite::ChaCha20),
            _ => Err(DatabaseIntegrityError::InvalidInnerCipherID { cid: v }.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_plain_cipher_expect_success() {
        let key = [0u8;32].as_ref();

        let plaintext = "This is a plaintext".as_bytes();

        let suite = InnerCipherSuite::Plain
            .get_cipher(key);

        let mut cipher_box = suite.unwrap();

        let encryption_result =  cipher_box.encrypt(plaintext.as_ref());

        let ciphertext = assert_that(&encryption_result)
            .is_ok();

        let deciphered_plaintext = cipher_box.decrypt(ciphertext.subject);

        assert_that(&deciphered_plaintext)
            .is_ok()
            .is_equal_to(plaintext.to_vec());
    }

    #[test]
    fn test_salsa20_cipher_expect_success() {
        let key = [0u8;32].as_ref();

        let plaintext = "This is a plaintext".as_bytes();

        let suite = InnerCipherSuite::Salsa20;

        let encryption_suite = suite
            .get_cipher(key);

        assert_that(&encryption_suite.is_ok()).is_true();

        let mut encryption_cipher_box = encryption_suite.unwrap();

        let encryption_result =  encryption_cipher_box.encrypt(plaintext.as_ref());

        let ciphertext = assert_that(&encryption_result)
            .is_ok();


        let decryption_suite = suite
            .get_cipher(key);

        assert_that(&decryption_suite.is_ok()).is_true();

        let mut decryption_cipher_box = decryption_suite.unwrap();

        let deciphered_plaintext = decryption_cipher_box.decrypt(ciphertext.subject);

        assert_that(&deciphered_plaintext)
            .is_ok()
            .is_equal_to(plaintext.to_vec());
    }

    #[test]
    fn test_chacha20_cipher_expect_success() {
        let key = [0u8;32].as_ref();

        let plaintext = "This is a plaintext".as_bytes();

        let suite = InnerCipherSuite::ChaCha20;

        let encryption_suite = suite
            .get_cipher(key);

        assert_that(&encryption_suite.is_ok()).is_true();

        let mut encryption_cipher_box = encryption_suite.unwrap();

        let encryption_result =  encryption_cipher_box.encrypt(plaintext.as_ref());

        let ciphertext = assert_that(&encryption_result)
            .is_ok();


        let decryption_suite = suite
            .get_cipher(key);

        assert_that(&decryption_suite.is_ok()).is_true();

        let mut decryption_cipher_box = decryption_suite.unwrap();

        let deciphered_plaintext = decryption_cipher_box.decrypt(ciphertext.subject);

        assert_that(&deciphered_plaintext)
            .is_ok()
            .is_equal_to(plaintext.to_vec());
    }
}
