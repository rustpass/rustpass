use std::convert::TryFrom;

use crate::{
    api::suites::OuterCipherSuite,
    errors::{
        DatabaseIntegrityError,
        Error
    },
    internal::suites,
    results::Result,
};
use crate::internal::cryptopraphy;

impl OuterCipherSuite {
    pub(crate) fn get_cipher(
        &self,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Box<dyn cryptopraphy::cipher::Cipher>> {
        match self {
            OuterCipherSuite::AES256 => Ok(
                Box::new(
                    cryptopraphy::cipher::AES256Cipher::new(key, iv)?
                )
            ),
            OuterCipherSuite::Twofish => Ok(
                Box::new(
                    cryptopraphy::cipher::TwofishCipher::new(key, iv)?
                )
            ),
            OuterCipherSuite::ChaCha20 => Ok(
                Box::new(
                    cryptopraphy::cipher::ChaCha20Cipher::new(key, iv)?
                )
            ),
        }
    }
}

impl TryFrom<&[u8]> for OuterCipherSuite {
    type Error = Error;
    fn try_from(v: &[u8]) -> Result<OuterCipherSuite> {
        if v == suites::CIPHERSUITE_AES256 {
            Ok(OuterCipherSuite::AES256)
        } else if v == suites::CIPHERSUITE_TWOFISH {
            Ok(OuterCipherSuite::Twofish)
        } else if v == suites::CIPHERSUITE_CHACHA20 {
            Ok(OuterCipherSuite::ChaCha20)
        } else {
            Err(DatabaseIntegrityError::InvalidOuterCipherID { cid: v.to_vec() }.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use spectral::prelude::*;

    use super::*;

    #[test]
    fn test_encrypt_decrypt_aes256_suite_expect_success() {
        let key = [23u8; 32];
        let iv = [42u8; 16];
        let plaintext = "This is my plaintext".as_bytes();

        let suite = OuterCipherSuite::AES256;
        let selected_cipher = suite
            .get_cipher(
                key.as_ref(),
                iv.as_ref(),
            );

        let mut cipher_box = selected_cipher.unwrap();

        let ciphertext = cipher_box
            .encrypt(plaintext)
            .unwrap();

        assert_that(&ciphertext).is_not_equal_to(plaintext.to_vec());

        let deciphered_plaintext = cipher_box
            .decrypt(ciphertext.as_ref());

        assert_that(&deciphered_plaintext)
            .is_ok()
            .is_equal_to(plaintext.to_vec());
    }

    #[test]
    fn test_encrypt_decrypt_aes256_suite_expect_wrong_key() {
        let key = [23u8; 7];
        let iv = [42u8; 16];
        let plaintext = "This is my plaintext".as_bytes();

        let suite = OuterCipherSuite::AES256;
        let selected_cipher = suite
            .get_cipher(
                key.as_ref(),
                iv.as_ref(),
            );

        let mut cipher_box = selected_cipher.unwrap();

        let ciphertext = cipher_box.encrypt(plaintext);

        assert_that(&ciphertext).is_err();
    }

    #[test]
    fn test_encrypt_decrypt_aes256_suite_expect_wrong_iv() {
        let key = [23u8; 32];
        let iv = [42u8; 3];
        let plaintext = "This is my plaintext".as_bytes();

        let suite = OuterCipherSuite::AES256;
        let selected_cipher = suite
            .get_cipher(
                key.as_ref(),
                iv.as_ref(),
            );

        let mut cipher_box = selected_cipher.unwrap();

        let ciphertext = cipher_box.encrypt(plaintext);

        assert_that(&ciphertext).is_err();
    }

    #[test]
    fn test_encrypt_decrypt_aes256_suite_expect_invalid_decrypt() {
        let encrypt_key = [0u8; 32];
        let encrypt_iv = [0u8; 16];

        let decrypt_key = [1u8;32];
        let decrypt_iv = [0u8;16];

        let plaintext = "This is my plaintext".as_bytes();

        let suite = OuterCipherSuite::AES256;

        // setup encryption
        let selected_encrypt_cipher = suite
            .get_cipher(
                encrypt_key.as_ref(),
                encrypt_iv.as_ref(),
            );

        let mut encrypt_box = selected_encrypt_cipher.unwrap();

        let ciphertext = encrypt_box
            .encrypt(plaintext)
            .unwrap();

        assert_that(&ciphertext).is_not_equal_to(plaintext.to_vec());

        // setup decryption
        let select_decrypt_cipher = suite
            .get_cipher(
                decrypt_key.as_ref(),
                decrypt_iv.as_ref()
            );

        let mut decrypt_box = select_decrypt_cipher.unwrap();

        let deciphered_plaintext = decrypt_box
            .decrypt(ciphertext.as_ref());

        assert_that(&deciphered_plaintext)
            .is_err();
    }

    #[test]
    fn test_encrypt_decrypt_twofish_suite_expect_success() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let plaintext = "This is my plaintext".as_bytes();

        let suite = OuterCipherSuite::Twofish;

        let selected_cipher = suite
            .get_cipher(
                key.as_ref(),
                iv.as_ref(),
            );

        let mut cipher_box = selected_cipher.unwrap();

        let ciphertext = cipher_box
            .encrypt(plaintext)
            .unwrap();

        assert_that(&ciphertext).is_not_equal_to(plaintext.to_vec());

        let deciphered_plaintext = cipher_box
            .decrypt(ciphertext.as_ref());

        assert_that(&deciphered_plaintext)
            .is_ok()
            .is_equal_to(plaintext.to_vec());
    }

    #[test]
    fn test_encrypt_decrypt_twofish_suite_expect_wrong_key() {
        let key = [23u8; 7];
        let iv = [42u8; 16];
        let plaintext = "This is my plaintext".as_bytes();

        let suite = OuterCipherSuite::Twofish;
        let selected_cipher = suite
            .get_cipher(
                key.as_ref(),
                iv.as_ref(),
            );

        let mut cipher_box = selected_cipher.unwrap();

        let ciphertext = cipher_box.encrypt(plaintext);

        assert_that(&ciphertext).is_err();
    }

    #[test]
    fn test_encrypt_decrypt_twofish_suite_expect_wrong_iv() {
        let key = [23u8; 32];
        let iv = [42u8; 3];
        let plaintext = "This is my plaintext".as_bytes();

        let suite = OuterCipherSuite::Twofish;
        let selected_cipher = suite
            .get_cipher(
                key.as_ref(),
                iv.as_ref(),
            );

        let mut cipher_box = selected_cipher.unwrap();

        let ciphertext = cipher_box.encrypt(plaintext);

        assert_that(&ciphertext).is_err();
    }

    #[test]
    fn test_encrypt_decrypt_chacha20_suite_expect_success() {
        let key = [23u8; 32];
        let iv = [42u8; 12];
        let plaintext = "This is my plaintext".as_bytes().to_vec();

        let suite = OuterCipherSuite::ChaCha20;

        let selected_encrypt_cipher = suite
            .get_cipher(
                key.as_ref(),
                iv.as_ref(),
            );

        let mut encrypt_cipher_box = selected_encrypt_cipher.unwrap();

        let ciphertext = encrypt_cipher_box
            .encrypt(plaintext.as_ref())
            .unwrap();

        assert_that(&ciphertext)
            .is_not_equal_to(plaintext.to_vec());


        // reinitialize the cipher - reset the internal state

        let selected_decrypt_cipher = suite
            .get_cipher(
                key.as_ref(),
                iv.as_ref(),
            );

        let mut decrypt_cipher_box = selected_decrypt_cipher.unwrap();

        let deciphered_plaintext = decrypt_cipher_box
            .decrypt(ciphertext.as_ref());

        assert_that(&deciphered_plaintext)
            .is_ok()
            .is_equal_to(plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_chacha20_suite_expect_invalid_nonce() {
        let key = [0u8; 32];
        let iv = [0u8; 0];

        let plaintext = "This is my plaintext".as_bytes();

        let suite = OuterCipherSuite::ChaCha20;

        let selected_cipher = suite
            .get_cipher(
                key.as_ref(),
                iv.as_ref(),
            );

        assert_that(
            &selected_cipher.is_err()
        ).is_false();

        let mut cipher_box = selected_cipher.unwrap();
        let result = cipher_box.encrypt(plaintext);

        assert_that(&result)
            .is_err();
    }

    #[test]
    fn test_encrypt_decrypt_chacha20_suite_expect_invalid_key() {
        let key = [0u8; 16];
        let iv = [0u8; 0];

        let plaintext = "This is my plaintext".as_bytes();

        let suite = OuterCipherSuite::ChaCha20;

        let selected_cipher = suite
            .get_cipher(
                key.as_ref(),
                iv.as_ref(),
            );

        assert_that(
            &selected_cipher.is_err()
        ).is_false();

        let mut cipher = selected_cipher.unwrap();

        let result = cipher.encrypt(plaintext);

        assert_that(
            &result
        )
            .is_err();
    }

    #[test]
    fn test_encrypt_decrypt_chacha20_suite_expect_invalid_decrypt() {
        let encrypt_key = [0u8; 32];
        let encrypt_iv = [0u8; 12];

        let decrypt_key = [1u8;32];
        let decrypt_iv = [23u8;12];

        let plaintext = "This is my plaintext".as_bytes();

        let suite = OuterCipherSuite::ChaCha20;

        // setup encryption
        let selected_encrypt_cipher = suite
            .get_cipher(
                encrypt_key.as_ref(),
                encrypt_iv.as_ref(),
            );

        let mut encrypt_box = selected_encrypt_cipher.unwrap();

        let ciphertext = encrypt_box
            .encrypt(plaintext)
            .unwrap();

        assert_that(&ciphertext).is_not_equal_to(plaintext.to_vec());

        // setup decryption
        let select_decrypt_cipher = suite
            .get_cipher(
                decrypt_key.as_ref(),
                decrypt_iv.as_ref()
            );

        let mut decrypt_box = select_decrypt_cipher.unwrap();

        let deciphered_plaintext = decrypt_box
            .decrypt(ciphertext.as_ref());

        assert_that(&deciphered_plaintext)
            .is_ok()
            .is_not_equal_to(plaintext.to_vec());
    }
}
