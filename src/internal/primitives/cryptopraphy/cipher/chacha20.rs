use super::{
    Cipher,
    Decrypt,
    Encrypt,
    Result,
    Error,
    DatabaseIntegrityError,
    CryptoError,
    super::sha512,
};

use chacha20::ChaCha20;
use cipher::{
    StreamCipher,
    NewStreamCipher
};

#[derive(Debug)]
pub struct ChaCha20Cipher {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl ChaCha20Cipher {

    pub fn new(
        key: &[u8],
        iv: &[u8]
    ) -> Result<Self> {
        Ok(
            ChaCha20Cipher {
                key: key.to_vec(),
                iv: iv.to_vec()
            }
        )
    }

    pub fn with_key(key: &[u8]) -> Result<Self> {
        let iv = sha512(&[key])?;

        let derived_key = &iv[0..32];
        let derived_nonce = &iv[32..44];

        Self::new(derived_key, derived_nonce)
    }
}

impl Decrypt for ChaCha20Cipher {

    #[inline(always)]
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut cipher = ChaCha20::new_var(
            self.key.as_ref(),
            self.iv.as_ref()
        ).map_err(|e| {
            Error::from(
                DatabaseIntegrityError::from(
                    CryptoError::from(e)
                )
            )
        })?;

        let mut buffer = Vec::from(ciphertext);
        cipher.decrypt(&mut buffer);
        Ok(buffer)
    }
}

impl Encrypt for ChaCha20Cipher {

    #[inline(always)]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut cipher = ChaCha20::new_var(
            self.key.as_ref(),
            self.iv.as_ref()
        ).map_err(|e| {
            Error::from(
                DatabaseIntegrityError::from(
                    CryptoError::from(e)
                )
            )
        })?;
        let mut buffer = Vec::from(plaintext);
        cipher.encrypt(&mut buffer);
        Ok(buffer)
    }
}

impl Cipher for ChaCha20Cipher {}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let iv = [1u8; 12];

        let plaintext = "this is a simple plaintext";

        let encrypt_algo = ChaCha20Cipher::new(key.as_ref(), iv.as_ref());

        let encrypted = encrypt_algo
            .unwrap()
            .encrypt(
                plaintext.as_bytes()
            );

        assert_that(&encrypted)
            .is_ok();


        let decrypt_algo = ChaCha20Cipher::new(key.as_ref(), iv.as_ref());

        let decrypted = decrypt_algo
            .unwrap()
            .decrypt(
                encrypted.unwrap().as_ref()
            );

        assert_that(&decrypted)
            .is_ok()
            .matches(|f| {
                f.starts_with(plaintext.as_bytes())
            })
    }

    #[test]
    fn test_encrypt_decrypt_derived_key() {
        let key = [0u8; 32];

        let plaintext = "this is a simple plaintext";

        let encrypt_algo = ChaCha20Cipher::with_key(key.as_ref());

        let encrypted = encrypt_algo
            .unwrap()
            .encrypt(
                plaintext.as_bytes()
            );

        assert_that(&encrypted)
            .is_ok();


        let decrypt_algo = ChaCha20Cipher::with_key(key.as_ref());

        let decrypted = decrypt_algo
            .unwrap()
            .decrypt(
                encrypted.unwrap().as_ref()
            );

        assert_that(&decrypted)
            .is_ok()
            .matches(|f| {
                f.starts_with(plaintext.as_bytes())
            })
    }

    #[test]
    fn test_encrypt_decrypt_not_matching_keys() {
        let key = [0u8; 32];
        let iv = [1u8; 12];

        let plaintext = "this is a simple plaintext".as_bytes().to_vec();

        let encrypt_algo = ChaCha20Cipher::with_key(key.as_ref());

        let encrypted = encrypt_algo
            .unwrap()
            .encrypt(
                plaintext.as_ref()
            );

        assert_that(&encrypted)
            .is_ok();


        let decrypt_algo = ChaCha20Cipher::new(key.as_ref(), iv.as_ref());

        let decrypted = decrypt_algo
            .unwrap()
            .decrypt(encrypted.unwrap().as_ref());

        assert_that(&decrypted)
            .is_ok()
            .is_not_equal_to(plaintext);
    }
}
