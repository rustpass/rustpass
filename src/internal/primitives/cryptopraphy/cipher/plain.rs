use super::{
    Cipher,
    Decrypt,
    Encrypt,
};

use crate::results::Result;

#[derive(Debug)]
pub struct PlainCipher;

impl PlainCipher {
    #[allow(dead_code)]
    pub fn new(_: &[u8], _: &[u8]) -> Result<Self> {
        Ok(PlainCipher)
    }

    pub fn with_key(_: &[u8]) -> Result<Self> {
        Ok(PlainCipher)
    }
}

impl Decrypt for PlainCipher {
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::from(ciphertext))
    }
}

impl Encrypt for PlainCipher {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> { Ok(Vec::from(plaintext)) }
}

impl Cipher for PlainCipher {}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let iv = [1u8; 12];

        let plaintext = "this is a simple plaintext";

        let encrypt_algo = PlainCipher::new(key.as_ref(), iv.as_ref());

        let encrypted = encrypt_algo
            .unwrap()
            .encrypt(
                plaintext.as_bytes()
            );

        assert_that(&encrypted)
            .is_ok();


        let decrypt_algo = PlainCipher::new(key.as_ref(), iv.as_ref());

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
}
