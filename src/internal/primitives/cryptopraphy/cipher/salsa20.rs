use super::{
    Cipher,
    Decrypt,
    Encrypt,
    Result,
};

use salsa20::{
    Salsa20,
    cipher::{
        NewStreamCipher,
        StreamCipher,
    }
};
use aes::cipher::generic_array::GenericArray;

#[derive(Debug)]
pub struct Salsa20Cipher {
    key: Vec<u8>,
    iv: Vec<u8>
}

impl Salsa20Cipher {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        Ok(
            Salsa20Cipher {
                key: key.to_vec(),
                iv: iv.to_vec()
            }
        )
    }

    pub fn with_key(key: &[u8]) -> Result<Self> {
        let iv: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
        Self::new(key, iv.as_ref())
    }
}
/*

 */
impl Decrypt for Salsa20Cipher {
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut cipher = Salsa20::new(
            GenericArray::from_slice(self.key.as_slice()),
                GenericArray::from_slice(self.iv.as_slice())
        );
        let mut buffer = Vec::from(ciphertext);
        cipher.decrypt(&mut buffer);
        Ok(buffer)
    }
}

impl Encrypt for Salsa20Cipher {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut cipher = Salsa20::new(
            GenericArray::from_slice(self.key.as_slice()),
            GenericArray::from_slice(self.iv.as_slice())
        );
        let mut buffer = Vec::from(plaintext);
        cipher.encrypt(&mut buffer);
        Ok(buffer)
    }
}

impl Cipher for Salsa20Cipher {}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let iv = [1u8; 8];

        let plaintext = "this is a simple plaintext";

        let encrypt_algo = Salsa20Cipher::new(key.as_ref(), iv.as_ref());

        let encrypted = encrypt_algo
            .unwrap()
            .encrypt(
                plaintext.as_bytes()
            );

        assert_that(&encrypted)
            .is_ok();


        let decrypt_algo = Salsa20Cipher::new(key.as_ref(), iv.as_ref());

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
