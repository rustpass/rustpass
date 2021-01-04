use super::{
    Cipher,
    Decrypt,
    Encrypt,
};

use crate::{
    errors::{
        CryptoError,
        DatabaseIntegrityError,
        Error
    },
    results::Result,
};

use aes::Aes256;

use block_modes::{
    BlockMode,
    Cbc,
    block_padding::Pkcs7,
};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;


#[derive(Debug)]
pub struct AES256Cipher {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl AES256Cipher {
    pub fn new(
        key: &[u8],
        iv: &[u8],
    ) -> Result<Self> {
        Ok(
            AES256Cipher {
                key: Vec::from(key),
                iv: Vec::from(iv),
            }
        )
    }
}

impl Decrypt for AES256Cipher {

    #[inline(always)]
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Cbc::new_var(&self.key, &self.iv)
            .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

        let mut buffer = ciphertext.to_vec();
        Ok(
            cipher
            .decrypt_vec(&mut buffer)
            .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?
        )
    }
}

impl Encrypt for AES256Cipher {

    #[inline(always)]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Cbc::new_var(&self.key, &self.iv)
            .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

        let mut buffer = plaintext.to_vec();
        Ok(
            cipher.encrypt_vec(&mut buffer)
        )
    }
}

impl Cipher for AES256Cipher {}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let iv = [1u8; 16];

        let plaintext = "this is a simple plaintext";

        let encrypt_algo = AES256Cipher::new(key.as_ref(), iv.as_ref());

        let encrypted = encrypt_algo
            .unwrap()
            .encrypt(
                plaintext.as_bytes()
            );

        assert_that(&encrypted)
            .is_ok();


        let decrypt_algo = AES256Cipher::new(key.as_ref(), iv.as_ref());

        let decrypted = decrypt_algo
            .unwrap()
            .decrypt(
                encrypted.unwrap().as_ref()
            );

        assert_that(&decrypted)
            .is_ok()
            .is_equal_to(plaintext.as_bytes().to_vec());
    }
}
