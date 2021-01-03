use super::{
    Cipher,
    Decrypt,
    Encrypt,
    Result,
    Error,
    DatabaseIntegrityError,
    CryptoError,
};

use block_modes::{
    BlockMode,
    Cbc,
    block_padding::Pkcs7,
};

use twofish::Twofish;

type TwofishCbc = Cbc<Twofish, Pkcs7>;

#[derive(Debug)]
pub struct TwofishCipher {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl TwofishCipher {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        Ok(
            TwofishCipher {
                key: Vec::from(key),
                iv: Vec::from(iv),
            }
        )
    }
}

impl Decrypt for TwofishCipher {
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = TwofishCbc::new_var(&self.key, &self.iv)
            .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

        let mut buf = ciphertext.to_vec();
        Ok(
            cipher
            .decrypt_vec(&mut buf)
            .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?
        )
    }
}

impl Encrypt for TwofishCipher {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = TwofishCbc::new_var(&self.key, &self.iv)
            .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

        let mut buf = plaintext.to_vec();
        Ok(
            cipher
                .encrypt_vec(&mut buf)
        )
    }
}

impl Cipher for TwofishCipher {}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let iv = [1u8; 16];

        let plaintext = "this is a simple plaintext";

        let encrypt_algo = TwofishCipher::new(key.as_ref(), iv.as_ref());

        let encrypted = encrypt_algo
            .unwrap()
            .encrypt(
                plaintext.as_bytes()
            );

        assert_that(&encrypted)
            .is_ok();


        let decrypt_algo = TwofishCipher::new(key.as_ref(), iv.as_ref());

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
