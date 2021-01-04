mod aes256;
pub(crate) use self::aes256::AES256Cipher;

mod chacha20;
pub(crate) use self::chacha20::ChaCha20Cipher;

mod salsa20;
pub(crate) use self::salsa20::Salsa20Cipher;

mod plain;
pub(crate) use plain::PlainCipher;

mod twofish;
pub(crate) use self::twofish::TwofishCipher;

pub(crate) use crate::{
    errors::Error,
    results::Result,
};


pub(crate) trait Encrypt {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>>;
}

pub(crate) trait Decrypt {
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

pub(crate) trait Cipher: Encrypt + Decrypt {}
