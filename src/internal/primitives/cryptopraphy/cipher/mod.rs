mod aes256;
pub use self::aes256::AES256Cipher;

mod chacha20;
pub use self::chacha20::ChaCha20Cipher;

mod salsa20;
pub use self::salsa20::Salsa20Cipher;

mod plain;
pub use plain::PlainCipher;

mod twofish;
pub use self::twofish::TwofishCipher;

pub use crate::{
    errors::{
        CryptoError,
        DatabaseIntegrityError,
        Error,
    },
    results::Result,
};


pub trait Encrypt {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>>;
}

pub trait Decrypt {
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

pub trait Cipher: Encrypt + Decrypt {}
