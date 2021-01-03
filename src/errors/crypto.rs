use block_modes;
use hmac;
use cipher::stream::InvalidKeyNonceLength;

#[derive(Debug)]
pub enum CryptoError {
    Argon2 {
        e: argon2::Error,
    },
    InvalidKeyLength {
        e: hmac::crypto_mac::InvalidKeyLength,
    },
    InvalidKeyIvLength {
        e: block_modes::InvalidKeyIvLength,
    },
    InvalidKeyNonceLength {
        e: InvalidKeyNonceLength,
    },
    BlockMode {
        e: block_modes::BlockModeError,
    },
}

impl std::fmt::Display for CryptoError {
    #[cfg_attr(tarpaulin, skip)]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Crypto Error: {}",
            match self {
                CryptoError::Argon2 { e } => format!("Problem deriving key with Argon2: {}", e),
                CryptoError::InvalidKeyIvLength { e } => format!("Invalid key / IV length: {}", e),
                CryptoError::InvalidKeyLength { e } => format!("Invalid key length: {}", e),
                CryptoError::InvalidKeyNonceLength { e } => {
                    format!("Invalid key / nonce length: {}", e)
                }
                CryptoError::BlockMode { e } => format!("Block mode error: {}", e),
            }
        )
    }
}

impl std::error::Error for CryptoError {
    #[cfg_attr(tarpaulin, skip)]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoError::Argon2 { e } => Some(e),
            CryptoError::InvalidKeyIvLength { e } => Some(e),
            CryptoError::InvalidKeyNonceLength { .. } => None, // TODO pass this through once e implements Error
            CryptoError::InvalidKeyLength { .. } => None, // TODO pass this through once e implements Error
            CryptoError::BlockMode { e } => Some(e),
        }
    }
}

impl From<argon2::Error> for CryptoError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: argon2::Error) -> Self {
        CryptoError::Argon2 { e }
    }
}

impl From<hmac::crypto_mac::InvalidKeyLength> for CryptoError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: hmac::crypto_mac::InvalidKeyLength) -> Self {
        CryptoError::InvalidKeyLength { e }
    }
}

impl From<cipher::stream::InvalidKeyNonceLength> for CryptoError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: cipher::stream::InvalidKeyNonceLength) -> Self {
        CryptoError::InvalidKeyNonceLength { e }
    }
}

impl From<block_modes::InvalidKeyIvLength> for CryptoError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: block_modes::InvalidKeyIvLength) -> Self {
        CryptoError::InvalidKeyIvLength { e }
    }
}

impl From<block_modes::BlockModeError> for CryptoError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: block_modes::BlockModeError) -> Self {
        CryptoError::BlockMode { e }
    }
}
