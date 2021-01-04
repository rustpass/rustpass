use crate::{
    internal::{
        primitives::{
            cryptopraphy,
            variant_dictionary,
        },
        suites::{
            KDF_AES_KDBX3,
            KDF_AES_KDBX4,
            KDF_ARGON2
        }
    },
    errors::{
        DatabaseIntegrityError,
        Error
    },
    results::Result

};

use std::convert::TryFrom;

#[derive(Debug)]
pub enum KdfSettings {
    Aes {
        seed: Vec<u8>,
        rounds: u64,
    },
    Argon2 {
        memory: u64,
        salt: Vec<u8>,
        iterations: u64,
        parallelism: u32,
        version: argon2::Version,
    },
}

impl KdfSettings {
    pub(crate) fn get_kdf(&self) -> Box<dyn cryptopraphy::kdf::Kdf> {
        match self {
            KdfSettings::Aes { seed, rounds } => {
                Box::new(
                    cryptopraphy::kdf::AesKdf::new(
                        seed.as_ref(),
                        *rounds,
                    )
                )
            }
            KdfSettings::Argon2 {
                memory,
                salt,
                iterations,
                parallelism,
                version,
            } => {
                Box::new(
                    cryptopraphy::kdf::Argon2Kdf {
                        memory: *memory,
                        salt: salt.clone(),
                        iterations: *iterations,
                        parallelism: *parallelism,
                        version: *version,
                    }
                )
            }
        }
    }
}

impl TryFrom<variant_dictionary::VariantDictionary> for KdfSettings {
    type Error = Error;

    fn try_from(vd: variant_dictionary::VariantDictionary) -> Result<KdfSettings> {
        let uuid: Vec<u8> = vd.get("$UUID")?;

        if uuid == KDF_ARGON2 {
            let memory: u64 = vd.get("M")?;
            let salt: Vec<u8> = vd.get("S")?;
            let iterations: u64 = vd.get("I")?;
            let parallelism: u32 = vd.get("P")?;
            let version: u32 = vd.get("V")?;

            let version = match version {
                0x10 => argon2::Version::Version10,
                0x13 => argon2::Version::Version13,
                _ => {
                    return Err(Error::from(DatabaseIntegrityError::InvalidKDFVersion {
                        version,
                    }));
                }
            };

            Ok(
                KdfSettings::Argon2 {
                    memory,
                    salt,
                    iterations,
                    parallelism,
                    version,
                }
            )
        } else if uuid == KDF_AES_KDBX4 || uuid == KDF_AES_KDBX3 {
            let rounds: u64 = vd.get("R")?;
            let seed: Vec<u8> = vd.get("S")?;

            Ok(KdfSettings::Aes { rounds, seed })
        } else {
            Err(DatabaseIntegrityError::InvalidKDFUUID { uuid }.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;
    use hmac::crypto_mac::generic_array::{
        GenericArray,
        typenum,
    };

    #[test]
    fn test_argon2_settings() {
        let compose_key = GenericArray::<u8, typenum::U32>::from([46u8; 32]);

        let kdf = KdfSettings::Argon2 {
            memory: 1024 * 1024,
            salt: [23u8; 32].to_vec(),
            iterations: 128,
            parallelism: 4,
            version: argon2::Version::Version13,
        }.get_kdf();

        let result = kdf.transform_key(&compose_key);

        assert_that(&result)
            .is_ok();
    }

    #[test]
    fn test_aeskdf_settings() {
        let compose_key = GenericArray::<u8, typenum::U32>::from([46u8; 32]);

        let kdf = KdfSettings::Aes {
            seed: [42u8; 32].to_vec(),
            rounds: 128,
        }.get_kdf();

        let result = kdf.transform_key(&compose_key);

        assert_that(&result)
            .is_ok();
    }
}
