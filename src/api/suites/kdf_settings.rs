use crate::api::traits::Sizable;

#[derive(Debug, Clone)]
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
        version: argon2::Version, // todo: this should be supplied via our own api
    },
}

impl Sizable for KdfSettings {
    fn size_in_bytes(&self) -> usize {
        match self {
            KdfSettings::Aes {
                seed,
                ..
            } => {
                seed.len()
                    + std::mem::size_of::<u64>()
            }
            KdfSettings::Argon2 {
                memory,
                salt,
                ..
            } => {
                std::mem::size_of::<u64>()
                    + salt.len()
                    + std::mem::size_of::<u64>()
                    + std::mem::size_of::<u32>()
                    + std::mem::size_of::<argon2::Version>()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::random::generate_random_bytes;

    #[test]
    fn test_aes_kdf_settings_has_size_40() {
        let settings = KdfSettings::Aes {
            rounds: 1_000_000,
            seed: generate_random_bytes(32).to_vec()
        };
        let size = settings.size();

        assert_eq!(size, 40);
    }

    #[test]
    fn test_aes_kdf_settings_has_size_20() {
        let settings = KdfSettings::Aes {
            rounds: 1_000_000,
            seed: generate_random_bytes(12).to_vec()
        };
        let size = settings.size();

        assert_eq!(size, 20);
    }

    #[test]
    fn test_argon2_kdf_settings_has_size_53() {
        let settings = KdfSettings::Argon2 {
            memory: 128_000,
            salt: generate_random_bytes(32).to_vec(),
            iterations: 2_000,
            parallelism: 2,
            version: argon2::Version::Version13
        };

        let size = settings.size();

        assert_eq!(size, 53);
    }
}
