use crate::{
    api::{
        compression::Compression,
        suites::{
            InnerCipherSuite,
            KdfSettings,
            OuterCipherSuite,
        }
    },
    internal::random::generate_random_bytes
};

#[derive(Debug)]
pub struct Settings {
    compression: Compression,
    transform_rounds: u64,
    kdf_settings: KdfSettings,
    outer_cipher_suite: OuterCipherSuite,
    inner_cipher_suite: Option<InnerCipherSuite>
}

impl Settings {

    pub fn for_kdbx3(
        compression: Compression,
        transform_rounds: u64,
        outer_cipher_suite: OuterCipherSuite,
        rounds: u64,
    ) -> Self {
        Self {
            compression,
            transform_rounds,
            kdf_settings: KdfSettings::Aes {
                seed: generate_random_bytes(32),
                rounds
            },
            outer_cipher_suite,
            inner_cipher_suite: None
        }
    }

    pub fn for_kdbx4(
        compression: Compression,
        transform_rounds: u64,
        kdf_settings: KdfSettings,
        outer_cipher_suite: OuterCipherSuite,
        inner_cipher_suite: InnerCipherSuite
    ) -> Self {
        Self {
            compression,
            transform_rounds,
            kdf_settings,
            outer_cipher_suite,
            inner_cipher_suite: Some(inner_cipher_suite)
        }
    }

    pub fn compression(&self) -> Compression {
        self.compression.clone()
    }

    pub fn transform_rounds(&self) -> u64 {
        self.transform_rounds
    }

    pub fn kdf_settings(&self) -> KdfSettings {
        self.kdf_settings.clone()
    }

    pub fn outer_cipher_suite(&self) -> OuterCipherSuite {
        self.outer_cipher_suite.clone()
    }

    pub fn inner_cipher_suite(&self) -> Option<InnerCipherSuite> {
        self.inner_cipher_suite.clone()
    }
}
