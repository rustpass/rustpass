use super::{
    compression::Compression,
    suites::{
        InnerCipherSuite,
        KdfSettings,
        OuterCipherSuite,
    }
};

#[derive(Debug)]
pub struct KDBX4Header {
    pub version: u32,
    pub file_major_version: u16,
    pub file_minor_version: u16,
    pub outer_cipher: OuterCipherSuite,
    pub compression: Compression,
    pub(crate) master_seed: Vec<u8>,
    pub(crate) outer_iv: Vec<u8>,
    pub kdf: KdfSettings,
    pub body_start: usize,
}

#[derive(Debug)]
pub struct KDBX4InnerHeader {
    pub(crate) inner_random_stream: InnerCipherSuite,
    pub(crate) inner_random_stream_key: Vec<u8>,
    pub(crate) binaries: Vec<BinaryAttachment>,
    pub(crate) body_start: usize,
}

#[derive(Debug)]
pub struct BinaryAttachment {
    flags: u8,
    content: Vec<u8>,
}

impl BinaryAttachment {
    pub(crate) fn new(flags: u8, content: &[u8]) -> Self {
        Self {
            flags: flags,
            content: content.to_vec()
        }
    }
}
