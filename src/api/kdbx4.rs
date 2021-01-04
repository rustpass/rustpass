use super::{
    compression::Compression,
    suites::{
        InnerCipherSuite,
        KdfSettings,
        OuterCipherSuite,
    },
    traits::Sizable
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

impl Sizable for KDBX4Header {
    fn size_in_bytes(&self) -> usize {
        std::mem::size_of::<u32>()
        + std::mem::size_of::<u16>()
        + std::mem::size_of::<u16>()
        + std::mem::size_of::<OuterCipherSuite>()
        + std::mem::size_of::<Compression>()
        + self.master_seed.len()
        + self.outer_iv.len()
        + self.kdf.size()
    }
}

#[derive(Debug)]
pub struct KDBX4InnerHeader {
    pub(crate) inner_random_stream: InnerCipherSuite,
    pub(crate) inner_random_stream_key: Vec<u8>,
    pub(crate) binaries: Vec<BinaryAttachment>,
    pub(crate) body_start: usize,
}

impl Sizable for KDBX4InnerHeader {
    fn size_in_bytes(&self) -> usize {
        let mut res = std::mem::size_of::<InnerCipherSuite>()
        + self.inner_random_stream_key.len();
        for ref x in self.binaries.iter() {
            res += x.size();
        }
        res

    }
}

#[derive(Debug)]
pub struct BinaryAttachment {
    flags: u8,
    content: Vec<u8>,
}

impl BinaryAttachment {
    pub(crate) fn new(flags: u8, content: &[u8]) -> Self {
        Self {
            flags,
            content: content.to_vec()
        }
    }
}

impl Sizable for BinaryAttachment {
    fn size_in_bytes(&self) -> usize {
        std::mem::size_of::<u8>() * (
            1 + self.content.len()
        )
    }
}
