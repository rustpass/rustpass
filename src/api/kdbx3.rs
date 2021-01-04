use super::{
    compression::Compression,
    suites::{
        OuterCipherSuite,
        InnerCipherSuite
    }
};

#[derive(Debug)]
pub struct KDBX3Header {
    pub version: u32,
    pub file_major_version: u16,
    pub file_minor_version: u16,
    pub outer_cipher: OuterCipherSuite,
    pub compression: Compression,
    pub master_seed: Vec<u8>,
    pub transform_seed: Vec<u8>,
    pub transform_rounds: u64,
    pub outer_iv: Vec<u8>,
    pub protected_stream_key: Vec<u8>,
    pub stream_start: Vec<u8>,
    pub inner_cipher: InnerCipherSuite,
    pub body_start: usize,
}
