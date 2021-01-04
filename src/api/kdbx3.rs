use super::{
    compression::Compression,
    suites::{
        OuterCipherSuite,
        InnerCipherSuite
    },
    traits::Sizable
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
    pub outer_iv: Vec<u8>, // ENCRYPTIONIV
    pub protected_stream_key: Vec<u8>,
    pub stream_start: Vec<u8>,
    pub inner_cipher: InnerCipherSuite,
    pub body_start: usize,
}

impl Sizable for KDBX3Header {
    fn size_in_bytes(&self) -> usize {
        std::mem::size_of::<u32>()
            + std::mem::size_of::<u16>()
            + std::mem::size_of::<u16>()
            + std::mem::size_of::<OuterCipherSuite>()
            + std::mem::size_of::<Compression>()
            + self.master_seed.len()
            + self.transform_seed.len()
            + std::mem::size_of::<u64>()
            + self.outer_iv.len()
            + self.protected_stream_key.len()
            + self.stream_start.len()
            + std::mem::size_of::<InnerCipherSuite>()
    }
}

#[cfg(test)]
mod tests {

}
