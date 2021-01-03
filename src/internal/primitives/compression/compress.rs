use crate::results::Result;

use flate2::{
    Compression,
    write::GzEncoder,
};

use std::io::Write;

pub trait Compress {
    fn compress(&self, in_buffer: &[u8], level: u32) -> Result<Vec<u8>>;
}

pub struct NoCompression;

impl Compress for NoCompression {
    fn compress(&self, in_buffer: &[u8], _level: u32) -> Result<Vec<u8>> {
        Ok(in_buffer.to_vec())
    }
}

pub struct GZipCompression;

impl Compress for GZipCompression {
    fn compress(&self, in_buffer: &[u8], level: u32) -> Result<Vec<u8>> {
        let res = Vec::new();
        let mut encoder = GzEncoder::new(res, Compression::new(level));
        encoder.write(in_buffer)?;
        Ok(encoder.finish()?)
    }
}

