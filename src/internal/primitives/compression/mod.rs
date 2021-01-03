mod compress;
mod decompress;

use crate::{
    errors::{
        DatabaseIntegrityError,
        Error,
    },
    results::{

        Result,
    }
};

use std::convert::TryFrom;

#[derive(Debug)]
pub enum Compression {
    None,
    GZip,
}

impl Compression {
    pub fn get_compression(&self) -> Box<dyn compress::Compress> {
        match self {
            Compression::None => Box::new(compress::NoCompression),
            Compression::GZip => Box::new(compress::GZipCompression),
        }
    }
    pub fn get_decompression(&self) -> Box<dyn decompress::Decompress> {
        match self {
            Compression::None => Box::new(decompress::NoCompression),
            Compression::GZip => Box::new(decompress::GZipCompression),
        }
    }
}

impl TryFrom<u32> for Compression {
    type Error = Error;

    fn try_from(v: u32) -> Result<Compression> {
        match v {
            0 => Ok(Compression::None),
            1 => Ok(Compression::GZip),
            _ => Err(DatabaseIntegrityError::InvalidCompressionSuite { cid: v }.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_no_compress() {
        let compressor = Compression::None.get_compression();
        let decompressor = Compression::None.get_decompression();

        test_compress_decompress(&compressor, &decompressor, 0);
    }

    #[test]
    fn test_compress_deflate() {
        let compressor = Compression::GZip.get_compression();
        let decompressor = Compression::GZip.get_decompression();

        for lvl in 1..9 {
            test_compress_decompress(&compressor, &decompressor, lvl);
        }
    }

    #[test]
    fn test_compress_store() {
        let compressor = Compression::GZip.get_compression();
        let decompressor = Compression::GZip.get_decompression();

        test_compress_decompress(&compressor, &decompressor, 0);
    }

    fn test_compress_decompress(
        compressor: &Box<dyn compress::Compress>,
        decompressor: &Box<dyn decompress::Decompress>,
        lvl: u32,
    ) {
        let buf = [42u8; 32];

        let compressed = compressor.compress(buf.as_ref(), lvl);

        assert_that(&compressed)
            .is_ok();

        let decompressed = decompressor
            .decompress(compressed.unwrap().as_ref());

        assert_that(&decompressed)
            .is_ok()
            .is_equal_to(Vec::from(buf));
    }
}
