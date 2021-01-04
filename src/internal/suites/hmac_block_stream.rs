use crate::{
    internal::primitives::cryptopraphy,
    errors::DatabaseIntegrityError,
    results::Result,
};

use byteorder::{
    ByteOrder,
    LittleEndian,
};

use generic_array::{
    GenericArray,
    typenum,
};

pub fn read_hmac_block_stream(
    data: &[u8],
    key: &GenericArray<u8, typenum::U64>,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();

    let mut pos = 0;
    let mut block_index = 0;

    while pos < data.len() {
        let hmac = &data[pos..(pos + 32)];
        let size_bytes = &data[(pos + 32)..(pos + 36)];
        let size = LittleEndian::read_u32(size_bytes) as usize;
        let block = &data[(pos + 36)..(pos + 36 + size)];

        let hmac_block_key = get_hmac_block_key(block_index, key)?;

        let mut block_index_buf = [0u8; 8];
        LittleEndian::write_u64(
            &mut block_index_buf,
            block_index as u64,
        );

        if hmac != cryptopraphy::hmac(
            &[
                &block_index_buf,
                size_bytes,
                &block
            ],
            &hmac_block_key,
        )?
            .as_slice()
        {
            return Err(DatabaseIntegrityError::BlockHashMismatch { block_index }.into());
        }

        pos += 36 + size;
        block_index += 1;

        out.extend_from_slice(block);
    }

    Ok(out)
}

pub fn create_hmac_block_stream(
    data: &[u8],
    size: usize,
    key: &GenericArray<u8, typenum::U64>,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();

    let mut pos = 0;
    let mut block_index = 0;

    while pos < data.len() {
        let mut block = &data[pos..(pos + size)];

        let mut block_size = [0u8; 4];
        LittleEndian::write_u32(
            &mut block_size,
            size as u32,
        );

        let mut block_index_buf = [0u8; 8];
        LittleEndian::write_u64(
            &mut block_index_buf,
            block_index as u64,
        );

        let hmac_block_key = get_hmac_block_key(block_index, key)?;
        let block_hmac = cryptopraphy::hmac(
            &[
                &block_index_buf,
                block_size.as_ref(),
                &block
            ],
            &hmac_block_key,
        )?;

        pos += size;
        block_index += 1;

        out.extend_from_slice(block_hmac.as_slice());
        out.extend_from_slice(&(size as u32).to_le_bytes());
        out.extend_from_slice(block);
    }

    Ok(out)
}

pub fn get_hmac_block_key(
    block_index: usize,
    key: &GenericArray<u8, typenum::U64>,
) -> Result<GenericArray<u8, typenum::U64>> {
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, block_index as u64);
    cryptopraphy::sha512(&[&buf, key])
}

#[cfg(test)]
mod tests {
    use super::*;
    use extfmt::{Hexlify, AsHexdump};
    use hex;
    use spectral::prelude::*;

    const DATA_VEC_SHORT: &[u8] = &[
        0x01, 0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    const DATA_VEC_LONG: &[u8] = &[
        0x01, 0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_create_hmac_block_stream_fixture() {
        let key = GenericArray::from_slice(&[0u8; 64]);

        let result = create_hmac_block_stream(DATA_VEC_SHORT, 64, &key);

        let subject = assert_that(&result)
            .is_ok()
            .subject;

        assert_that(&Hexlify(subject.as_slice())
            .to_string()
        ).matches(|subj| {
            subj.starts_with(
                "ed09b0f3548d00efa7c184297e23b034c6a60560230a6f33dd055f4ddee9b0fe"
            )
        });

        assert_that(&subject.len())
            .is_equal_to(100);
    }

    #[test]
    fn test_create_hmac_block_stream_long_data_fixture() {
        let key = GenericArray::from_slice(&[0u8; 64]);

        let result = create_hmac_block_stream(DATA_VEC_LONG, 64, &key);

        let subject = assert_that(&result)
            .is_ok()
            .subject;

        assert_that(&Hexlify(subject.as_slice())
            .to_string()
        ).matches(|subj| {
            subj.starts_with(
                "ed09b0f3548d00efa7c184297e23b034c6a60560230a6f33dd055f4ddee9b0fe"
            ) && subj.contains(
                "ce5956b8eaf46c20f5e22714e203e4a742c7055ec0f58e3387997049cd72d379"
            )
        });
    }

    #[test]
    fn test_read_hmac_block_stream_fixture() {
        let data = hex::decode(
            "ed09b0f3548d00efa7c184297e23b034c6a60560230a6f33dd055f4ddee9b0fe4000000001020203040506070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ce5956b8eaf46c20f5e22714e203e4a742c7055ec0f58e3387997049cd72d3794000000001020203040506070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
        let key = GenericArray::from_slice(&[0u8; 64]);

        let result = read_hmac_block_stream(
            data.unwrap().as_slice(),
            &key,
        );

        let subj = assert_that(&result)
            .is_ok()
            .is_equal_to(DATA_VEC_LONG.to_vec());
    }
}
