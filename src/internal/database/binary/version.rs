use crate::{
    errors::DatabaseIntegrityError,
    results::Result,
};

use byteorder::{
    ByteOrder,
    LittleEndian,
};

const KDBX_IDENTIFIER: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];

pub fn get_kdbx_version(data: &[u8]) -> Result<(u32, u16, u16)> {
    if data[0..4] != KDBX_IDENTIFIER {
        return Err(DatabaseIntegrityError::InvalidKDBXIdentifier.into());
    }

    let version = LittleEndian::read_u32(&data[4..8]);
    let file_minor_version = LittleEndian::read_u16(&data[8..10]);
    let file_major_version = LittleEndian::read_u16(&data[10..12]);

    Ok((version, file_major_version, file_minor_version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_get_kdbx_version_invalid() {
        let mut bytes = vec![0x00, 0x00, 0x00, 0x00]; // invalid magic bytes
        bytes.extend_from_slice(&[
            0x65, 0xfb, 0x4b, 0xb5,
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00
        ]);

        let result = get_kdbx_version(bytes.as_ref());
        assert_that(&result)
            .is_err();
    }

    #[test]
    fn test_get_kdbx_version_kdb() {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(KDBX_IDENTIFIER.as_ref());
        bytes.extend_from_slice(&[
            0x65, 0xfb, 0x4b, 0xb5,
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00
        ]);

        let result = get_kdbx_version(bytes.as_ref());

        let (version, file_major_version, file_minor_version) =
            assert_that(&result)
                .is_ok()
                .subject;
        assert_eq!(*version, 0xb54bfb65);
        assert_eq!(*file_major_version, 0x0);
        assert_eq!(*file_minor_version, 0x0);
    }

    #[test]
    fn test_get_kdbx_version_kdbx3() {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(KDBX_IDENTIFIER.as_ref());
        bytes.extend_from_slice(&[
            0x67, 0xfb, 0x4b, 0xb5,
            0x01, 0x00, 0x03, 0x00
        ]);

        let result = get_kdbx_version(bytes.as_ref());

        let (version, file_major_version, file_minor_version) =
            assert_that(&result)
                .is_ok()
                .subject;
        assert_eq!(*version, 0xb54bfb67);
        assert_eq!(*file_major_version, 0x0003);
        assert_eq!(*file_minor_version, 0x0001);
    }

    #[test]
    fn test_get_kdbx_version_kdbx4() {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(KDBX_IDENTIFIER.as_ref());
        bytes.extend_from_slice(&[
            0x67, 0xfb, 0x4b, 0xb5,
            0x00, 0x00, 0x04, 0x00
        ]);

        let result = get_kdbx_version(bytes.as_ref());

        let (version, file_major_version, file_minor_version) =
            assert_that(&result)
                .is_ok()
                .subject;
        assert_eq!(*version, 0xb54bfb67);
        assert_eq!(*file_major_version, 0x0004);
        assert_eq!(*file_minor_version, 0x0000);
    }
}
