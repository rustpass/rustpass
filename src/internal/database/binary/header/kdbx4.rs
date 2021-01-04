use crate::{
    api::{
        kdbx4::{
            KDBX4Header,
            KDBX4InnerHeader,
            BinaryAttachment
        },
        compression::Compression,
        suites::{
            InnerCipherSuite,
            KdfSettings,
            OuterCipherSuite
        },
        traits::Sizable
    },
    errors::{
        DatabaseIntegrityError,
        Error,
    },
    results::Result,
    internal::{
        database::binary::{
            BlockData,
            BlockId,
            header::block,
            header::constants,
            version::get_kdbx_version,
        },
        primitives::{
            variant_dictionary::{
                FromBytes,
                VariantDictionary
            }
        },
    },
};

use byteorder::{
    ByteOrder,
    LittleEndian,
};

use std::convert::TryFrom;

impl TryFrom<&[u8]> for BinaryAttachment {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        let flags = data[0];
        let content = data[1..].as_ref();

        Ok(BinaryAttachment::new(flags, content))
    }
}

pub(crate) fn read_outer_header(data: &[u8]) -> Result<KDBX4Header> {
    let (version, file_major_version, file_minor_version) = get_kdbx_version(data)?;

    if version != 0xb54b_fb67 || file_major_version != 4 {
        return Err(DatabaseIntegrityError::InvalidKDBXVersion {
            version,
            file_major_version,
            file_minor_version,
        }
            .into());
    }

    let mut outer_cipher: Option<OuterCipherSuite> = None;
    let mut compression: Option<Compression> = None;
    let mut master_seed: Option<Vec<u8>> = None;
    let mut outer_iv: Option<Vec<u8>> = None;
    let mut kdf: Option<KdfSettings> = None;

    let mut pos = 12;

    loop {
        let block = super::super::read::<block::HeaderBlock4>(
            &data[pos..]
        ).unwrap();

        pos += block.size() as usize;

        match block.block_id() {
            constants::DH_BLOCKID_END => {
                break;
            }
            constants::DH_BLOCKID_COMMENT => {
                // intentionally left blank
            }
            constants::DH_BLOCKID_CIPHERID => {
                outer_cipher = Some(
                    OuterCipherSuite::try_from(
                        block.block_data().as_ref()
                    )?
                );
            }
            constants::DH_BLOCKID_COMPRESSIONFLAGS => {
                compression = Some(
                    Compression::try_from(
                        LittleEndian::read_u32(
                            block.block_data().as_ref(),
                        )
                    )?
                );
            }
            constants::DH_BLOCKID_MASTERSEED => {
                master_seed = Some(block.block_data())
            },
            constants::DH_BLOCKID_ENCRYPTIONIV => {
                outer_iv = Some(block.block_data())
            },
            constants::DH_BLOCKID_KDFPARAMETERS => {
                let vd = VariantDictionary::parse(
                    block.block_data().as_ref()
                )?;

                kdf = Some(KdfSettings::try_from(vd)?);
            }
            _ => {
                return Err(
                    DatabaseIntegrityError::InvalidOuterHeaderEntry {
                        entry_type: block.block_id()
                    }.into()
                );
            }
        };
    }

    fn get_or_err<T>(v: Option<T>, err: &str) -> Result<T> {
        v.ok_or_else(|| {
            DatabaseIntegrityError::IncompleteOuterHeader {
                missing_field: err.into(),
            }
                .into()
        })
    }

    let outer_cipher = get_or_err(outer_cipher, "Outer Cipher ID")?;
    let compression = get_or_err(compression, "Compression ID")?;
    let master_seed = get_or_err(master_seed, "Master seed")?;
    let outer_iv = get_or_err(outer_iv, "Outer IV")?;
    let kdf = get_or_err(kdf, "Key Derivation Function Parameters")?;

    Ok(
        KDBX4Header {
            version,
            file_major_version,
            file_minor_version,
            outer_cipher,
            compression,
            master_seed,
            outer_iv,
            kdf,
            body_start: pos,
        }
    )
}

pub(crate) fn read_inner_header(data: &[u8]) -> Result<KDBX4InnerHeader> {
    let mut pos = 0;

    let mut inner_random_stream = None;
    let mut inner_random_stream_key = None;
    let mut binaries = Vec::new();

    loop {
        let entry_type = data[pos];
        let entry_length: usize = LittleEndian::read_u32(&data[pos + 1..(pos + 5)]) as usize;
        let entry_buffer = &data[(pos + 5)..(pos + 5 + entry_length)];

        pos += 5 + entry_length;

        match entry_type {
            constants::DH_INNER_BLOCKID_END => break,
            constants::DH_INNER_BLOCKID_RANDOM_STREAM_ID => {
                inner_random_stream = Some(InnerCipherSuite::try_from(LittleEndian::read_u32(
                    &entry_buffer,
                ))?);
            }
            constants::DH_INNER_BLOCKID_RANDOM_STREAM_KEY => {
                inner_random_stream_key = Some(entry_buffer.to_vec())
            }
            constants::DH_INNER_BLOCKID_BINARY_ATTACHMENT => {
                let binary = BinaryAttachment::try_from(entry_buffer)?;
                binaries.push(binary);
            }
            _ => {
                return Err(DatabaseIntegrityError::InvalidInnerHeaderEntry { entry_type }.into());
            }
        }
    }

    fn get_or_err<T>(v: Option<T>, err: &str) -> Result<T> {
        v.ok_or_else(|| {
            DatabaseIntegrityError::IncompleteInnerHeader {
                missing_field: err.into(),
            }
                .into()
        })
    }

    let inner_random_stream = get_or_err(inner_random_stream, "Inner random stream UUID")?;
    let inner_random_stream_key = get_or_err(inner_random_stream_key, "Inner random stream key")?;

    Ok(
        KDBX4InnerHeader {
            inner_random_stream,
            inner_random_stream_key,
            binaries,
            body_start: pos,
        }
    )
}
