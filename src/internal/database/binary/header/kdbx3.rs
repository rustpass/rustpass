use std::convert::TryFrom;

use byteorder::{
    ByteOrder,
    LittleEndian,
};

use crate::{
    errors::DatabaseIntegrityError,
    internal::{
        primitives::compression::Compression,
        suites::{
            InnerCipherSuite,
            OuterCipherSuite,
        },
    },
    results::Result,
};
use crate::internal::database::binary::{
    self,
    BlockData,
    BlockId,
    BlockSize,
    header::block,
    header::constants,
    version::get_kdbx_version,
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

pub(crate) fn read_header(data: &[u8]) -> Result<KDBX3Header> {
    let (version, file_major_version, file_minor_version) = get_kdbx_version(data)?;

    if version != 0xb54b_fb67 || file_major_version != 3 {
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
    let mut transform_seed: Option<Vec<u8>> = None;
    let mut transform_rounds: Option<u64> = None;
    let mut outer_iv: Option<Vec<u8>> = None;
    let mut protected_stream_key: Option<Vec<u8>> = None;
    let mut stream_start: Option<Vec<u8>> = None;
    let mut inner_cipher: Option<InnerCipherSuite> = None;

    // database header
    let mut pos = 12;

    loop {
        let block = binary::read::<block::HeaderBlock3>(
            &data[pos..]
        ).unwrap();

        pos += block.size() as usize;

        match block.block_id() {
            constants::DH_BLOCKID_END => {
                // no more header blocks after this block id
                break;
            }
            constants::DH_BLOCKID_COMMENT => {
                // intentionally left blank
            }
            constants::DH_BLOCKID_CIPHERID => {
                outer_cipher = Some(OuterCipherSuite::try_from(block.block_data().as_ref())?);
            }
            constants::DH_BLOCKID_COMPRESSIONFLAGS => {
                compression = Some(Compression::try_from(LittleEndian::read_u32(
                    &block.block_data(),
                ))?);
            }
            constants::DH_BLOCKID_MASTERSEED => {
                master_seed = Some(block.block_data())
            },
            constants::DH_BLOCKID_TRANSFORMSEED => {
                transform_seed = Some(block.block_data())
            },
            constants::DH_BLOCKID_TRANSFORMROUNDS => {
                transform_rounds = Some(
                    LittleEndian::read_u64(block.block_data().as_ref())
                )
            },
            constants::DH_BLOCKID_ENCRYPTIONIV => outer_iv = {
                Some(block.block_data())
            },
            constants::DH_BLOCKID_PROTECTEDSTREAMKEY => {
                protected_stream_key = Some(block.block_data())
            },
            constants::DH_BLOCKID_STREAMSTARTBYTES => {
                stream_start = Some(block.block_data())
            },
            constants::DH_BLOCKID_INNERRANDOMSTREAMID => {
                inner_cipher = Some(
                    InnerCipherSuite::try_from(
                        LittleEndian::read_u32(
                            block.block_data().as_ref(),
                        )
                    )?
                );
            }
            _ => {
                return Err(DatabaseIntegrityError::InvalidOuterHeaderEntry { entry_type: block.block_id() }.into());
            }
        };
    }

    // at this point, the header needs to be fully defined - unwrap options and return errors if
    // something is missing

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
    let transform_seed = get_or_err(transform_seed, "Transform seed")?;
    let transform_rounds = get_or_err(transform_rounds, "Number of transformation rounds")?;
    let outer_iv = get_or_err(outer_iv, "Outer cipher IV")?;
    let protected_stream_key = get_or_err(protected_stream_key, "Protected stream key")?;
    let stream_start = get_or_err(stream_start, "Stream start bytes")?;
    let inner_cipher = get_or_err(inner_cipher, "Inner cipher ID")?;

    Ok(
        KDBX3Header {
            version,
            file_major_version,
            file_minor_version,
            outer_cipher,
            compression,
            master_seed,
            transform_seed,
            transform_rounds,
            outer_iv,
            protected_stream_key,
            stream_start,
            inner_cipher,
            body_start: pos,
        }
    )
}

