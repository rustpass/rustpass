use crate::{
    api::kdb::KDBHeader,
    errors::DatabaseIntegrityError,
    results::Result,
    internal::database::binary::version::get_kdbx_version,
};

use byteorder::{
    ByteOrder,
    LittleEndian,
};

pub const HEADER_SIZE: usize = 4 + 4 + 4 + 4 + 16 + 16 + 4 + 4 + 32 + 32 + 4; // first 4 bytes are the KeePass magic

pub(crate) fn read_header(data: &[u8]) -> Result<KDBHeader> {
    let (version, _, _) = get_kdbx_version(data)?;

    if version != 0xb54b_fb65 {
        return Err(DatabaseIntegrityError::InvalidKDBXVersion {
            version,
            file_major_version: 0,
            file_minor_version: 0,
        }
            .into());
    }

    if data.len() < HEADER_SIZE {
        return Err(DatabaseIntegrityError::InvalidFixedHeader { size: data.len() }.into());
    }

    Ok(
        KDBHeader {
            version,
            flags: LittleEndian::read_u32(&data[8..]),
            subversion: LittleEndian::read_u32(&data[12..]),
            master_seed: data[16..32].to_vec(),
            encryption_iv: data[32..48].to_vec(),
            num_groups: LittleEndian::read_u32(&data[48..]),
            num_entries: LittleEndian::read_u32(&data[52..]),
            contents_hash: data[56..88].to_vec(),
            transform_seed: data[88..120].to_vec(),
            transform_rounds: LittleEndian::read_u32(&data[120..]),
        }
    )
}
