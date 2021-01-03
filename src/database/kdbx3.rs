use byteorder::{
    ByteOrder,
    LittleEndian
};

use crate::{
    database::Database,
    errors::{
        DatabaseIntegrityError,
        Error
    },
    internal::{
        primitives::cryptopraphy::{
            self,
            kdf::Kdf,
        }
    },
    results::Result,
    xml_parse,
};
use crate::internal::database::binary::{
    header::kdbx3::read_header,
    structure::{
        Header,
        InnerHeader
    }
};
use crate::database::items::Group;

/// Open, decrypt and database a KeePass types from a source and a password
pub(crate) fn parse(data: &[u8], key_elements: &[Vec<u8>]) -> Result<Database> {
    // database header
    let header = read_header(data)?;

    let mut pos = header.body_start;

    // Turn enums into appropriate trait objects
    let compression = header.compression.get_decompression();

    // Rest of file after header is payload
    let payload_encrypted = &data[pos..];

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = cryptopraphy::sha256(&key_elements)?;

    // KDF is hard coded for KDBX 3
    let transformed_key = cryptopraphy::kdf::AesKdf::new(
        header.transform_seed.as_ref(),
        header.transform_rounds,
    ).transform_key(&composite_key)?;

    let master_key = cryptopraphy::sha256(&[header.master_seed.as_ref(), &transformed_key])?;

    // Decrypt payload
    let payload = header
        .outer_cipher
        .get_cipher(&master_key, header.outer_iv.as_ref())?
        .decrypt(payload_encrypted)?;

    // Check if we decrypted correctly
    if &payload[0..header.stream_start.len()] != header.stream_start.as_slice() {
        return Err(Error::IncorrectKey);
    }

    // Derive stream key for decrypting inner protected values and set up decryption context
    let stream_key = cryptopraphy::sha256(&[header.protected_stream_key.as_ref()])?;
    let mut inner_decryptor = header.inner_cipher.get_cipher(&stream_key)?;

    let mut db = Database {
        header: Header::KDBX3(header),
        inner_header: InnerHeader::None,
        root: Group::root(),
    };

    pos = 32;
    let mut block_index = 0;
    loop {
        // Parse blocks in payload.
        //
        // Each block is a tuple of size (40 + block_size) with structure:
        //
        // (
        //   block_id: u32,                                 // a numeric block ID (starts at 0)
        //   block_hash: [u8, 32],                          // SHA256 of block_buffer_compressed
        //   block_size: u32,                               // block_size size in bytes
        //   block_buffer_compressed: [u8, block_size]      // Block data, possibly compressed
        // )

        // let block_id = LittleEndian::read_u32(&payload[pos..(pos + 4)]);
        let block_hash = &payload[(pos + 4)..(pos + 36)];
        let block_size = LittleEndian::read_u32(&payload[(pos + 36)..(pos + 40)]) as usize;

        // A block with size 0 means we have hit EOF
        if block_size == 0 {
            break;
        }

        let block_buffer_compressed = &payload[(pos + 40)..(pos + 40 + block_size)];

        // Test block hash
        let block_hash_check = cryptopraphy::sha256(&[&block_buffer_compressed])?;
        if block_hash != block_hash_check.as_slice() {
            return Err(DatabaseIntegrityError::BlockHashMismatch { block_index }.into());
        }

        // Decompress block_buffer_compressed
        let block_buffer = compression.decompress(block_buffer_compressed)?;

        // Parse XML data
        let block_group = xml_parse::parse_xml_block(&block_buffer, &mut *inner_decryptor)?;
        db.root
            .child_groups
            .insert(block_group.name.clone(), block_group);

        pos += 40 + block_size;
        block_index += 1;
    }

    // Re-root database.root if it contains only one child (if there was only one block)
    if db.root.child_groups.len() == 1 {
        let mut new_root = Default::default();
        for (_, v) in db.root.child_groups.drain() {
            new_root = v
        }
        db.root = new_root;
    }

    Ok(db)
}
