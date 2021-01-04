use crate::{
    api::{
        header::{
            Header,
            InnerHeader,
        },
        kdbx4::{
            KDBX4Header,
            KDBX4InnerHeader
        },
        settings::Settings,
        suites::InnerCipherSuite,
        traits::Sizable
    },
    database::{
        Database,
        items
    },
    errors::{
        DatabaseIntegrityError,
        Error,
    },
    internal::{
        database::{
            binary::{
                constants,
                header::kdbx4
            },
            xml::parser
        },
        random,
        suites::hmac_block_stream,
    },
    results::Result,
};
use crate::internal::cryptopraphy;

// create a new database
pub(crate) fn create(
    settings: &Settings
) -> Result<Database> {
    let mut kdbx4_header = KDBX4Header {
        version: constants::KDBX_MAGIC,
        file_major_version: 4,
        file_minor_version: 0,
        outer_cipher: settings.outer_cipher_suite(),
        compression: settings.compression(),
        master_seed: random::generate_random_bytes(32),
        outer_iv: random::generate_random_bytes(32),
        kdf: settings.kdf_settings(),
        body_start: 0,
    };
    let mut kdbx4_inner_header = KDBX4InnerHeader {
        inner_random_stream: InnerCipherSuite::ChaCha20,
        inner_random_stream_key: random::generate_random_bytes(32),
        binaries: vec![],
        body_start: 0
    };

    kdbx4_header.body_start = kdbx4_header.size();
    kdbx4_inner_header.body_start = kdbx4_header.size() + kdbx4_inner_header.size();

    Ok(
        Database {
            header: Header::KDBX4(kdbx4_header),
            inner_header: InnerHeader::KDBX4(kdbx4_inner_header),
            root: items::Group::root(),
        }
    )
}

/// Open, decrypt and database a KeePass types from a source and key elements
pub(crate) fn parse(data: &[u8], key_elements: &[Vec<u8>]) -> Result<Database> {
    // database header
    let header = kdbx4::read_outer_header(data)?;
    let pos = header.body_start;

    // split file into segments:
    //      header_data         - The outer header data
    //      header_sha256       - A Sha256 hash of header_data (for verification of header integrity)
    //      header_hmac         - A HMAC of the header_data (for verification of the key_elements)
    //      hmac_block_stream   - A HMAC-verified block stream of encrypted and compressed blocks
    let header_data = &data[0..pos];
    let header_sha256 = &data[pos..(pos + 32)];
    let header_hmac = &data[(pos + 32)..(pos + 64)];
    let hmac_block_stream = &data[(pos + 64)..];

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = cryptopraphy::sha256(&key_elements)?;
    let transformed_key = header.kdf.get_kdf().transform_key(&composite_key)?;
    let master_key = cryptopraphy::sha256(&[header.master_seed.as_ref(), &transformed_key])?;

    // verify header
    if header_sha256 != cryptopraphy::sha256(&[&data[0..pos]])?.as_slice() {
        return Err(DatabaseIntegrityError::HeaderHashMismatch.into());
    }

    // verify credentials
    let hmac_key = cryptopraphy::sha512(&[&header.master_seed, &transformed_key, b"\x01"])?;
    let header_hmac_key = hmac_block_stream::get_hmac_block_key(usize::max_value(), &hmac_key)?;
    if header_hmac != cryptopraphy::hmac(&[header_data], &header_hmac_key)?.as_slice() {
        return Err(Error::IncorrectKey);
    }

    // read encrypted payload from hmac-verified block stream
    let payload_encrypted =
        hmac_block_stream::read_hmac_block_stream(&hmac_block_stream, &hmac_key)?;

    // Decrypt and decompress encrypted payload
    let payload_compressed = header
        .outer_cipher
        .get_cipher(&master_key, header.outer_iv.as_ref())?
        .decrypt(&payload_encrypted)?;
    let payload = header
        .compression
        .get_decompression()
        .decompress(&payload_compressed)?;

    // KDBX4 has inner header, too - database it
    let inner_header = kdbx4::read_inner_header(&payload)?;

    // Initialize inner decryptor from inner header params
    let mut inner_decryptor = inner_header
        .inner_random_stream
        .get_cipher(&inner_header.inner_random_stream_key)?;

    // after inner header is one XML document
    let xml = &payload[inner_header.body_start..];
    let root = parser::parse(&xml, &mut *inner_decryptor)?;

    let db = Database {
        header: Header::KDBX4(header),
        inner_header: InnerHeader::KDBX4(inner_header),
        root,
    };

    Ok(db)
}
