use super::Error;
use super::crypto;

#[derive(Debug)]
pub enum DatabaseIntegrityError {
    Compression,
    Crypto {
        e: crypto::CryptoError,
    },
    HeaderHashMismatch,
    BlockHashMismatch {
        block_index: usize,
    },
    InvalidKDBXIdentifier,
    InvalidKDBXVersion {
        version: u32,
        file_major_version: u16,
        file_minor_version: u16,
    },
    InvalidFixedHeader {
        size: usize,
    },
    InvalidOuterHeaderEntry {
        entry_type: u8,
    },
    IncompleteOuterHeader {
        missing_field: String,
    },
    InvalidInnerHeaderEntry {
        entry_type: u8,
    },
    IncompleteInnerHeader {
        missing_field: String,
    },
    InvalidKDFVersion {
        version: u32,
    },
    InvalidKDFUUID {
        uuid: Vec<u8>,
    },
    MissingKDFParams {
        key: String,
    },
    MistypedKDFParam {
        key: String,
    },
    InvalidFixedCipherID {
        cid: u32,
    },
    InvalidOuterCipherID {
        cid: Vec<u8>,
    },
    InvalidInnerCipherID {
        cid: u32,
    },
    InvalidCompressionSuite {
        cid: u32,
    },
    InvalidVariantDictionaryVersion {
        version: u16,
    },
    InvalidVariantDictionaryFormat {
        length: usize,
    },
    InvalidVariantDictionaryValueType {
        value_type: u8,
    },
    InvalidKDBFieldLength {
        field_type: u16,
        field_size: u32,
        expected_field_size: u32,
    },
    InvalidKDBGroupFieldType {
        field_type: u16,
    },
    InvalidKDBEntryFieldType {
        field_type: u16,
    },
    MissingKDBGroupId,
    InvalidKDBGroupId {
        group_id: u32,
    },
    MissingKDBGroupLevel,
    InvalidKDBGroupLevel {
        group_level: u16,
        current_level: u16,
    },
    IncompleteKDBGroup,
    IncompleteKDBEntry,
    MissingKDBEntryTitle,
    XMLParsing {
        e: xml::reader::Error,
    },
    Base64 {
        e: base64::DecodeError,
    },
    UTF8 {
        e: std::str::Utf8Error,
    },
}

impl std::error::Error for DatabaseIntegrityError {
    #[cfg_attr(tarpaulin, skip)]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DatabaseIntegrityError::Crypto { e } => Some(e),
            DatabaseIntegrityError::XMLParsing { e } => Some(e),
            DatabaseIntegrityError::Base64 { e } => Some(e),
            DatabaseIntegrityError::UTF8 { e } => Some(e),
            _ => None,
        }
    }
}

#[cfg_attr(tarpaulin, skip)]
impl std::fmt::Display for DatabaseIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Database integrity error: {}",
            match self {
                DatabaseIntegrityError::Compression => "(De)compression error".to_owned(),
                DatabaseIntegrityError::Crypto { e } => format!("Cryptography error: {:?}", e),
                DatabaseIntegrityError::HeaderHashMismatch => {
                    "Hash mismatch when verifying header".to_owned()
                }
                DatabaseIntegrityError::BlockHashMismatch { block_index } => {
                    format!("Error when verifying integrity of block {}", block_index)
                }
                DatabaseIntegrityError::InvalidKDBXIdentifier => {
                    "Invalid KDBX Identifier".to_owned()
                }
                DatabaseIntegrityError::InvalidKDBXVersion {
                    version,
                    file_major_version,
                    file_minor_version,
                } => format!(
                    "Invalid KDBX Version (version: {:0x} file version {}.{})",
                    version, file_major_version, file_minor_version
                ),
                DatabaseIntegrityError::InvalidFixedHeader { size } =>
                    format!("Invalid KBD Header (size: {})", size),
                DatabaseIntegrityError::InvalidOuterHeaderEntry { entry_type } => format!(
                    "Encountered an invalid outer header entry with type {}",
                    entry_type
                ),
                DatabaseIntegrityError::InvalidInnerHeaderEntry { entry_type } => format!(
                    "Encountered an invalid inner header entry with type {}",
                    entry_type
                ),
                DatabaseIntegrityError::IncompleteOuterHeader { missing_field } => {
                    format!("Missing field in outer header: {}", missing_field)
                }
                DatabaseIntegrityError::IncompleteInnerHeader { missing_field } => {
                    format!("Missing field in inner header: {}", missing_field)
                }
                DatabaseIntegrityError::MissingKDFParams { key } => {
                    format!("Missing field in KDF parameters: {}", key)
                }
                DatabaseIntegrityError::MistypedKDFParam { key } => {
                    format!("KDF parameter {} has wrong type", key)
                }
                DatabaseIntegrityError::InvalidKDFVersion { version } => {
                    format!("Encountered an invalid KDF version: {}", version)
                }
                DatabaseIntegrityError::InvalidKDFUUID { uuid } => {
                    format!("Encountered an invalid KDF UUID: {:0x?}", uuid)
                }
                DatabaseIntegrityError::InvalidFixedCipherID { cid } => {
                    format!("Encountered an invalid KBD cipher ID: {:0x?}", cid)
                }
                DatabaseIntegrityError::InvalidOuterCipherID { cid } => {
                    format!("Encountered an invalid outer cipher ID: {:0x?}", cid)
                }
                DatabaseIntegrityError::InvalidInnerCipherID { cid } => {
                    format!("Encountered an invalid inner cipher ID: {}", cid)
                }
                DatabaseIntegrityError::InvalidCompressionSuite { cid } => {
                    format!("Encountered an invalid compression suite ID: {}", cid)
                }
                DatabaseIntegrityError::InvalidVariantDictionaryVersion { version } => format!(
                    "Encountered a VariantDictionary with an invalid version: {}",
                    version
                ),
                DatabaseIntegrityError::InvalidVariantDictionaryFormat { length } => format!(
                    "Encountered a VariantDictionary with no content: {}",
                    length
                ),
                DatabaseIntegrityError::InvalidVariantDictionaryValueType { value_type } => {
                    format!(
                        "Encountered an invalid VariantDictionary value type: {}",
                        value_type
                    )
                }
                DatabaseIntegrityError::InvalidKDBFieldLength { field_type, field_size, expected_field_size } =>
                    format!("Encountered a field with an invalid size: expected {}, got {} for field type {}", expected_field_size, field_size, field_type),
                DatabaseIntegrityError::InvalidKDBGroupFieldType { field_type } =>
                    format!("Encountered an invalid group field type: {}", field_type),
                DatabaseIntegrityError::InvalidKDBEntryFieldType { field_type } =>
                    format!("Encountered an invalid entry field type: {}", field_type),
                DatabaseIntegrityError::MissingKDBGroupId =>
                    format!("Encountered a group/entry without a GroupId"),
                DatabaseIntegrityError::InvalidKDBGroupId { group_id } =>
                    format!("Encountered an entry with an invalid GroupId: {}", group_id),
                DatabaseIntegrityError::MissingKDBGroupLevel =>
                    format!("Encountered a group without a Level"),
                DatabaseIntegrityError::InvalidKDBGroupLevel {
                    group_level,
                    current_level,
                } => format!(
                    "Encountered a group with an invalid Level: {} (current: {})",
                    group_level, current_level
                ),
                DatabaseIntegrityError::IncompleteKDBGroup =>
                    format!("Encountered an incomplete group"),
                DatabaseIntegrityError::IncompleteKDBEntry =>
                    format!("Encountered an incomplete entry"),
                DatabaseIntegrityError::MissingKDBEntryTitle =>
                    format!("Encountered an entry without a title"),
                DatabaseIntegrityError::XMLParsing { e } => format!(
                    "Encountered an error when parsing the inner XML payload: {}",
                    e
                ),
                DatabaseIntegrityError::UTF8 { e } => format!(
                    "Encountering an error when parsing an UTF-8 formatted string: {}",
                    e
                ),
                DatabaseIntegrityError::Base64 { e } => format!(
                    "Encountered an error when parsing a base64-encoded string: {}",
                    e
                ),
            }
        )
    }
}

impl From<DatabaseIntegrityError> for Error {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: DatabaseIntegrityError) -> Self {
        Error::DatabaseIntegrity { e }
    }
}

impl From<crypto::CryptoError> for DatabaseIntegrityError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: crypto::CryptoError) -> Self {
        DatabaseIntegrityError::Crypto { e }
    }
}

impl From<xml::reader::Error> for DatabaseIntegrityError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: xml::reader::Error) -> Self {
        DatabaseIntegrityError::XMLParsing { e }
    }
}

impl From<std::str::Utf8Error> for DatabaseIntegrityError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: std::str::Utf8Error) -> Self {
        DatabaseIntegrityError::UTF8 { e }
    }
}

impl From<base64::DecodeError> for DatabaseIntegrityError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: base64::DecodeError) -> Self {
        DatabaseIntegrityError::Base64 { e }
    }
}
