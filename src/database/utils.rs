use crate::{
    errors::{
        DatabaseIntegrityError,
        Error
    },
    results::Result
};

use std::str;

pub(crate) fn from_utf8(data: &[u8]) -> Result<String> {
    Ok(str::from_utf8(data)
        .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?
        .trim_end_matches('\0')
        .to_owned())
}

pub(crate) fn ensure_length(field_type: u16, field_size: u32, expected_field_size: u32) -> Result<()> {
    if field_size != expected_field_size {
        Err(DatabaseIntegrityError::InvalidKDBFieldLength {
            field_type,
            field_size,
            expected_field_size,
        }
            .into())
    } else {
        Ok(())
    }
}
