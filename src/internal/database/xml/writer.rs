use super::*;
use crate::{
    errors::{
        DatabaseIntegrityError,
        Error,
    },
    results::Result,
    internal::cryptopraphy::cipher::Cipher,
};

use base64;
use secstr::SecStr;
use xml::{
    name::OwnedName,
    writer::{
        EventWriter,
        XmlEvent
    }
};
#[allow(dead_code)]
pub(crate) fn write_xml_block(_group: &Group, _inner_cipher: &mut dyn Cipher) -> Result<Vec<u8>> {
    let res = vec![];
    Ok(res)
}
