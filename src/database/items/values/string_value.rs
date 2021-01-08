use super::Identifier;
use secstr::SecStr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StringValue {
    Bytes(Vec<u8>),
    UnprotectedString(String),
    ProtectedString(SecStr),
}

impl Identifier for StringValue {
    const IDENTIFIER: &'static [u8] = b"String";
}
