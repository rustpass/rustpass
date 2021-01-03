use secstr::SecStr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StringValue {
    Bytes(Vec<u8>),
    UnprotectedString(String),
    ProtectedString(SecStr),
}
