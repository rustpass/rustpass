use super::{
    Identifier,
    Entry,
    UuidValue
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct History {
    pub uuid: UuidValue,
    pub entries: Vec<Entry>
}

impl Identifier for History {
    const IDENTIFIER: &'static [u8] = b"History";
}
