use super::{
    Entry,
    UuidValue
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct History {
    pub uuid: UuidValue,
    pub entries: Vec<Entry>
}
