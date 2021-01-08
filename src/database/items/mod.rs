mod autotype;
pub(crate) mod deleted;
pub(crate) mod entry;
pub(crate) mod group;
pub(crate) mod history;
pub(crate) mod metadata;
pub(crate) mod node;
pub(crate) mod notes;
pub(crate) mod times;
pub(crate) mod values;


////////////////////////////////////////////////////////////////////////////////
/// Re-Exports
///

pub(crate) use autotype::{
    AutoType,
    AutoTypeAssociation,
};

pub(crate) use deleted::DeletedObject;
pub(crate) use entry::Entry;
pub(crate) use group::Group;
pub(crate) use history::History;
pub(crate) use metadata::{
    Binary,
    MemoryProtection,
    Meta,
};

pub(crate) use node::{
    Node,
    NodeIter,
};

pub(crate) use notes::Notes;

pub(crate) use times::Times;

pub(crate) use values::{
    Base64Value,
    ColorValue,
    StringValue,
    TimestampValue,
    UuidValue,
};

pub struct Database {
    meta: Meta,
    root: Group
}

impl Database {
}

impl Default for Database {
    fn default() -> Self {
        Database {
            meta: Meta::default(),
            root: Group::root()
        }
    }
}

pub(crate) trait Identifier {
    const IDENTIFIER: &'static [u8];
}
