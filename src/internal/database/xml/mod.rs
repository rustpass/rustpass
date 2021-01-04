pub(crate) mod parser;
pub(crate) mod writer;

use crate::{
    database::items::*,
};

#[derive(Debug)]
pub(super) enum Node {
    Entry(Entry),
    Group(Group),
    KeyValue(String, StringValue),
    AutoType(AutoType),
    AutoTypeAssociation(AutoTypeAssociation),
}
