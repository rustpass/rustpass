use super::Identifier;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Notes {}

impl Identifier for Notes {
    const IDENTIFIER: &'static [u8] = b"Notes";
}
