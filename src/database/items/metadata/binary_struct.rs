use super::Identifier;
use crate::database::items::values::Base64Value;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Binary {
    id: String,
    compressed: bool,
    value: Base64Value,
}

impl Binary {
    pub fn new(
        id: &str,
        compressed: bool,
        value: &[u8],
    ) -> Self {
        Binary {
            id: id.to_owned(),
            compressed: compressed,
            value: Base64Value::from(value),
        }
    }

    pub fn id(&self) -> String {
        self.id.clone()
    }

    pub fn compressed(&self) -> bool {
        self.compressed
    }

    pub fn value(&self) -> Vec<u8> {
        self.value.to_vec()
    }

    pub fn raw_value(&self) -> Vec<u8> {
        self.value.as_raw_bytes().to_vec()
    }
}

impl Default for Binary {
    fn default() -> Self {
        Binary {
            id: "".to_owned(),
            compressed: false,
            value: Base64Value::default(),
        }
    }
}

impl Identifier for Binary{
    const IDENTIFIER: &'static [u8] = b"Binary";
}


#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_construct() {
        let bin = Binary::new(
            "1",
            true,
            "hello world".as_bytes()
        );

        assert_that(&bin.id())
            .is_equal_to("1".to_owned());
        assert_that(&bin.compressed)
            .is_true();
        assert_that(&bin.value())
            .is_equal_to("hello world".as_bytes().to_vec());
    }

    #[test]
    fn test_default() {
        let bin = Binary::default();

        assert_that(&bin.id())
            .is_equal_to("".to_owned());
        assert_that(&bin.compressed)
            .is_false();
        assert_that(&bin.value())
            .is_equal_to("".as_bytes().to_vec());
    }
}
