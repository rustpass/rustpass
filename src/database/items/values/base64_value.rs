use base64::{
    encode,
    decode
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Base64Value(Vec<u8>);

impl Base64Value {
    fn new(data: &[u8]) -> Self {
        Base64Value(
            encode(data).as_bytes().to_vec()
        )
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let res = decode(&self.0);
        res.unwrap_or_default()
    }

    pub fn as_raw_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn to_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(decode(&self.0).unwrap_or_default()) }
    }

    pub fn to_raw_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.0.clone()) }
    }
}

impl Default for Base64Value {
    fn default() -> Self {
        Base64Value(vec![])
    }
}

impl From<String> for Base64Value {
    fn from(data: String) -> Self {
        Base64Value::new(data.as_bytes())
    }
}

impl From<&str> for Base64Value {
    fn from(data: &str) -> Self {
        Base64Value::new(data.as_bytes())
    }
}

impl From<&[u8]> for Base64Value {
    fn from(data: &[u8]) -> Self {
        Base64Value::new(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_construct_read() {
        let sample = "hello world".as_bytes();

        let mut b64 = Base64Value::new(sample);

        let read_res = b64.to_vec();

        assert_that(&read_res).is_equal_to(sample.to_vec());
    }

    #[test]
    fn test_from_bytes_read_roundtrip() {
        let sample = "hello world".as_bytes();

        let mut b64 = Base64Value::from(sample.clone());

        let read_res = b64.to_vec();

        assert_that(&read_res).is_equal_to(sample.to_vec());
    }

    #[test]
    fn test_from_string_read_roundtrip() {
        let sample = "hello world".to_owned();

        let mut b64 = Base64Value::from(sample.clone());

        let read_res = b64.to_vec();

        assert_that(&read_res).is_equal_to(sample.as_bytes().to_vec());
    }

    #[test]
    fn test_from_str_read_roundtrip() {
        let sample = "hello world";

        let mut b64 = Base64Value::from(sample);

        let read_res = b64.to_vec();

        assert_that(&read_res).is_equal_to(sample.as_bytes().to_vec());
    }
}
