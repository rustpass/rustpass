use super::{
    Base64Value,
    UuidValue,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IconValue {
    uuid: UuidValue,
    data: Base64Value
}

impl IconValue {
    pub fn uuid(&self) -> String {
        self.uuid.to_string()
    }

    pub fn data(&self) -> Vec<u8> {
        self.data.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_construct() {
        let uuid_str = "76c975e9-a564-46b5-9adc-fcb5136b1f48";
        let data_bytes = "test-string".as_bytes();

        let uuid = UuidValue::from(uuid_str);
        let data = Base64Value::from(data_bytes);

        let icon_value = IconValue {
            uuid,
            data
        };

        assert_that(&icon_value.uuid()).is_equal_to(uuid_str.to_string());
        assert_that(&icon_value.data()).is_equal_to(data_bytes.to_vec());
    }
}
