use uuid::Uuid;

use std::str::FromStr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UuidValue(Uuid);

impl UuidValue {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes().as_ref()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

impl Default for UuidValue {
    fn default() -> Self {
        UuidValue(
            Uuid::new_v4()
        )
    }
}

impl ToString for UuidValue {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl FromStr for UuidValue {
    type Err = ();

    fn from_str(bla: &str) -> Result<Self, Self::Err> {
        //...
        Ok(UuidValue::from(bla))
    }
}

impl From<&str> for UuidValue {
    fn from(value: &str) -> Self {
        UuidValue(
            Uuid::parse_str(value)
                .expect("invalid uuid str given")
        )
    }
}

impl From<&[u8]> for UuidValue {
    fn from(value: &[u8]) -> Self {
        UuidValue(
            Uuid::from_slice(value)
                .expect("invalid uuid slice given")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_create_from_str() {
        let uuid = "77b2ff13-c5da-4026-b383-1c4193a7bde6";
        let uuid_value = UuidValue::from(uuid);

        assert_that(&uuid_value.to_string()).is_equal_to(uuid.to_owned());
    }

    #[test]
    #[should_panic]
    fn test_create_invalid_uuid() {
        let uuid = "this is clearly no valid uuid";
        let _ = UuidValue::from(uuid);
    }

}

