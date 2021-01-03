use super::TimestampValue;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Times {
    pub last_modification_time: Option<TimestampValue>,
    pub creation_time: Option<TimestampValue>,
    pub last_access_time: Option<TimestampValue>,
    pub expiry_time: Option<TimestampValue>,
    pub expires: Option<bool>,
    pub usage_count: u32,
    pub location_changed: Option<TimestampValue>,
}

impl Times {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Times {
    fn default() -> Self {
        Times {
            last_modification_time: None,
            creation_time: None,
            last_access_time: None,
            expiry_time: None,
            expires: Some(false),
            usage_count: 0,
            location_changed: None,
        }
    }
}
