use super::{
    UuidValue,
    TimestampValue
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeletedObject {
    uuid: UuidValue,
    deletion_time: TimestampValue
}

impl DeletedObject {
    pub fn new(
        uuid: &UuidValue,
        deletion_time: &TimestampValue
    ) -> Self {
        Self {
            uuid: uuid.to_owned(),
            deletion_time: deletion_time.to_owned()
        }
    }

    pub fn uuid(&self) -> UuidValue {
        self.uuid.clone()
    }

    pub fn set_uuid(&mut self, value: &UuidValue) -> &mut Self {
        self.uuid = value.to_owned();
        self
    }

    pub fn deletion_time(&self) -> TimestampValue {
        self.deletion_time.clone()
    }

    pub fn set_deletion_time(&mut self, value: &TimestampValue) -> &mut Self {
        self.deletion_time = value.to_owned();
        self
    }
}
