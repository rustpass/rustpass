use chrono::{
    DateTime,
    Utc,
};

use std::{
    convert::TryFrom,
    ops::Deref,
    str::FromStr,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimestampValue(String);

impl TimestampValue {
    pub fn now() -> Self {
        TimestampValue(format!("{:?}", Utc::now()))
    }
}

impl Default for TimestampValue {
    fn default() -> Self {
        TimestampValue::now()
    }
}

impl Deref for TimestampValue {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for TimestampValue {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DateTime::<Utc>::from_str(s)
            .map(|parsed| Self(format!("{:?}", parsed)))
            .map_err(|_| ())
    }
}

impl ToString for TimestampValue {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl TryFrom<String> for TimestampValue {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(value.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_from_iso() {
        let sample = "2012-01-12T18:42:00Z";
        let tsv_res = TimestampValue::from_str(sample);

        assert_that(&tsv_res)
            .is_ok()
            .is_equal_to(TimestampValue(sample.to_owned()));
    }

    #[test]
    fn test_to_string() {
        let sample = "2012-01-12T18:42:00Z";
        let tsv_res = TimestampValue::from_str(sample);

        let res = assert_that(&tsv_res)
            .is_ok().subject;
        assert_that(&res.to_string())
            .is_equal_to(sample.to_owned());
    }

    #[test]
    fn test_deref() {
        let sample = "2012-01-12T18:42:00Z";
        let tsv_res = TimestampValue::from_str(sample);

        let res = assert_that(&tsv_res)
            .is_ok().subject;

        assert_that(&**res).is_equal_to(sample.to_owned());
    }
}
