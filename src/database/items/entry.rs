use super::{
    AutoType,
    StringValue,
    ColorValue,
    UuidValue,
    Times,
    Binary,
};

use std::collections::HashMap;

/// A types entry containing several key-value fields.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Entry {
    uuid: UuidValue,
    icon_id: i32,
    foreground_color: Option<ColorValue>,
    background_color: Option<ColorValue>,
    override_url: Option<String>,
    tags: Option<String>,
    times: Option<Times>,
    binary: Option<Binary>,
    fields: HashMap<String, StringValue>,
    autotype: Option<AutoType>,
    history: Vec<Entry>,
}

impl Entry {
    pub fn new(uuid: &UuidValue) -> Self {
        Self {
            uuid: uuid.to_owned(),
            icon_id: -1,
            foreground_color: None,
            background_color: None,
            override_url: None,
            tags: None,
            times: None,
            binary: None,
            fields: HashMap::new(),
            autotype: None,
            history: vec![],
        }
    }

    pub fn from(fields: &HashMap<String, StringValue>) -> Self {
        let mut entry = Self::default();
        let _ = entry.set_fields(fields);
        entry
    }

    fn set_fields(&mut self, fields: &HashMap<String, StringValue>) -> &mut Self {
        fields.iter().for_each(|(key, value)| {
            self.fields.insert(
                key.to_owned(),
                value.to_owned()
            );
        });
        self
    }

    pub fn uuid(&self) -> UuidValue {
        self.uuid.clone()
    }

    pub fn set_uuid(&mut self, value: &UuidValue) -> &mut Self {
        self.uuid = value.to_owned();
        self
    }

    pub fn icon_id(&self) -> i32 {
        self.icon_id
    }

    pub fn set_icon_id(&mut self, value: i32) -> &mut Self {
        self.icon_id = value;
        self
    }

    pub fn foreground_color(&self) -> Option<ColorValue> {
        self.foreground_color.clone()
    }

    pub fn set_foreground_color(&mut self, value: &ColorValue) -> &mut Self {
        self.foreground_color = Some(value.to_owned());
        self
    }

    pub fn background_color(&self) -> Option<ColorValue> {
        self.background_color.clone()
    }

    pub fn set_background_color(&mut self, value: &ColorValue) -> &mut Self {
        self.background_color = Some(value.to_owned());
        self
    }

    pub fn override_url(&self) -> Option<String> {
        self.override_url.clone()
    }

    pub fn set_override_url(
        &mut self,
        value: &str) -> &mut Self
    {
        self.override_url = Some(value.to_owned());
        self
    }

    pub fn binary(&self) -> Option<Binary> {
        self.binary.clone()
    }

    pub fn set_binary(
        &mut self,
        value: &Binary) -> &mut Self
    {
        self.binary = Some(value.to_owned());
        self
    }

    pub fn add(
        &mut self,
        key: &str,
        value: &StringValue) -> &mut Self
    {
        self.fields.insert(key.to_owned(), value.to_owned());
        self
    }

    pub fn remove(
        &mut self,
        key: &str) -> &mut Self
    {
        self.fields.remove(key);
        self
    }

    pub fn has_fields(&self) -> bool {
        !self.fields.is_empty()
    }

    pub fn history_items(&self) -> Vec<Entry> {
        self.history.clone()
    }

    pub fn add_history(
        &mut self,
        value: &Entry) -> &mut Self
    {
        self.history.push(value.to_owned());
        self
    }

    pub fn remove_history(
        &mut self,
        value: &Entry) -> &mut Self
    {
        if let Some(pos) = self.history.iter().position(|item| *item == *value) {
            self.history.remove(pos);
            self.history.shrink_to_fit();
        }
        self
    }

    pub fn clear_history(&mut self) -> &mut Self {
        self.history.clear();
        self
    }

    pub fn has_history_items(&self) -> bool {
        !self.history.is_empty()
    }

    pub fn set_autotype(&mut self, autotype: &AutoType) -> &mut Self {
        self.autotype = Some(autotype.clone());
        self
    }
}

impl<'a> Entry {
    pub fn get(
        &'a self,
        key: &str,
    ) -> Option<&'a str> {
        match self.fields.get(key) {
            Some(&StringValue::Bytes(_)) => None,
            Some(&StringValue::ProtectedString(ref pv)) => std::str::from_utf8(pv.unsecure()).ok(),
            Some(&StringValue::UnprotectedString(ref uv)) => Some(&uv),
            None => None,
        }
    }

    pub fn get_bytes(
        &'a self,
        key: &str,
    ) -> Option<&'a [u8]> {
        match self.fields.get(key) {
            Some(&StringValue::Bytes(ref b)) => Some(&b),
            Some(&StringValue::ProtectedString(_)) => None,
            Some(&StringValue::UnprotectedString(_)) => None,
            None => None,
        }
    }

    pub fn history_item(
        &'a self,
        index: usize,
    ) -> Option<&'a Entry> {
        self.history.get(index)
    }

    pub fn get_title(&'a self) -> Option<&'a str> {
        self.get("Title")
    }

    pub fn title(&'a self) -> Option<&'a str> {
        self.get("Title")
    }

    pub fn get_username(&'a self) -> Option<&'a str> {
        self.get("UserName")
    }
    pub fn username(&'a self) -> Option<&'a str> {
        self.get("UserName")
    }

    pub fn get_password(&'a self) -> Option<&'a str> {
        self.get("Password")
    }

    pub fn password(&'a self) -> Option<&'a str> {
        self.get("Password")
    }
}
