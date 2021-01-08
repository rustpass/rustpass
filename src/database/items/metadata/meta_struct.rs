use super::{
    Identifier,
    binary_struct::Binary,
    memory_protection_struct::MemoryProtection,
};

use crate::database::items::values::{
    ColorValue,
    IconValue,
    TimestampValue,
    UuidValue,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Meta {
    generator: String,
    database_name: String,
    database_name_change: Option<TimestampValue>,
    database_description: String,
    database_description_changed: Option<TimestampValue>,
    default_user_name: String,
    default_user_name_changed: Option<TimestampValue>,
    maintenance_history_days: i32,
    color: Option<ColorValue>,
    master_key_changed: Option<TimestampValue>,
    master_key_change_rec: i32,
    master_key_change_force: i32,
    memory_protection: MemoryProtection,
    custom_icons: Vec<IconValue>,
    recycle_bin_enabled: bool,
    recycle_bin_uuid: Option<UuidValue>,
    entry_templates_group: Option<UuidValue>,
    entry_templates_group_changed: Option<TimestampValue>,
    last_selected_group: Option<UuidValue>,
    last_top_visible_group: Option<UuidValue>,
    history_max_items: i32,
    history_max_size: usize,
    binaries: Vec<Binary>,
}

impl Meta {
    pub fn generator(&self) -> String {
        self.generator.clone()
    }

    pub fn set_generator(&mut self, value: &str) -> &mut Self {
        self.generator = value.to_owned();
        self
    }

    pub fn database_name(&self) -> String {
        self.database_name.clone()
    }

    pub fn database_name_change(&self) -> Option<TimestampValue> {
        self.database_name_change.clone()
    }

    pub fn set_database_name(&mut self, value: &str) -> &mut Self {
        self.database_name = value.to_owned();
        self.database_name_change = Some(TimestampValue::now());
        self
    }

    pub fn database_description(&self) -> String {
        self.database_description.clone()
    }

    pub fn database_description_changed(&self) -> Option<TimestampValue> {
        self.database_description_changed.clone()
    }

    pub fn set_database_description(&mut self, value: &str) -> &mut Self {
        self.database_description = value.to_owned();
        self.database_description_changed = Some(TimestampValue::now());
        self
    }

    pub fn default_user_name(&self) -> String {
        self.default_user_name.clone()
    }

    pub fn default_user_name_changed(&self) -> Option<TimestampValue> {
        self.default_user_name_changed.clone()
    }

    pub fn set_default_user_name(&mut self, value: &str) -> &mut Self {
        self.default_user_name = value.to_owned();
        self.default_user_name_changed = Some(TimestampValue::now());
        self
    }

    pub fn color(&self) -> Option<ColorValue> {
        self.color.clone()
    }

    pub fn set_color(&mut self, value: &ColorValue) -> &mut Self {
        self.color = Some(value.to_owned());
        self
    }

    pub fn master_key_changed(&self) -> Option<TimestampValue> {
        self.master_key_changed.clone()
    }

    pub fn master_key_change_rec(&self) -> i32 {
        self.master_key_change_rec
    }

    pub fn master_key_change_force(&self) -> i32 {
        self.master_key_change_force
    }

    pub fn set_master_key_changed(&mut self, force: bool) -> &mut Self {
        self.master_key_changed = Some(TimestampValue::now());
        self.master_key_change_rec += 1;
        if force {
            self.master_key_change_force += 1;
        }
        self
    }

    pub fn protect_title(&self) -> bool {
        self.memory_protection.protect_title
    }

    pub fn set_protect_title(&mut self, value: bool) -> &mut Self {
        self.memory_protection.protect_title = value;
        self
    }

    pub fn protect_user_name(&self) -> bool {
        self.memory_protection.protect_user_name
    }

    pub fn set_protect_user_name(&mut self, value: bool) -> &mut Self {
        self.memory_protection.protect_user_name = value;
        self
    }

    pub fn protect_password(&self) -> bool {
        self.memory_protection.protect_password
    }

    pub fn set_protect_password(&mut self, value: bool) -> &mut Self {
        self.memory_protection.protect_password = value;
        self
    }

    pub fn protect_url(&self) -> bool {
        self.memory_protection.protect_url
    }

    pub fn set_protect_url(&mut self, value: bool) -> &mut Self {
        self.memory_protection.protect_url = value;
        self
    }

    pub fn protect_notes(&self) -> bool {
        self.memory_protection.protect_notes
    }

    pub fn set_protect_notes(&mut self, value: bool) -> &mut Self {
        self.memory_protection.protect_notes = value;
        self
    }

    pub fn custom_icons(&self) -> Vec<IconValue> {
        self.custom_icons.clone()
    }

    pub fn add_custom_icon(&mut self, value: &IconValue) -> &mut Self {
        self.custom_icons.push(value.clone());
        self
    }

    pub fn remove_custom_icon(&mut self, value: &IconValue) -> &mut Self {
        if let Some(pos) = self.custom_icons
            .iter()
            .position(|item| {
                *item == *value
            })
        {
            self.custom_icons.remove(pos);
            self.custom_icons.shrink_to_fit();
        }
        self
    }

    pub fn clear_custom_icons(&mut self) -> &mut Self {
        self.custom_icons.clear();
        self
    }

    pub fn recycle_bin_enabled(&self) -> bool {
        self.recycle_bin_enabled
    }

    pub fn set_recycle_bin_enabled(&mut self, value: bool) -> &mut Self {
        self.recycle_bin_enabled = value;
        self
    }

    pub fn recycle_bin_uuid(&self) -> Option<UuidValue> {
        self.recycle_bin_uuid.clone()
    }

    pub fn set_recycle_bin_uuid(&mut self, value: &UuidValue) -> &mut Self {
        self.recycle_bin_uuid = Some(value.to_owned());
        self
    }

    pub fn entry_templates_group(&self) -> Option<UuidValue> {
        self.entry_templates_group.clone()
    }

    pub fn entry_templates_group_changed(&self) -> Option<TimestampValue> {
        self.entry_templates_group_changed.clone()
    }

    pub fn set_entry_templates_group(&mut self, value: &UuidValue) -> &mut Self {
        self.entry_templates_group = Some(value.to_owned());
        self.entry_templates_group_changed = Some(TimestampValue::now());
        self
    }

    pub fn last_selected_group(&self) -> Option<UuidValue> {
        self.last_selected_group.clone()
    }

    pub fn set_last_selected_group(&mut self, value: &UuidValue) -> &mut Self {
        self.last_selected_group = Some(value.to_owned());
        self
    }

    pub fn last_top_visible_group(&self) -> Option<UuidValue> {
        self.last_top_visible_group.clone()
    }

    pub fn set_last_top_visible_group(&mut self, value: UuidValue) -> &mut Self {
        self.last_top_visible_group = Some(value.to_owned());
        self
    }

    pub fn history_max_items(&self) -> i32 {
        self.history_max_items
    }

    pub fn set_history_max_items(&mut self, value: i32) -> &mut Self {
        self.history_max_items = value;
        self
    }

    pub fn history_max_size(&self) -> usize {
        self.history_max_size
    }

    pub fn set_history_max_size(&mut self, value: usize) -> &mut Self {
        self.history_max_size = value;
        self
    }

    pub fn binaries(&self) -> Vec<Binary> {
        self.binaries.clone()
    }

    pub fn add_binary(&mut self, value: &Binary) -> &mut Self {
        self.binaries.push(value.to_owned());
        self
    }

    pub fn remove_binary(&mut self, value: &Binary) -> &mut Self {
        if let Some(pos) = self.binaries
            .iter()
            .position(|item| {
                *item == *value
            })
        {
            self.binaries.remove(pos);
            self.binaries.shrink_to_fit();
        }
        self
    }

    pub fn clear_binaries(&mut self) -> &mut Self {
        self.binaries.clear();
        self
    }
}

impl Default for Meta {
    fn default() -> Self {
        Self {
            generator: "rustpass".to_owned(),
            database_name: "".to_owned(),
            database_name_change: None,
            database_description: "".to_owned(),
            database_description_changed: None,
            default_user_name: "".to_owned(),
            default_user_name_changed: None,
            maintenance_history_days: -1,
            color: None,
            master_key_changed: None,
            master_key_change_rec: -1,
            master_key_change_force: -1,
            memory_protection: MemoryProtection::default(),
            custom_icons: vec![],
            recycle_bin_enabled: false,
            recycle_bin_uuid: None,
            entry_templates_group: None,
            entry_templates_group_changed: None,
            last_selected_group: None,
            last_top_visible_group: None,
            history_max_items: -1,
            history_max_size: 512 * 1024,
            binaries: vec![],
        }
    }
}

impl Identifier for Meta {
    const IDENTIFIER: &'static [u8] = b"Meta";
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn test_construct_default() {
        let m = Meta::default();

        assert_that(&m)
            .matches(|f| {
                f.generator == "rustpass"
                    && f.database_name == ""
                    && f.database_description_changed == None
                    && f.database_description == ""
                    && f.database_description_changed == None
                    && f.default_user_name == ""
                    && f.default_user_name_changed == None
                    && f.maintenance_history_days == -1
                    && f.color == None
                    && f.master_key_changed == None
                    && f.master_key_change_rec == -1
                    && f.master_key_change_force == -1
                    && f.memory_protection == MemoryProtection::default()
                    && f.custom_icons.is_empty()
                    && f.recycle_bin_enabled == false
                    && f.recycle_bin_uuid == None
                    && f.entry_templates_group == None
                    && f.entry_templates_group_changed == None
                    && f.last_selected_group == None
                    && f.last_top_visible_group == None
                    && f.history_max_items == -1
                    && f.history_max_size == 512 * 1024
                    && f.binaries == vec![]
            });
    }

    #[test]
    fn test_construct_database_name_modification() {
        let mut m = Meta::default();

        m.set_database_name("test name");

        assert_that(&m.database_name)
            .is_equal_to("test name".to_owned());
        assert_that(&m.database_name_change)
            .is_some();
    }

    #[test]
    fn test_construct_database_description_modification() {
        let mut m = Meta::default();

        m.set_database_description("test description");

        assert_that(&m.database_description)
            .is_equal_to("test description".to_owned());
        assert_that(&m.database_description_changed)
            .is_some();
    }

    #[test]
    fn test_construct_default_user_name_modification() {
        let mut m = Meta::default();

        m.set_default_user_name("test name");

        assert_that(&m.default_user_name)
            .is_equal_to("test name".to_owned());
        assert_that(&m.default_user_name_changed)
            .is_some();
    }

    #[test]
    fn test_construct_color_modification() {
        let mut m = Meta::default();

        m.set_color(&ColorValue::white());
        assert_that(&m.color)
            .is_some()
            .is_equal_to(ColorValue::white());

        m.set_color(&ColorValue::black());
        assert_that(&m.color)
            .is_some()
            .is_equal_to(ColorValue::black());
    }

    #[test]
    fn test_construct_memory_protection_modification() {
        let mut m = Meta::default();

        m.set_protect_title(true);
        assert_that(&m.memory_protection.protect_title)
            .is_true();

        m.set_protect_user_name(true);
        assert_that(&m.memory_protection.protect_user_name)
            .is_true();

        m.set_protect_password(true);
        assert_that(&m.memory_protection.protect_password)
            .is_true();

        m.set_protect_url(true);
        assert_that(&m.memory_protection.protect_url)
            .is_true();

        m.set_protect_notes(true);
        assert_that(&m.memory_protection.protect_notes)
            .is_true();
    }
}
