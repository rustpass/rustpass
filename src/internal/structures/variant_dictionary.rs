use crate::{
    errors::{
        DatabaseIntegrityError,
        Error,
    },
    results::Result,
    internal::traits::{
        AsBytes,
        TryFromBytes
    }
};

use byteorder::{
    ByteOrder,
    LittleEndian,
    WriteBytesExt
};

use std::{
    cell::RefCell,
    collections::HashMap,
    io::Write
};

#[derive(Debug)]
pub(crate) struct VariantDictionary {
    data: RefCell<HashMap<String, VariantDictionaryValue>>
}

impl VariantDictionary {
    pub(crate) fn get<T>(
        &self,
        key: &str,
    ) -> Result<T>
        where T: FromVariantDictionaryValue<T>,
    {
        let map = self.data.borrow();

        let vdv = if let Some(v) = map.get(key) {
            v
        } else {
            return Err(
                Error::from(
                    DatabaseIntegrityError::MissingKDFParams {
                        key: key.to_owned(),
                    }
                )
            );
        };

        T::from_variant_dictionary_value(vdv)
            .ok_or_else(|| {
                DatabaseIntegrityError::MistypedKDFParam {
                    key: key.to_owned(),
                }.into()
            })
    }

    pub(crate) fn put(
        &mut self,
        key: &str,
        val: VariantDictionaryValue,
    ) -> Option<VariantDictionaryValue>
    {
        let mut map = self.data.borrow_mut();

        map.insert(
            key.to_owned(),
            val,
        )
    }
}

impl Default for VariantDictionary {
    fn default() -> Self {
        VariantDictionary {
            data: RefCell::new(HashMap::new())
        }
    }
}

impl TryFromBytes for VariantDictionary {
    type Error = Error;

    fn from_bytes(buffer: &[u8]) -> Result<VariantDictionary> {
        let version = LittleEndian::read_u16(&buffer[0..2]);

        if version != 0x100 {
            return Err(DatabaseIntegrityError::InvalidVariantDictionaryVersion { version }.into());
        }

        if buffer.len() < 9 {
            return Err(DatabaseIntegrityError::InvalidVariantDictionaryFormat { length: buffer.len() }.into());
        }

        let mut pos = 2;
        let mut data = HashMap::new();

        while pos < buffer.len() - 9 {
            let value_type = buffer[pos];
            pos += 1;

            let key_length = LittleEndian::read_u32(&buffer[pos..(pos + 4)]) as usize;
            pos += 4;

            let key = std::str::from_utf8(&buffer[pos..(pos + key_length)])
                .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?
                .to_owned();
            pos += key_length;

            let value_length = LittleEndian::read_u32(&buffer[pos..(pos + 4)]) as usize;
            pos += 4;

            let value_buffer = &buffer[pos..(pos + value_length)];
            pos += value_length;

            let value = match value_type {
                VariantDictionaryValue::UINT32 => {
                    VariantDictionaryValue::UInt32(
                        LittleEndian::read_u32(value_buffer)
                    )
                },
                VariantDictionaryValue::UINT64 => {
                    VariantDictionaryValue::UInt64(
                        LittleEndian::read_u64(value_buffer)
                    )
                },
                VariantDictionaryValue::BOOL => {
                    VariantDictionaryValue::Bool(value_buffer != [0])
                },
                VariantDictionaryValue::INT32 => {
                    VariantDictionaryValue::Int32(
                        LittleEndian::read_i32(value_buffer)
                    )
                },
                VariantDictionaryValue::INT64 => {
                    VariantDictionaryValue::Int64(
                        LittleEndian::read_i64(value_buffer)
                    )
                },
                VariantDictionaryValue::STRING => {
                    VariantDictionaryValue::String(
                        std::str::from_utf8(value_buffer)
                            .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?
                            .into(),
                    )
                },
                VariantDictionaryValue::BYTE_ARRAY => {
                    VariantDictionaryValue::ByteArray(
                        value_buffer.to_vec()
                    )
                },
                _ => {
                    return Err(
                        DatabaseIntegrityError::InvalidVariantDictionaryValueType {
                            value_type
                        }.into()
                    );
                }
            };
            data.insert(key, value);
        }

        Ok(
            VariantDictionary {
                data: RefCell::new(data)
            }
        )
    }
}
impl AsBytes for VariantDictionary {
    fn as_bytes(&self) -> Vec<u8> {
        let mut res = Vec::new();

        let _ = res.write_u16::<LittleEndian>(0x100);

        self.data
            .borrow()
            .iter()
            .for_each(|(key, val)| {
                let _ = res.write_u8(val.to_code());
                let _ = res.write_i32::<LittleEndian>(key.len() as i32);
                let _ = res.write(key.as_bytes());
                let _ = res.write_i32::<LittleEndian>(val.len() as i32);
                let _ = res.write(val.to_vec().as_ref());
            });

        let _ = res.write_u8(0x00);

        res
    }
}

pub(crate) trait FromVariantDictionaryValue<T> {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<T>;
}

impl FromVariantDictionaryValue<u32> for u32 {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<u32> {
        if let VariantDictionaryValue::UInt32(v) = vdv {
            Some(*v)
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<u64> for u64 {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<u64> {
        if let VariantDictionaryValue::UInt64(v) = vdv {
            Some(*v)
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<bool> for bool {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<bool> {
        if let VariantDictionaryValue::Bool(v) = vdv {
            Some(*v)
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<i32> for i32 {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<i32> {
        if let VariantDictionaryValue::Int32(v) = vdv {
            Some(*v)
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<i64> for i64 {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<i64> {
        if let VariantDictionaryValue::Int64(v) = vdv {
            Some(*v)
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<String> for String {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<String> {
        if let VariantDictionaryValue::String(v) = vdv {
            Some(v.clone())
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<Vec<u8>> for Vec<u8> {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<Vec<u8>> {
        if let VariantDictionaryValue::ByteArray(v) = vdv {
            Some(v.clone())
        } else {
            None
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum VariantDictionaryValue {
    UInt32(u32),
    UInt64(u64),
    Bool(bool),
    Int32(i32),
    Int64(i64),
    String(String),
    ByteArray(Vec<u8>),
}

impl VariantDictionaryValue {
    // 0x00 - 0x03: reserved
    pub const UINT32: u8 = 0x04;
    pub const UINT64: u8 = 0x05;
    // 0x06 - 0x07: reserved
    pub const BOOL: u8 = 0x08;
    // 0x09 - 0x0b: reserved
    pub const INT32: u8 = 0x0c;
    pub const INT64: u8 = 0x0d;
    // 0x0e - 0x17: reserved
    pub const STRING: u8 = 0x18;
    // 0x19 - 0x41: reserved
    pub const BYTE_ARRAY: u8 = 0x42;

    pub fn len(&self) -> usize {
        match self {
            Self::Bool(_) => 0x01,
            Self::Int32(_) | Self::UInt32(_) => 0x04,
            Self::Int64(_) | Self::UInt64(_) => 0x08,
            Self::String(v) => v.len(),
            Self::ByteArray(v) => v.len(),
        }
    }

    pub fn to_code(&self) -> u8 {
        match self {
            Self::UInt32(_) => Self::UINT32,
            Self::UInt64(_) => Self::UINT64,
            Self::Bool(_) => Self::BOOL,
            Self::Int32(_) => Self::INT32,
            Self::Int64(_) => Self::INT64,
            Self::String(_) => Self::STRING,
            Self::ByteArray(_) => Self::BYTE_ARRAY,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::UInt32(v) => Vec::from(v.to_le_bytes()),
            Self::UInt64(v) => Vec::from(v.to_le_bytes()),
            Self::Bool(v) => Vec::from((*v as u8).to_le_bytes().as_ref()),
            Self::Int32(v) => Vec::from(v.to_le_bytes().as_ref()),
            Self::Int64(v) => Vec::from(v.to_le_bytes().as_ref()),
            Self::String(v) => Vec::from(v.as_bytes()),
            Self::ByteArray(v) => v.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;

    fn create_variant_dictionary() -> VariantDictionary {
        let mut vd = VariantDictionary::default();
        vd.put("bool_true", VariantDictionaryValue::Bool(true));
        vd.put("bool_false", VariantDictionaryValue::Bool(false));
        vd.put("test_u32_min", VariantDictionaryValue::UInt32(u32::MIN));
        vd.put("test_u32_max", VariantDictionaryValue::UInt32(u32::MAX));
        vd.put("test_u64_min", VariantDictionaryValue::UInt64(u64::MIN));
        vd.put("test_u64_max", VariantDictionaryValue::UInt64(u64::MAX));
        vd.put("test_i32_min", VariantDictionaryValue::Int32(i32::MIN));
        vd.put("test_i32_max", VariantDictionaryValue::Int32(i32::MAX));
        vd.put("test_i64_min", VariantDictionaryValue::Int64(i64::MIN));
        vd.put("test_i64_max", VariantDictionaryValue::Int64(i64::MAX));
        vd.put("test_str_empty", VariantDictionaryValue::String("".to_owned()));
        vd.put("test_str_hello", VariantDictionaryValue::String("hello".to_owned()));
        vd.put("test_bytearray_empty", VariantDictionaryValue::ByteArray([42u8; 0].to_vec()));
        vd.put("test_bytearray_32", VariantDictionaryValue::ByteArray([42u8; 32].to_vec()));

        vd
    }

    #[test]
    fn test_valid_bool() {
        let vd = create_variant_dictionary();

        assert_that(&vd.get::<bool>("bool_true")).is_ok_containing(true);
        assert_that(&vd.get::<bool>("bool_false")).is_ok_containing(false);
    }

    #[test]
    fn test_valid_u32() {
        let vd = create_variant_dictionary();

        assert_that(&vd.get::<u32>("test_u32_min")).is_ok_containing(u32::MIN);
        assert_that(&vd.get::<u32>("test_u32_max")).is_ok_containing(u32::MAX);
    }

    #[test]
    fn test_valid_u64() {
        let vd = create_variant_dictionary();

        assert_that(&vd.get::<u64>("test_u64_min")).is_ok_containing(u64::MIN);
        assert_that(&vd.get::<u64>("test_u64_max")).is_ok_containing(u64::MAX);
    }

    #[test]
    fn test_valid_i32() {
        let vd = create_variant_dictionary();

        assert_that(&vd.get::<i32>("test_i32_min")).is_ok_containing(i32::MIN);
        assert_that(&vd.get::<i32>("test_i32_max")).is_ok_containing(i32::MAX);
    }

    #[test]
    fn test_valid_i64() {
        let vd = create_variant_dictionary();

        assert_that(&vd.get::<i64>("test_i64_min")).is_ok_containing(i64::MIN);
        assert_that(&vd.get::<i64>("test_i64_max")).is_ok_containing(i64::MAX);
    }

    #[test]
    fn test_valid_string() {
        let vd = create_variant_dictionary();

        assert_that(&vd.get::<String>("test_str_empty")).is_ok_containing("".to_owned());
        assert_that(&vd.get::<String>("test_str_hello")).is_ok_containing("hello".to_owned());
    }

    #[test]
    fn test_valid_bytearray() {
        let vd = create_variant_dictionary();

        assert_that(&vd.get::<Vec<u8>>("test_bytearray_empty")).is_ok_containing(Vec::from([42u8; 0].as_ref()));
        assert_that(&vd.get::<Vec<u8>>("test_bytearray_32")).is_ok_containing(Vec::from([42u8; 32].as_ref()));
    }

    #[test]
    fn test_serialize_deserialize_empty() {
        let vd = VariantDictionary::default();

        let serialized = vd.as_bytes();

        let parsed_data = VariantDictionary::from_bytes(serialized.as_ref());

        assert_that(&parsed_data)
            .is_err();
    }

    #[test]
    fn test_serialize_deserialize_values() {
        let vd = create_variant_dictionary();

        let serialized = vd.as_bytes();

        let parsed_data = VariantDictionary::from_bytes(serialized.as_ref());

        let parsed_data_spec = assert_that(&parsed_data)
            .is_ok()
            .subject;

        let original_data = vd.data.borrow();

        original_data
            .iter()
            .for_each(|(key, val)| {
                let deserialized_data = parsed_data_spec.data.borrow();
                assert_that(&deserialized_data.get(key)).is_some().is_equal_to(val);
            });
    }
}
