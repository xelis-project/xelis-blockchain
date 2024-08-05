use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use thiserror::Error;

use crate::{
    serializer::{Reader, ReaderError, Serializer, Writer},
    crypto::Hash
};

#[derive(Debug, Error)]
pub enum DataConversionError {
    #[error("Expected a value")]
    ExpectedValue,
    #[error("Expected an array")]
    ExpectedArray,
    #[error("Expected an element")]
    ExpectedElement,
    #[error("Expected a map")]
    ExpectedMap,
    #[error("Unexpected value type {:?}", _0)]
    UnexpectedValue(ValueType),
}

// All types availables
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Clone, Copy)]
pub enum ValueType {
    Bool,
    String,
    U8,
    U16,
    U32,
    U64,
    U128,
    Hash,
    Blob,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub enum ElementType {
    // Single value
    Value(ValueType),
    // Array of elements
    Array,
    // Map<K, V> of elements
    Fields,
}

impl ValueType {
    pub fn is_number(&self) -> bool {
        match self {
            Self::U128 |
            Self::U64 |
            Self::U32 |
            Self::U16 |
            Self::U8 => true,
            _ => false
        }
    }
}

impl Serializer for ValueType {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => Self::Bool,
            1 => Self::String,
            2 => Self::U8,
            3 => Self::U16,
            4 => Self::U32,
            5 => Self::U64,
            6 => Self::U128,
            7 => Self::Hash,
            8 => Self::Blob,
            _ => return Err(ReaderError::InvalidValue)
        })
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_u8(match self {
            Self::Bool => 0,
            Self::String => 1,
            Self::U8 => 2,
            Self::U16 => 3,
            Self::U32 => 4,
            Self::U64 => 5,
            Self::U128 => 6,
            Self::Hash => 7,
            Self::Blob => 8
        });
    }

    fn size(&self) -> usize {
        1
    }

}

// This enum allows complex structures with multi depth if necessary
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum DataElement {
    Value(DataValue),
    // For two next variants, we support up to 255 (u8::MAX) elements maximum
    Array(Vec<DataElement>),
    // Key-Value map with key as DataValue and value as DataElement
    Fields(HashMap<DataValue, DataElement>),
}

impl DataElement {
    pub fn has_key(&self, key: &DataValue) -> bool {
        let Self::Fields(fields) = &self else {
            return false
        };

        fields.contains_key(key)
    }

    pub fn get_value_by_key(&self, key: &DataValue, value_type: Option<ValueType>) -> Option<&DataValue> {
        let Self::Fields(data) = &self else {
            return None
        };

        let Self::Value(value) = data.get(key)? else {
            return None;
        };

        if let Some(data_type) = value_type {
            if value.kind() != data_type {
                return None
            }
        }

        Some(value)
    }

    pub fn get_value_by_string_key(&self, name: String, value_type: ValueType) -> Option<&DataValue> {
        self.get_value_by_key(&DataValue::String(name), Some(value_type))
    }

    pub fn kind(&self) -> ElementType {
        match self {
            Self::Array(_) => ElementType::Array,
            Self::Fields(_) => ElementType::Fields,
            Self::Value(value) => ElementType::Value(value.kind()),
        }
    }

    pub fn to_value(self) -> Result<DataValue, DataConversionError> {
        match self {
            Self::Value(v) => Ok(v),
            _ => Err(DataConversionError::ExpectedValue)
        }
    }

    pub fn to_array(self) -> Result<Vec<DataElement>, DataConversionError> {
        match self {
            Self::Array(v) => Ok(v),
            _ => Err(DataConversionError::ExpectedArray)
        }
    }

    pub fn to_map(self) -> Result<HashMap<DataValue, DataElement>, DataConversionError> {
        match self {
            Self::Fields(v) => Ok(v),
            _ => Err(DataConversionError::ExpectedMap)
        }
    }

    pub fn as_value(&self) -> Result<&DataValue, DataConversionError> {
        match self {
            Self::Value(v) => Ok(v),
            _ => Err(DataConversionError::ExpectedValue)
        }
    }

    pub fn as_array(&self) -> Result<&Vec<DataElement>, DataConversionError> {
        match self {
            Self::Array(v) => Ok(v),
            _ => Err(DataConversionError::ExpectedArray)
        }
    }

    pub fn as_map(&self) -> Result<&HashMap<DataValue, DataElement>, DataConversionError> {
        match self {
            Self::Fields(v) => Ok(v),
            _ => Err(DataConversionError::ExpectedMap)
        }
    }
} 

impl Serializer for DataElement {
    // Don't do any pre-allocation because of infinite depth
    // Otherwise an attacker could generate big depth with high size until max limit
    // which can create OOM on low devices
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => Self::Value(DataValue::read(reader)?),
            1 => {
                let size = reader.read_u8()?;
                let mut values = Vec::new();
                for _ in 0..size {
                    values.push(DataElement::read(reader)?)
                }
                Self::Array(values)
            },
            2 => {
                let size = reader.read_u8()?;
                let mut fields = HashMap::new();
                for _ in 0..size {
                    let key = DataValue::read(reader)?;
                    let value = DataElement::read(reader)?;
                    fields.insert(key, value);
                }
                Self::Fields(fields)
            },
            _ => return Err(ReaderError::InvalidValue)
        })
    }

    fn write(&self, writer: &mut Writer) {
        match self {
            Self::Value(value) => {
                writer.write_u8(0);
                value.write(writer);
            }
            Self::Array(values) => {
                writer.write_u8(1);
                writer.write_u8(values.len() as u8); // we accept up to 255 values
                for value in values {
                    value.write(writer);    
                }
            }
            Self::Fields(fields) => {
                writer.write_u8(2);
                writer.write_u8(fields.len() as u8);
                for (key, value) in fields {
                    key.write(writer);
                    value.write(writer);
                }
            }
        }
    }

    fn size(&self) -> usize {
        1 + match self {
            Self::Value(value) => value.size(),
            Self::Array(values) => {
                let mut size = 1;
                for value in values {
                    size += value.size();
                }
                size
            },
            Self::Fields(fields) => {
                let mut size = 1;
                for (key, value) in fields {
                    size += key.size() + value.size();
                }
                size
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
#[serde(untagged)]
pub enum DataValue {
    Bool(bool),
    String(String),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    Hash(Hash),
    // This is a specific type for optimized size of binary data
    // Because above variants rewrite for each element the byte of the element and of each value
    // It supports up to 65535 bytes (u16::MAX)
    Blob(Vec<u8>),
}

impl DataValue {
    pub fn kind(&self) -> ValueType {
        match self {
            Self::Bool(_) => ValueType::Bool,
            Self::String(_) => ValueType::String,
            Self::U8(_) => ValueType::U8,
            Self::U16(_) => ValueType::U16,
            Self::U32(_) => ValueType::U32,
            Self::U64(_) => ValueType::U64,
            Self::U128(_) => ValueType::U128,
            Self::Hash(_) => ValueType::Hash,
            Self::Blob(_) => ValueType::Blob
        }
    }

    pub fn to_bool(self) -> Result<bool, DataConversionError> {
        match self {
            Self::Bool(v) => Ok(v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn to_string(self) -> Result<String, DataConversionError> {
        match self {
            Self::String(v) => Ok(v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn to_u8(self) -> Result<u8, DataConversionError> {
        match self {
            Self::U8(v) => Ok(v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn to_u16(self) -> Result<u16, DataConversionError> {
        match self {
            Self::U16(v) => Ok(v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn to_u32(self) -> Result<u32, DataConversionError> {
        match self {
            Self::U32(v) => Ok(v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn to_u64(self) -> Result<u64, DataConversionError> {
        match self {
            Self::U64(v) => Ok(v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn to_u128(self) -> Result<u128, DataConversionError> {
        match self {
            Self::U128(v) => Ok(v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn to_hash(self) -> Result<Hash, DataConversionError> {
        match self {
            Self::Hash(v) => Ok(v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn to_blob(self) -> Result<Vec<u8>, DataConversionError> {
        match self {
            Self::Blob(v) => Ok(v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn to_type<T: Serializer>(self) -> Result<T, DataConversionError> {
        match &self {
            Self::Blob(v) => T::from_bytes(&v).map_err(|_| DataConversionError::UnexpectedValue(self.kind())),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn as_bool(&self) -> Result<bool, DataConversionError> {
        match self {
            Self::Bool(v) => Ok(*v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn as_string(&self) -> Result<&String, DataConversionError> {
        match self {
            Self::String(v) => Ok(v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn as_u8(&self) -> Result<u8, DataConversionError> {
        match self {
            Self::U8(v) => Ok(*v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn as_u16(&self) -> Result<u16, DataConversionError> {
        match self {
            Self::U16(v) => Ok(*v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn as_u32(&self) -> Result<u32, DataConversionError> {
        match self {
            Self::U32(v) => Ok(*v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn as_u64(&self) -> Result<u64, DataConversionError> {
        match self {
            Self::U64(v) => Ok(*v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn as_u128(&self) -> Result<u128, DataConversionError> {
        match self {
            Self::U128(v) => Ok(*v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    pub fn as_hash(&self) -> Result<&Hash, DataConversionError> {
        match self {
            Self::Hash(v) => Ok(v),
            _ => Err(DataConversionError::UnexpectedValue(self.kind()))
        }
    }

    fn read_with_type(reader: &mut Reader, value_type: ValueType) -> Result<Self, ReaderError> {
        Ok(match value_type {
            ValueType::Bool => Self::Bool(reader.read_bool()?),
            ValueType::String => Self::String(reader.read_string()?),
            ValueType::U8 => Self::U8(reader.read_u8()?),
            ValueType::U16 => Self::U16(reader.read_u16()?),
            ValueType::U32 => Self::U32(reader.read_u32()?),
            ValueType::U64 => Self::U64(reader.read_u64()?),
            ValueType::U128 => Self::U128(reader.read_u128()?),
            ValueType::Hash => Self::Hash(reader.read_hash()?),
            ValueType::Blob => Self::Blob(Vec::read(reader)?)
        })
    }

    fn write_no_type(&self, writer: &mut Writer) {
        match self {
            Self::Bool(bool) => {
                writer.write_bool(*bool);
            },
            Self::String(string) => {
                string.write(writer);
            },
            Self::U8(value) => {
                writer.write_u8(*value);
            },
            Self::U16(value) => {
                writer.write_u16(*value);
            },
            Self::U32(value) => {
                writer.write_u32(value);
            },
            Self::U64(value) => {
                writer.write_u64(value);
            },
            Self::U128(value) => {
                writer.write_u128(value);
            },
            Self::Hash(hash) => {
                writer.write_hash(hash);
            },
            Self::Blob(blob) => {
                blob.write(writer);
            }
        };
    }
}

impl ToString for DataValue {
    fn to_string(&self) -> String {
        match self {
            Self::Bool(v) => format!("{}", v),
            Self::String(v) => format!("{}", v),
            Self::U8(v) => format!("{}", v),
            Self::U16(v) => format!("{}", v),
            Self::U32(v) => format!("{}", v),
            Self::U64(v) => format!("{}", v),
            Self::U128(v) => format!("{}", v),
            Self::Hash(v) => format!("{}", v),
            Self::Blob(v) => format!("{:?}", v)
        }
    }
}

impl Serializer for DataValue {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let value_type = ValueType::read(reader)?;
        Self::read_with_type(reader, value_type)
    }

    fn write(&self, writer: &mut Writer) {
        self.kind().write(writer);
        self.write_no_type(writer);
    }

    fn size(&self) -> usize {
        let size = match self {
            Self::Bool(v) => v.size(),
            Self::String(v) => v.size(),
            Self::U8(v) => v.size(),
            Self::U16(v) => v.size(),
            Self::U32(v) => v.size(),
            Self::U64(v) => v.size(),
            Self::U128(v) => v.size(),
            Self::Hash(hash) => hash.size(),
            Self::Blob(blob) => blob.size()
        };
        // 1 byte for the type
        size + 1
    }
}

macro_rules! impl_data_value_vec {
    ($(($type:ident, $type2:ident)),*) => {
        $(
            impl From<Vec<$type2>> for DataElement {
                fn from(value: Vec<$type2>) -> Self {
                    Self::Array(value.into_iter().map(|v| v.into()).collect())
                }
            }

            impl TryInto<Vec<$type2>> for DataElement {
                type Error = DataConversionError;

                fn try_into(self) -> Result<Vec<$type2>, Self::Error> {
                    match self {
                        Self::Array(v) => v.into_iter().map(|v| v.try_into()).collect(),
                        _ => Err(DataConversionError::ExpectedArray)
                    }
                }
            }
        )*
    };

}
macro_rules! impl_data_value {
    ($(($type:ident, $type2:ident)),*) => {
        $(
            impl From<$type2> for DataValue {
                fn from(value: $type2) -> Self {
                    Self::$type(value)
                }
            }

            impl From<$type2> for DataElement {
                fn from(value: $type2) -> Self {
                    DataElement::Value(value.into())
                }
            }

            impl TryInto<$type2> for DataValue {
                type Error = DataConversionError;

                fn try_into(self) -> Result<$type2, Self::Error> {
                    match self {
                        Self::$type(v) => Ok(v),
                        _ => Err(DataConversionError::UnexpectedValue(self.kind()))
                    }
                }
            }

            impl TryInto<$type2> for DataElement {
                type Error = DataConversionError;

                fn try_into(self) -> Result<$type2, Self::Error> {
                    match self {
                        DataElement::Value(v) => v.try_into(),
                        _ => Err(DataConversionError::ExpectedValue)
                    }
                }
            }
        )*
    };
}

type Blob = Vec<u8>;

impl_data_value!(
    (String, String),
    (Hash, Hash),
    (U8, u8),
    (U16, u16),
    (U32, u32),
    (U64, u64),
    (U128, u128),
    (Bool, bool),
    (Blob, Blob)
);

// u8 is missing because it's already implemented by Blob type
impl_data_value_vec!(
    (String, String),
    (Hash, Hash),
    (U16, u16),
    (U32, u32),
    (U64, u64),
    (U128, u128),
    (Bool, bool),
    (Blob, Blob)
);

// Special case
impl From<&str> for DataValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}

impl From<&str> for DataElement {
    fn from(value: &str) -> Self {
        DataElement::Value(value.into())
    }
}

impl From<Vec<&str>> for DataElement {
    fn from(value: Vec<&str>) -> Self {
        Self::Array(value.into_iter().map(|v| v.into()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_into() {
        let value = DataValue::U8(10);
        let element = DataElement::Value(value.clone());
        assert_eq!(element.size(), element.to_bytes().len());
        let value2: u8 = element.try_into().unwrap();
        assert_eq!(value2, 10);

        let array: DataElement = vec![0u64, 24u64, 37u64, 55u64].into();
        let array2: Vec<u64> = array.try_into().unwrap();
        assert_eq!(array2, vec![0, 24, 37, 55]);
    }

    #[test]
    fn test_serialize_vec_u64() {
        let val = vec![0u64; 5];
        let data: DataElement = val.clone().into();
        let elem = DataElement::from_bytes(&data.to_bytes()).unwrap();
        assert_eq!(data, elem);
        assert_eq!(data.size(), elem.to_bytes().len());

        let val2: Vec<u64> = elem.try_into().unwrap();
        assert_eq!(val, val2);
    }

    #[test]
    fn test_blob() {
        let data = vec![0u8; 1000];
        let element: DataElement = data.clone().into();
        let element2: Vec<u8> = element.try_into().unwrap();
        assert_eq!(data, element2);

        let json = "[0, 55, 77, 99, 88, 77]";
        let element: DataElement = serde_json::from_str(json).unwrap();
        assert_eq!(element.kind(), ElementType::Value(ValueType::Blob));
    }

    #[test]
    fn test_array() {
        // Mixed types
        let json = "[0, 55, 77, 99, 88, 77, false]";
        let element: DataElement = serde_json::from_str(json).unwrap();
        assert_eq!(element.kind(), ElementType::Array);

        // Using integer types
        let json = "[0, 55, 77, 99, 88, 777777]";
        let element: DataElement = serde_json::from_str(json).unwrap();
        assert_eq!(element.kind(), ElementType::Array);
    }

    #[test]
    fn test_map() {
        let json = r#"{"name": "John", "age": 25, "is_active": true}"#;
        let element: DataElement = serde_json::from_str(json).unwrap();
        assert_eq!(element.kind(), ElementType::Fields);

        let bytes = element.to_bytes();
        let element2 = DataElement::from_bytes(&bytes).unwrap();
        assert_eq!(element, element2);
    }

    #[test]
    fn test_map_array() {
        let json = r#"{"name": "John", "age": 25, "is_active": true, "friends": [0, 1, 2, 3, 4]}"#;
        let element: DataElement = serde_json::from_str(json).unwrap();
        assert_eq!(element.kind(), ElementType::Fields);

        let bytes = element.to_bytes();
        let element2 = DataElement::from_bytes(&bytes).unwrap();
        assert_eq!(element, element2);
    }

    #[test]
    fn test_dummy_struct() {
        #[derive(Debug, Serialize, Deserialize, Clone)]
        struct Dummy {
            name: String,
            age: u8,
            is_active: bool,
            friends: Vec<u8>
        }

        impl Serializer for Dummy {
            fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
                let name = String::read(reader)?;
                let age = u8::read(reader)?;
                let is_active = bool::read(reader)?;
                let friends = Vec::<u8>::read(reader)?;
                Ok(Self {
                    name,
                    age,
                    is_active,
                    friends
                })
            }

            fn write(&self, writer: &mut Writer) {
                self.name.write(writer);
                self.age.write(writer);
                self.is_active.write(writer);
                self.friends.write(writer);
            }
        }

        let dummy = Dummy {
            name: "John".to_string(),
            age: 25,
            is_active: true,
            friends: vec![0, 1, 2, 3, 4]
        };

        let value = DataValue::Blob(dummy.to_bytes());
        assert_eq!(value.kind(), ValueType::Blob);

        let dummy: Dummy = value.to_type().unwrap();
        assert_eq!(dummy.name, "John");
        assert_eq!(dummy.age, 25);
        assert_eq!(dummy.is_active, true);
        assert_eq!(dummy.friends, vec![0, 1, 2, 3, 4]);
    }
}