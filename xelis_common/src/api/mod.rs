use std::{collections::HashMap, borrow::Cow};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use crate::{
    serializer::{Serializer, Reader, ReaderError, Writer},
    crypto::Hash
};

pub mod wallet;
pub mod daemon;
pub mod query;

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
    UnexpectedValue(DataType),
}

// All types availables
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Clone, Copy)]
pub enum DataType {
    Bool,
    String,
    U8,
    U16,
    U32,
    U64,
    U128,
    Hash,
    Array,
    Fields,
    Undefined
}

impl DataType {
    pub fn is_data(&self) -> bool {
        match self {
            Self::Bool |
            Self::String |
            Self::Hash |
            Self::U128 |
            Self::U64 |
            Self::U32 |
            Self::U16 |
            Self::U8 => true,
            _ => false
        }
    }

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

// This enum allows complex structures with multi depth if necessary
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum DataElement {
    // Value can be Optional to represent null in JSON
    Value(Option<DataValue>),
    // For two next variants, we support up to 255 (u8::MAX) elements maximum
    Array(Vec<DataElement>),
    Fields(HashMap<DataValue, DataElement>)
}

impl DataElement {
    pub fn has_key(&self, key: &DataValue) -> bool {
        let Self::Fields(fields) = &self else {
            return false
        };

        fields.contains_key(key)
    }

    pub fn get_value_by_key(&self, key: &DataValue, data_type: Option<DataType>) -> Option<&DataValue> {
        let Self::Fields(data) = &self else {
            return None
        };

        let Self::Value(value) = data.get(key)? else {
            return None;
        };

        let Some(unwrapped) = &value else {
            return None;
        };

        if let Some(data_type) = data_type {
            if unwrapped.kind() != data_type {
                return None
            }
        }

        value.as_ref()
    }

    pub fn get_value_by_string_key(&self, name: String, data_type: DataType) -> Option<&DataValue> {
        self.get_value_by_key(&DataValue::String(name), Some(data_type))
    }

    pub fn kind(&self) -> DataType {
        match self {
            Self::Array(_) => DataType::Array,
            Self::Fields(_) => DataType::Fields,
            Self::Value(value) => match value {
                Some(v) => v.kind(),
                None => DataType::Undefined
            }
        }
    }

    pub fn is_null(&self) -> bool {
        match self {
            Self::Value(None) => true,
            _ => false
        }
    }

    pub fn to_value(self) -> Result<DataValue, DataConversionError> {
        match self {
            Self::Value(Some(v)) => Ok(v),
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
            Self::Value(Some(v)) => Ok(v),
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
            0 => Self::Value(Option::<DataValue>::read(reader)?),
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
}

impl DataValue {
    pub fn kind(&self) -> DataType {
        match self {
            Self::Bool(_) => DataType::Bool,
            Self::String(_) => DataType::String,
            Self::U8(_) => DataType::U8,
            Self::U16(_) => DataType::U16,
            Self::U32(_) => DataType::U32,
            Self::U64(_) => DataType::U64,
            Self::U128(_) => DataType::U128,
            Self::Hash(_) => DataType::Hash
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
            Self::Hash(v) => format!("{}", v)
        }
    }
}

impl Serializer for DataValue {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => Self::Bool(reader.read_bool()?),
            1 => Self::String(reader.read_string()?),
            2 => Self::U8(reader.read_u8()?),
            3 => Self::U16(reader.read_u16()?),
            4 => Self::U32(reader.read_u32()?),
            5 => Self::U64(reader.read_u64()?),
            6 => Self::U128(reader.read_u128()?),
            7 => Self::Hash(reader.read_hash()?),
            _ => return Err(ReaderError::InvalidValue)
        })
    }

    fn write(&self, writer: &mut Writer) {
        match self {
            Self::Bool(bool) => {
                writer.write_u8(0);
                writer.write_bool(*bool);
            },
            Self::String(string) => {
                writer.write_u8(1);
                string.write(writer);
            },
            Self::U8(value) => {
                writer.write_u8(2);
                writer.write_u8(*value);
            },
            Self::U16(value) => {
                writer.write_u8(3);
                writer.write_u16(*value);
            },
            Self::U32(value) => {
                writer.write_u8(4);
                writer.write_u32(value);
            },
            Self::U64(value) => {
                writer.write_u8(5);
                writer.write_u64(value);
            },
            Self::U128(value) => {
                writer.write_u8(6);
                writer.write_u128(value);
            },
            Self::Hash(hash) => {
                writer.write_u8(7);
                writer.write_hash(hash);
            }
        };
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
            Self::Hash(hash) => hash.size()
        };
        // 1 byte for the type
        size + 1
    }
}

#[derive(Serialize, Deserialize)]
pub struct SubscribeParams<'a, E: Clone> {
    pub notify: Cow<'a, E>
}

#[derive(Serialize, Deserialize)]
pub struct EventResult<'a, E: Clone> {
    pub event: Cow<'a, E>,
    #[serde(flatten)]
    pub value: Value
}

#[derive(Serialize, Deserialize)]
pub struct DataHash<'a, T: Clone> {
    pub hash: Cow<'a, Hash>,
    #[serde(flatten)]
    pub data: Cow<'a, T>
}
