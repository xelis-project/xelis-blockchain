use std::{collections::HashMap, borrow::Cow};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::{serializer::{Serializer, Reader, ReaderError, Writer}, crypto::hash::Hash};

pub mod wallet;
pub mod daemon;

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
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
#[serde(untagged)]
pub enum DataValue {
    // represent a null value
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
                writer.write_string(string);
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
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryNumber {
    // >
    Above(usize),
    // >=
    AboveOrEqual(usize),
    // <
    Below(usize),
    // <=
    BelowOrEqual(usize),
}

impl QueryNumber {
    pub fn verify(&self, v: &DataValue) -> bool {
        match self {
            Self::Above(value) => match v {
                DataValue::U128(v) => *v > *value as u128,
                DataValue::U64(v) => *v > *value as u64,
                DataValue::U32(v) => *v > *value as u32,
                DataValue::U16(v) => *v > *value as u16,
                DataValue::U8(v) => *v > *value as u8,
                _ => false
            },
            Self::AboveOrEqual(value) => match v {
                DataValue::U128(v) => *v >= *value as u128,
                DataValue::U64(v) => *v >= *value as u64,
                DataValue::U32(v) => *v >= *value as u32,
                DataValue::U16(v) => *v >= *value as u16,
                DataValue::U8(v) => *v >= *value as u8,
                _ => false
            },
            Self::Below(value) => match v {
                DataValue::U128(v) => *v < *value as u128,
                DataValue::U64(v) => *v < *value as u64,
                DataValue::U32(v) => *v < *value as u32,
                DataValue::U16(v) => *v < *value as u16,
                DataValue::U8(v) => *v < *value as u8,
                _ => false
            },
            Self::BelowOrEqual(value) => match v {
                DataValue::U128(v) => *v <= *value as u128,
                DataValue::U64(v) => *v <= *value as u64,
                DataValue::U32(v) => *v <= *value as u32,
                DataValue::U16(v) => *v <= *value as u16,
                DataValue::U8(v) => *v <= *value as u8,
                _ => false
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryValue {
    // ==
    Equal(DataValue),
    // Following are transformed to string and compared
    StartsWith(DataValue),
    EndsWith(DataValue),
    ContainsValue(DataValue),
    // Regex pattern on DataValue only
    #[serde(with = "serde_regex")]
    Pattern(Regex),
    #[serde(untagged)]
    NumberOp(QueryNumber)
}

impl QueryValue {
    pub fn verify(&self, v: &DataValue) -> bool {
        match self {
            Self::Equal(expected) => *v == *expected,
            Self::StartsWith(value) => v.to_string().starts_with(&value.to_string()),
            Self::EndsWith(value) => v.to_string().starts_with(&value.to_string()),
            Self::ContainsValue(value) => v.to_string().contains(&value.to_string()),
            Self::Pattern(pattern) => pattern.is_match(&v.to_string()),
            Self::NumberOp(query) => query.verify(v)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Query {
    // !
    Not(Box<Query>),
    // &&
    And(Vec<Box<Query>>),
    // ||
    Or(Vec<Box<Query>>),
    // Check value type
    Type(DataType),
    #[serde(untagged)]
    Element(QueryElement),
    #[serde(untagged)]
    Value(QueryValue)
}

impl Query {
    pub fn verify_element(&self, element: &DataElement) -> bool {
        match self {
            Self::Element(query) => query.verify(element),
            Self::Value(query) => if let DataElement::Value(Some(value)) = element {
                query.verify(value)
            } else {
                false
            },
            Self::Not(op) => !op.verify_element(element),
            Self::Or(operations) => {
                for op in operations {
                    if op.verify_element(element) {
                        return true
                    }
                }
                false
            }
            Self::And(operations) => {
                for op in operations {
                    if !op.verify_element(element) {
                        return false
                    }
                }
                true
            },
            Self::Type(expected) => element.kind() == *expected,
        }
    }

    pub fn verify_value(&self, value: &DataValue) -> bool {
        match self {
            Self::Element(_) => false,
            Self::Value(query) => query.verify(value),
            Self::Not(op) => !op.verify_value(value),
            Self::Or(operations) => {
                for op in operations {
                    if op.verify_value(value) {
                        return true
                    }
                }
                false
            }
            Self::And(operations) => {
                for op in operations {
                    if !op.verify_value(value) {
                        return false
                    }
                }
                true
            },
            Self::Type(expected) => value.kind() == *expected,
        }
    }

    pub fn is_for_element(&self) -> bool {
        match self {
            Self::Element(_) => true,
            _ => false
        }
    }
}

// This is used to do query in daemon (in future for Smart Contracts) and wallet
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")] 
pub enum QueryElement {
    // Check if DataElement::Fields has key and optional check on value
    HasKey { key: DataValue, value: Option<Box<Query>> },
    // check the array
    ArrayLen(QueryNumber),
    // Only array supported
    ContainsElement(DataElement)
}

impl QueryElement {
    pub fn verify(&self, data: &DataElement) -> bool {
        match self {
            Self::HasKey { key, value } => if let DataElement::Fields(fields) = data {
                fields.get(key).map(|v|
                    if let Some(query) = value {
                        query.verify_element(v)
                    } else {
                        false
                    }
                ).unwrap_or(false)
            } else {
                false
            },
            Self::ArrayLen(query) => if let DataElement::Array(array) = data {
                query.verify(&DataValue::U64(array.len() as u64))
            } else {
                false
            },
            Self::ContainsElement(query) => match data {
                DataElement::Array(array) => array.contains(query),
                _ => false
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct QueryResult {
    pub entries: IndexMap<DataValue, DataElement>,
    pub next: Option<usize>
}

#[derive(Serialize, Deserialize)]
pub struct SubscribeParams<E> {
    pub notify: E
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
