use std::collections::HashMap;

use thiserror::Error;
use crate::crypto::Hash;
use crate::serializer::Serializer;

#[derive(Error, Debug)]
pub enum ArgError {
    #[error("Invalid value for this argument type")]
    InvalidType,
    #[error("Argument '{}' not found", _0)]
    NotFound(String)
}

pub enum ArgValue {
    Bool(bool),
    Number(u64),
    String(String),
    Hash(Hash),
    Array(Vec<ArgValue>)
}

impl ArgValue {
    pub fn to_bool(self) -> Result<bool, ArgError> {
        match self {
            ArgValue::Bool(b) => Ok(b),
            _ => Err(ArgError::InvalidType)
        }
    }

    pub fn to_number(self) -> Result<u64, ArgError> {
        match self {
            ArgValue::Number(n) => Ok(n),
            _ => Err(ArgError::InvalidType)
        }
    }

    pub fn to_string_value(self) -> Result<String, ArgError> {
        match self {
            ArgValue::String(s) => Ok(s),
            _ => Err(ArgError::InvalidType)
        }
    }

    pub fn to_hash(self) -> Result<Hash, ArgError> {
        match self {
            ArgValue::Hash(hash) => Ok(hash),
            _ => Err(ArgError::InvalidType)
        }
    }

    pub fn to_vec(self) -> Result<Vec<ArgValue>, ArgError> {
        match self {
            ArgValue::Array(v) => Ok(v),
            _ => Err(ArgError::InvalidType)
        }
    }
}

pub enum ArgType {
    Bool,
    Number,
    String,
    Hash,
    Array(Box<ArgType>),
}

impl ArgType {
    pub fn to_value(&self, value: &str) -> Result<ArgValue, ArgError> {
        Ok(match self {
            ArgType::Bool => ArgValue::Bool(value.parse().map_err(|_| ArgError::InvalidType)?),
            ArgType::Number => ArgValue::Number(value.parse().map_err(|_| ArgError::InvalidType)?),
            ArgType::String => ArgValue::String(value.to_owned()),
            ArgType::Hash => ArgValue::Hash(Hash::from_hex(value.to_string()).map_err(|_| ArgError::InvalidType)?),
            ArgType::Array(value_type) => {
                let values = value.split(",");
                let mut array: Vec<ArgValue> = Vec::new();
                for value in values {
                    let arg_value = value_type.to_value(value)?;
                    array.push(arg_value);
                }
                ArgValue::Array(array)
            }
        })
    }
}

pub struct Arg {
    name: String,
    arg_type: ArgType
}

impl Arg {
    pub fn new(name: &str, arg_type: ArgType) -> Self {
        Self {
            name: name.to_owned(),
            arg_type
        }
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_type(&self) -> &ArgType {
        &self.arg_type
    }
}

pub struct ArgumentManager {
    arguments: HashMap<String, ArgValue>
}

impl ArgumentManager {
    pub fn new(arguments: HashMap<String, ArgValue>) -> Self {
        Self {
            arguments
        }
    }

    pub fn get_arguments(&self) -> &HashMap<String, ArgValue> {
        &self.arguments
    }

    pub fn get_value(&mut self, name: &str) -> Result<ArgValue, ArgError> {
        self.arguments.remove(name).ok_or_else(|| ArgError::NotFound(name.to_owned()))
    }

    pub fn has_argument(&self, name: &str) -> bool {
        self.arguments.contains_key(name)
    }

    pub fn size(&self) -> usize {
        self.arguments.len()
    }
}