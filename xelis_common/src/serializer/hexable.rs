use std::ops::{Deref, DerefMut};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Serializer;

/// Hexable is a wrapper around a type that implements `Serializer` and `Serialize`/`DeserializeOwned`.
/// It allows the type to be deserialized from an hexadecimal.
#[derive(Serialize, JsonSchema)]
pub struct Hexable<T: Serializer>(pub T);

impl<T: Serializer> Deref for Hexable<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Serializer> DerefMut for Hexable<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Serializer> From<T> for Hexable<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<'de, T: Serializer + Deserialize<'de>> Deserialize<'de> for Hexable<T> {
    fn deserialize<D>(deserializer: D) -> Result<Hexable<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(hex) => Ok(Self(T::from_hex(&hex).map_err(serde::de::Error::custom)?)),
            _ => {
                let inner = T::deserialize(value)
                    .map_err(serde::de::Error::custom)?;
                Ok(Self(inner))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serializer::{Reader, ReaderError, Writer};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Test {
        a: u32,
        b: String,
    }

    impl Serializer for Test {
        fn write(&self, writer: &mut Writer) {
            self.a.write(writer);
            self.b.write(writer);
        }

        fn read(reader: &mut Reader) -> Result<Self, ReaderError>
        where
            Self: Sized,
        {
            Ok(Self {
                a: u32::read(reader)?,
                b: String::read(reader)?,
            })
        }
    }

    #[test]
    fn test_hexable() {
        let test = Test { a: 42, b: "hello".to_string() };
        let hexable = Hexable::from(test.clone());

        let hex = serde_json::to_string(&hexable).unwrap();
        let hexable: Hexable<Test> = serde_json::from_str(&hex).unwrap();
        assert_eq!(*hexable, test);
    }

    #[test]
    fn test_from_json() {
        let test = r#"{"a":42,"b":"hello"}"#;
        let test2: Test = serde_json::from_str(test).unwrap();
        assert_eq!(test2, Test {
            a: 42,
            b: "hello".to_string(),
        });
    }

    #[test]
    fn test_from_hex() {
        let test = Test { a: 42, b: "hello".to_string() };
        let hex = test.to_hex();
        let hexable: Hexable<Test> = serde_json::from_str(&format!("\"{}\"", hex)).unwrap();
        assert_eq!(*hexable, test);
    }
}