use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use super::{DataElement, DataValue, ElementType, ValueType};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryNumber {
    // >
    Greater(usize),
    // >=
    GreaterOrEqual(usize),
    // <
    Lesser(usize),
    // <=
    LesserOrEqual(usize),
}

impl QueryNumber {
    pub fn verify(&self, v: &DataValue) -> bool {
        match self {
            Self::Greater(value) => match v {
                DataValue::U128(v) => *v > *value as u128,
                DataValue::U64(v) => *v > *value as u64,
                DataValue::U32(v) => *v as usize > *value,
                DataValue::U16(v) => *v as usize > *value,
                DataValue::U8(v) => *v as usize > *value,
                _ => false
            },
            Self::GreaterOrEqual(value) => match v {
                DataValue::U128(v) => *v >= *value as u128,
                DataValue::U64(v) => *v >= *value as u64,
                DataValue::U32(v) => *v as usize >= *value,
                DataValue::U16(v) => *v as usize >= *value,
                DataValue::U8(v) => *v as usize >= *value,
                _ => false
            },
            Self::Lesser(value) => match v {
                DataValue::U128(v) => *v < *value as u128,
                DataValue::U64(v) => *v < *value as u64,
                DataValue::U32(v) => (*v as usize) < *value,
                DataValue::U16(v) => (*v as usize) < *value,
                DataValue::U8(v) => (*v as usize) < *value,
                _ => false
            },
            Self::LesserOrEqual(value) => match v {
                DataValue::U128(v) => *v <= *value as u128,
                DataValue::U64(v) => *v <= *value as u64,
                DataValue::U32(v) => *v as usize <= *value,
                DataValue::U16(v) => *v as usize <= *value,
                DataValue::U8(v) => *v as usize <= *value,
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
    // Check if value type is the one researched
    IsOfType(ValueType),
    // Regex pattern on DataValue only
    #[serde(with = "serde_regex")]
    Matches(Regex),
    #[serde(untagged)]
    NumberOp(QueryNumber)
}

impl QueryValue {
    pub fn verify(&self, v: &DataValue) -> bool {
        match self {
            Self::Equal(expected) => *v == *expected,
            Self::StartsWith(value) => v.to_string().starts_with(&value.to_string()),
            Self::EndsWith(value) => v.to_string().ends_with(&value.to_string()),
            Self::ContainsValue(value) => v.to_string().contains(&value.to_string()),
            Self::IsOfType(expected) => v.kind() == *expected,
            Self::Matches(pattern) => pattern.is_match(&v.to_string()),
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
    And(Vec<Query>),
    // ||
    Or(Vec<Query>),
    #[serde(untagged)]
    Element(QueryElement),
    #[serde(untagged)]
    Value(QueryValue)
}

impl Query {
    pub fn verify_element(&self, element: &DataElement) -> bool {
        match self {
            Self::Element(query) => query.verify(element),
            Self::Value(query) => if let DataElement::Value(value) = element {
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
            }
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
            }
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
    HasKey { key: DataValue, query: Option<Box<Query>> },
    // Check query on the value of the key
    AtKey { key: DataValue, query: Box<Query>},
    // check the array or map length
    Len(QueryNumber),
    // Only array supported
    ContainsElement(DataElement),
    // Verify with query the element at position
    // This is only for array
    AtPosition { position: usize, query: Box<Query> },
    // Check value type
    Type(ElementType),
}

impl QueryElement {
    pub fn verify(&self, data: &DataElement) -> bool {
        match self {
            Self::HasKey { key, query } => if let DataElement::Fields(fields) = data {
                fields.get(key).map(|v|
                    if let Some(query) = query {
                        query.verify_element(v)
                    } else {
                        false
                    }
                ).unwrap_or(false)
            } else {
                false
            },
            Self::AtKey { key, query } => if let DataElement::Fields(fields) = data {
                fields.get(key).map(|v| query.verify_element(v)).unwrap_or(false)
            } else {
                false
            },
            Self::Len(query) => match data {
                DataElement::Fields(fields) => query.verify(&DataValue::U8(fields.len() as u8)),
                DataElement::Array(array) => query.verify(&DataValue::U8(array.len() as u8)),
                _ => false
            },
            Self::ContainsElement(query) => match data {
                DataElement::Array(array) => array.contains(query),
                _ => false
            },
            Self::AtPosition { position, query } => if let DataElement::Array(array) = data {
                if let Some(element) = array.get(*position) {
                    query.verify_element(element)
                } else {
                    false
                }
            } else {
                false
            },
            Self::Type(expected) => data.kind() == *expected
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct QueryResult {
    pub entries: IndexMap<DataValue, DataElement>,
    pub next: Option<usize>
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn test_query_number() {
        let query = QueryNumber::Greater(5);
        assert!(query.verify(&DataValue::U8(6)));
        assert!(!query.verify(&DataValue::U8(5)));

        let query = QueryNumber::GreaterOrEqual(5);
        assert!(query.verify(&DataValue::U8(5)));
        assert!(query.verify(&DataValue::U8(6)));
        assert!(!query.verify(&DataValue::U8(4)));

        let query = QueryNumber::Lesser(5);
        assert!(query.verify(&DataValue::U8(4)));
        assert!(!query.verify(&DataValue::U8(5)));
        assert!(!query.verify(&DataValue::U8(6)));

        let query = QueryNumber::LesserOrEqual(5);
        assert!(query.verify(&DataValue::U8(4)));
        assert!(query.verify(&DataValue::U8(5)));
        assert!(!query.verify(&DataValue::U8(6)));
    }

    #[test]
    fn test_query_value() {
        let query = QueryValue::Equal(DataValue::U8(5));
        assert!(query.verify(&DataValue::U8(5)));
        assert!(!query.verify(&DataValue::U8(6)));

        let query = QueryValue::StartsWith(DataValue::String("hello".to_string()));
        assert!(query.verify(&DataValue::String("hello world".to_string())));
        assert!(!query.verify(&DataValue::String("world".to_string())));

        let query = QueryValue::EndsWith(DataValue::String("world".to_string()));
        assert!(query.verify(&DataValue::String("hello world".to_string())));
        assert!(!query.verify(&DataValue::String("hello".to_string())));

        let query = QueryValue::ContainsValue(DataValue::String("world".to_string()));
        assert!(query.verify(&DataValue::String("hello world".to_string())));
        assert!(!query.verify(&DataValue::String("hello".to_string())));

        let query = QueryValue::IsOfType(ValueType::String);
        assert!(query.verify(&DataValue::String("hello".to_string())));
        assert!(!query.verify(&DataValue::U8(5)));

        let query = QueryValue::Matches(Regex::new(r"^\d{3}-\d{3}-\d{4}$").unwrap());
        assert!(query.verify(&DataValue::String("123-456-7890".to_string())));
        assert!(!query.verify(&DataValue::String("hello".to_string())));
    }

    #[test]
    fn test_query_element() {
        let mut fields = HashMap::new();
        fields.insert(DataValue::String("owner".to_string()), DataElement::Value(DataValue::String("Slixe".to_string())));
        fields.insert(DataValue::String("balance".to_string()), DataElement::Value(DataValue::U8(25)));

        let element = DataElement::Fields(fields.clone());

        let query = QueryElement::HasKey {
            key: DataValue::String("owner".to_string()),
            query: Some(Box::new(Query::Value(QueryValue::Equal(DataValue::String("Slixe".to_string())))))
        };
        assert!(query.verify(&element));

        let query = QueryElement::AtKey {
            key: DataValue::String("balance".to_string()),
            query: Box::new(Query::Value(QueryValue::NumberOp(QueryNumber::Greater(20))))
        };
        assert!(query.verify(&element));

        let query = QueryElement::Len(QueryNumber::GreaterOrEqual(2));
        assert!(query.verify(&DataElement::Fields(fields.clone())));

        let query = QueryElement::ContainsElement(DataElement::Value(DataValue::String("Slixe".to_string())));
        assert!(query.verify(&DataElement::Array(vec![DataElement::Value(DataValue::String("Slixe".to_string()))])));

        let query = QueryElement::AtPosition {
            position: 0,
            query: Box::new(Query::Value(QueryValue::Equal(DataValue::String("Slixe".to_string()))))
        };
        assert!(query.verify(&DataElement::Array(vec![DataElement::Value(DataValue::String("Slixe".to_string()))])));

        let query = QueryElement::Type(ElementType::Fields);
        assert!(query.verify(&DataElement::Fields(fields)));
    }

    #[test]
    fn test_query_and() {
        let mut fields = HashMap::new();
        fields.insert(DataValue::String("owner".to_string()), DataElement::Value(DataValue::String("Slixe".to_string())));
        fields.insert(DataValue::String("balance".to_string()), DataElement::Value(DataValue::U8(25)));

        let element = DataElement::Fields(fields.clone());

        let query = Query::And(vec![
            Query::Element(QueryElement::HasKey {
                key: DataValue::String("owner".to_string()),
                query: Some(Box::new(Query::Value(QueryValue::Equal(DataValue::String("Slixe".to_string())))))
            }),
            Query::Element(QueryElement::AtKey {
                key: DataValue::String("balance".to_string()),
                query: Box::new(Query::Value(QueryValue::NumberOp(QueryNumber::Greater(20))))
            })
        ]);
        assert!(query.verify_element(&element));

        let query = Query::And(vec![
            Query::Element(QueryElement::HasKey {
                key: DataValue::String("owner".to_string()),
                query: Some(Box::new(Query::Value(QueryValue::Equal(DataValue::String("Slixe".to_string())))))
            }),
            Query::Element(QueryElement::AtKey {
                key: DataValue::String("balance".to_string()),
                query: Box::new(Query::Value(QueryValue::NumberOp(QueryNumber::Greater(30))))
            })
        ]);
        assert!(!query.verify_element(&element));
    }

    #[test]
    fn test_query_or() {
        let mut fields = HashMap::new();
        fields.insert(DataValue::String("owner".to_string()), DataElement::Value(DataValue::String("Slixe".to_string())));
        fields.insert(DataValue::String("balance".to_string()), DataElement::Value(DataValue::U8(25)));

        let element = DataElement::Fields(fields);

        let query = Query::Or(vec![
            Query::Element(QueryElement::AtKey {
                key: DataValue::String("balance".to_string()),
                query: Box::new(Query::Value(QueryValue::NumberOp(QueryNumber::Greater(30))))
            }),
            Query::Element(QueryElement::HasKey {
                key: DataValue::String("owner".to_string()),
                query: Some(Box::new(Query::Value(QueryValue::Equal(DataValue::String("Slixe".to_string())))))
            })
        ]);
        assert!(query.verify_element(&element));

        let query = Query::Or(vec![
            Query::Element(QueryElement::AtKey {
                key: DataValue::String("balance".to_string()),
                query: Box::new(Query::Value(QueryValue::NumberOp(QueryNumber::Greater(30))))
            }),
            Query::Not(Box::new(Query::Element(QueryElement::HasKey {
                key: DataValue::String("owner".to_string()),
                query: Some(Box::new(Query::Value(QueryValue::Equal(DataValue::String("Slixe".to_string())))))
            })))
        ]);
        assert!(!query.verify_element(&element));
    }
}