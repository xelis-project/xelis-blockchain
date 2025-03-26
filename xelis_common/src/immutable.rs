use std::{sync::Arc, ops::Deref};

use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize, Debug, Eq, Hash, PartialEq)]
#[serde(untagged)]
pub enum Immutable<T: Clone> {
    Owned(T),
    Arc(Arc<T>)
}

impl<T: Clone> Immutable<T> {
    pub fn get_inner(&self) -> &T {
        match &self {
            Immutable::Owned(v) => v,
            Immutable::Arc(v) => v
        }
    }

    pub fn to_arc(self) -> Arc<T> {
        match self {
            Immutable::Owned(v) => Arc::new(v),
            Immutable::Arc(v) => v
        }
    }

    pub fn as_arc(&self) -> Arc<T> {
        match &self {
            Immutable::Owned(v) => Arc::new(v.clone()),
            Immutable::Arc(v) => v.clone()
        }
    }

    pub fn into_owned(self) -> T {
        match self {
            Immutable::Owned(v) => v,
            Immutable::Arc(v) => match Arc::try_unwrap(v) {
                Ok(v) => v,
                Err(v) => v.as_ref().clone()
            }
        }
    }
}

impl<T: Clone> AsRef<T> for Immutable<T> {
    fn as_ref(&self) -> &T {
        self.get_inner()
    }
}

impl<T: Clone> From<T> for Immutable<T> {
    fn from(v: T) -> Self {
        Immutable::Owned(v)
    }
}

impl<T: Clone> From<Arc<T>> for Immutable<T> {
    fn from(v: Arc<T>) -> Self {
        Immutable::Arc(v)
    }
}

impl<T: Clone> Deref for Immutable<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.get_inner()        
    }
}