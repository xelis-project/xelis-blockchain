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

    pub fn into_owned(self) -> T {
        match self {
            Immutable::Owned(v) => v,
            Immutable::Arc(v) => v.as_ref().clone()
        }
    }
}

impl<T: Clone> AsRef<T> for Immutable<T> {
    fn as_ref(&self) -> &T {
        self.get_inner()
    }
}

impl<T: Clone> Deref for Immutable<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.get_inner()        
    }
}