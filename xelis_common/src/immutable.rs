use std::{fmt::{self, Display}, ops::Deref, sync::Arc};
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

    pub fn into_arc(&mut self) -> Arc<T> {
        match self {
            Immutable::Owned(v) => {
                let arced = Arc::new(v.clone());
                *self = Immutable::Arc(arced.clone());
                arced
            },
            Immutable::Arc(v) => v.clone()
        }
    }

    pub fn as_arc(&self) -> Arc<T> {
        match self {
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

    pub fn to_owned(&self) -> T {
        self.get_inner().clone()
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

impl<T: fmt::Display + Clone> Display for Immutable<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Immutable::Owned(v) => write!(f, "{}", v),
            Immutable::Arc(v) => write!(f, "{}", v)
        }
    }
}