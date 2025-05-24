use std::{
    fmt::{self, Display},
    hash::{Hash, Hasher},
    ops::Deref,
    sync::Arc
};
use serde::{Serialize, Deserialize};

use crate::serializer::*;

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Immutable<T> {
    Owned(T),
    Arc(Arc<T>)
}

impl<T> Immutable<T> {
    pub fn get_inner(&self) -> &T {
        match &self {
            Immutable::Owned(v) => v,
            Immutable::Arc(v) => v
        }
    }

    pub fn into_arc(self) -> Arc<T> {
        match self {
            Immutable::Owned(v) => Arc::new(v),
            Immutable::Arc(v) => v
        }
    }
}

impl<T: Clone> Immutable<T> {
    pub fn make_arc(&mut self) -> Arc<T> {
        match self {
            Immutable::Owned(v) => {
                // Replace self with Immutable::Arc
                let arc = Arc::new(v.clone());
                *self = Immutable::Arc(arc.clone());
                arc
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

impl<T: Hash> Hash for Immutable<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl<T: PartialEq> PartialEq for Immutable<T> {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl<T: Eq> Eq for Immutable<T> {}


impl<T> AsRef<T> for Immutable<T> {
    fn as_ref(&self) -> &T {
        self.get_inner()
    }
}

impl<T> From<T> for Immutable<T> {
    fn from(v: T) -> Self {
        Immutable::Owned(v)
    }
}

impl<T> From<Arc<T>> for Immutable<T> {
    fn from(v: Arc<T>) -> Self {
        Immutable::Arc(v)
    }
}

impl<T> Deref for Immutable<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.get_inner()        
    }
}

impl<T: fmt::Display> Display for Immutable<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Immutable::Owned(v) => write!(f, "{}", v),
            Immutable::Arc(v) => write!(f, "{}", v)
        }
    }
}

impl<T: Serializer> Serializer for Immutable<T> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Immutable::Owned(T::read(reader)?))
    }

    fn write(&self, writer: &mut Writer) {
        self.as_ref().write(writer);
    }

    fn size(&self) -> usize {
        self.as_ref().size()
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use super::*;

    #[test]
    fn test_eq() {
        assert!(Immutable::Owned(()) == Immutable::Arc(Arc::new(())));
    }

    #[test]
    fn test_hash() {
        let owned = Immutable::Owned(());
        let arc = Immutable::Arc(Arc::new(()));

        let mut hasher = DefaultHasher::new();
        owned.hash(&mut hasher);
        let owned_hash = hasher.finish();

        let mut hasher = DefaultHasher::new();
        arc.hash(&mut hasher);
        let arc_hash = hasher.finish();

        assert_eq!(owned_hash, arc_hash);
    }
}