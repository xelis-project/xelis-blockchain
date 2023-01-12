use std::{/*rc::Rc,*/ sync::Arc, ops::Deref};

use serde::Serialize;

#[derive(Clone, Serialize, Debug, Eq, Hash, PartialEq)]
#[serde(untagged)]
pub enum Immutable<T: Clone> {
    Owned(T),
    Arc(Arc<T>),
    //Rc(Rc<T>),
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
}

impl<T: Clone> Deref for Immutable<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.get_inner()        
    }
}