use std::{hash::{Hasher, BuildHasherDefault}, any::{TypeId, Any}, collections::HashMap};

use anyhow::{Result, Context as AnyContext};

// A hasher for `TypeId`s that takes advantage of its known characteristics.
#[derive(Debug, Default)]
pub struct NoOpHasher(u64);

impl Hasher for NoOpHasher {
    fn write(&mut self, _: &[u8]) {
        unimplemented!("This NoOpHasher can only handle u64s")
    }

    fn write_u64(&mut self, i: u64) {
        self.0 = i;
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

pub struct Context {
    values: HashMap<TypeId, Box<dyn Any + Send + Sync>, BuildHasherDefault<NoOpHasher>>,
}

impl Context {
    pub fn new() -> Self {
        Self {
            values: HashMap::default()
        }
    }

    pub fn store<T: Send + Sync + 'static>(&mut self, data: T) {
        self.values.insert(TypeId::of::<T>(), Box::new(data));
    }

    pub fn has<T: 'static>(&self) -> bool {
        self.values.contains_key(&TypeId::of::<T>())
    }

    pub fn get_optional<T: 'static>(&self) -> Option<&T> {
        self.values.get(&TypeId::of::<T>()).and_then(|b| b.downcast_ref())
    }

    pub fn get<T: 'static>(&self) -> Result<&T> {
        self.get_optional().context("Requested type not found")
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}