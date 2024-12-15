use std::any::TypeId;
use xelis_vm::Opaque;
use crate::crypto::Hash;

impl Opaque for Hash {
    fn get_type(&self) -> TypeId {
        TypeId::of::<Hash>()
    }

    fn display(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Hash({})", self)
    }

    fn clone_box(&self) -> Box<dyn Opaque> {
        Box::new(self.clone())
    }
}