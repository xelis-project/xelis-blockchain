use std::any::TypeId;
use xelis_vm::Opaque;
use crate::crypto::Address;

impl Opaque for Address {
    fn get_type(&self) -> TypeId {
        TypeId::of::<Address>()
    }

    fn display(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Address({})", self)
    }

    fn clone_box(&self) -> Box<dyn Opaque> {
        Box::new(self.clone())
    }
}