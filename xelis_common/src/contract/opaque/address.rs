use std::any::TypeId;
use xelis_vm::{traits::Serializable, Opaque};
use crate::crypto::Address;

use super::{Serializer, Writer, ADDRESS_OPAQUE_ID};

impl Serializable for Address {
    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(ADDRESS_OPAQUE_ID);
        self.write(&mut writer);
        writer.total_write()
    }
}

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