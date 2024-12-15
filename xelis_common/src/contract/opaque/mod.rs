mod transaction;
mod hash;
mod address;
mod random;

use log::debug;
use xelis_types::register_opaque as r_op;
use xelis_vm::OpaqueWrapper;

pub use transaction::*;
pub use hash::*;
pub use random::*;

use crate::{
    crypto::{Address, Hash},
    serializer::*
};

pub const HASH_OPAQUE_ID: u8 = 0;
pub const ADDRESS_OPAQUE_ID: u8 = 1;

macro_rules! register_opaque {
    ($name:literal, $opaque:ty) => {
        debug!("Registering opaque type: {}", $name);
        r_op!($name, $opaque);
    };
}

pub fn register_opaque_types() {
    debug!("Registering opaque types");
    register_opaque!("Transaction", OpaqueTransaction);
    register_opaque!("Hash", Hash);
    register_opaque!("Address", Address);
}

impl Serializer for OpaqueWrapper {
    fn write(&self, writer: &mut Writer) {
        self.inner().serialize(writer.as_mut_bytes());
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(match reader.read_u8()? {
            HASH_OPAQUE_ID => OpaqueWrapper::new(Hash::read(reader)?),
            ADDRESS_OPAQUE_ID => OpaqueWrapper::new(Address::read(reader)?),
            _ => return Err(ReaderError::InvalidValue)
        })
    }
}