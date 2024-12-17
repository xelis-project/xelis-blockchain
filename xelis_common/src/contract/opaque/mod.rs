mod transaction;
mod hash;
mod address;
mod random;
mod block;

use log::debug;
use xelis_types::{
    register_opaque_json,
    impl_opaque_json
};
use xelis_vm::OpaqueWrapper;

pub use transaction::*;
pub use hash::*;
pub use random::*;
pub use block::*;

use crate::{
    crypto::{Address, Hash},
    serializer::*
};

pub const HASH_OPAQUE_ID: u8 = 0;
pub const ADDRESS_OPAQUE_ID: u8 = 1;

impl_opaque_json!("Hash", Hash);
impl_opaque_json!("Address", Address);

pub fn register_opaque_types() {
    debug!("Registering opaque types");
    register_opaque_json!("Hash", Hash);
    register_opaque_json!("Address", Address);
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