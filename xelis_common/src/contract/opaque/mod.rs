mod transaction;
mod hash;
mod address;
mod random;
mod block;
mod storage;

use log::debug;
use xelis_types::{
    register_opaque_json,
    impl_opaque_json
};
use xelis_vm::{tid, OpaqueWrapper};
use crate::{
    block::Block,
    crypto::{Address, Hash},
    serializer::*,
    transaction::Transaction
};
use super::ChainState;

pub use transaction::*;
pub use hash::*;
pub use random::*;
pub use block::*;
pub use storage::*;
pub use address::*;


pub const HASH_OPAQUE_ID: u8 = 0;
pub const ADDRESS_OPAQUE_ID: u8 = 1;

impl_opaque_json!("Hash", Hash);
impl_opaque_json!("Address", Address);

// Injectable context data
tid!(ChainState<'_>);
tid!(Hash);
tid!(Transaction);
tid!(Block);

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