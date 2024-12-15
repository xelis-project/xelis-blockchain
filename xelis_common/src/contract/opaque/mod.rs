mod transaction;
mod hash;
mod address;
mod random;

use log::debug;
use xelis_types::register_opaque as r_op;
use xelis_vm::OpaqueWrapper;

pub use transaction::*;
pub use random::*;

use crate::{
    crypto::{Address, Hash},
    serializer::*
};

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
    fn write(&self, _: &mut Writer) {
        todo!("write opaque wrapper")
    }

    fn read(_: &mut Reader) -> Result<Self, ReaderError> {
        todo!("read opaque wrapper")
    }
}