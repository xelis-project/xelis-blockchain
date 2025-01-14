mod transaction;
mod hash;
mod address;
mod random;
mod block;
mod storage;
mod asset;

use log::debug;
use xelis_types::{
    register_opaque_json,
    impl_opaque
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
pub use asset::*;

pub const HASH_OPAQUE_ID: u8 = 0;
pub const ADDRESS_OPAQUE_ID: u8 = 1;

impl_opaque!(
    "Hash",
    Hash,
    display,
    json
);
impl_opaque!(
    "Address",
    Address,
    display,
    json
);
impl_opaque!(
    "OpaqueTransaction",
    OpaqueTransaction
);
impl_opaque!(
    "OpaqueBlock",
    OpaqueBlock
);
impl_opaque!(
    "OpaqueRandom",
    OpaqueRandom
);
impl_opaque!(
    "OpaqueStorage",
    OpaqueStorage
);
impl_opaque!(
    "Asset",
    OpaqueAsset
);

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

#[cfg(test)]
mod tests {
    use crate::crypto::KeyPair;

    use super::*;
    use serde_json::json;
    use xelis_vm::OpaqueWrapper;

    #[test]
    fn test_address_serde() {
        register_opaque_types();
        
        let address = KeyPair::new().get_public_key().to_address(true);
        let opaque = OpaqueWrapper::new(address.clone());
        let v = json!(opaque);

        let opaque: OpaqueWrapper = serde_json::from_value(v)
            .unwrap();
        let address2: Address = opaque.into_inner()
            .expect("Failed to unwrap");

        assert_eq!(address, address2);
    }

    #[test]
    fn test_hash_serde() {
        register_opaque_types();
        
        let hash = Hash::max();
        let opaque = OpaqueWrapper::new(hash.clone());
        let v = json!(opaque);

        let opaque: OpaqueWrapper = serde_json::from_value(v)
            .unwrap();
        let hash2: Hash = opaque.into_inner()
            .expect("Failed to unwrap");

        assert_eq!(hash, hash2);
    }
}