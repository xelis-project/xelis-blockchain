use crate::crypto::hash::Hash;
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct AssetInfo {
    identifier: Hash, // its identifier to be used in transactions 
    topoheight: u64 // its topoheight at which it got registered
}

impl AssetInfo {
    pub fn new(identifier: Hash, topoheight: u64) -> Self {
        Self {
            identifier,
            topoheight
        }
    }

    pub fn get_identifier(&self) -> &Hash {
        &self.identifier
    }

    pub fn to_indentifer(self) -> Hash {
        self.identifier
    }

    pub fn get_topoheight(&self) -> u64 {
        self.topoheight
    }
}