use indexmap::IndexSet;
use serde::{Deserialize, Serialize};

use crate::{crypto::Hash, serializer::*};

// Permission system for the smart contracts
// These permissions are used to restrict access to certain inter-contracts.
// This permission is checked when any contract tries to call another contract
// within the same transaction context.
// By default, the permission is None, meaning that the contract cannot call any other contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterContractPermission {
    // Cannot call any external contract
    // in your name. Only delegation calls are allowed.
    None,
    // Can call any external contract
    All,
    // Can call only specific contracts
    Specific(IndexSet<Hash>),
    // Can call any contract except specific ones
    Exclude(IndexSet<Hash>),
}

impl Default for InterContractPermission {
    fn default() -> Self {
        InterContractPermission::None
    }
}

impl InterContractPermission {
    // Check if the permission allows calling the target contract
    pub fn allows(&self, target: &Hash) -> bool {
        match self {
            InterContractPermission::None => false,
            InterContractPermission::All => true,
            InterContractPermission::Specific(allowed) => allowed.contains(target),
            InterContractPermission::Exclude(excluded) => !excluded.contains(target),
        }
    }
}

impl Serializer for InterContractPermission {
    fn write(&self, writer: &mut Writer) {
        match self {
            InterContractPermission::None => writer.write_u8(0),
            InterContractPermission::All => writer.write_u8(1),
            InterContractPermission::Specific(allowed) => {
                writer.write_u8(2);

                writer.write_u8(allowed.len() as u8);
                for hash in allowed {
                    hash.write(writer);
                }
            }
            InterContractPermission::Exclude(excluded) => {
                writer.write_u8(3);

                writer.write_u8(excluded.len() as u8);
                for hash in excluded {
                    hash.write(writer);
                }
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let tag = reader.read_u8()?;
        match tag {
            0 => Ok(InterContractPermission::None),
            1 => Ok(InterContractPermission::All),
            2 => {
                let len = reader.read_u8()? as usize;
                let mut allowed = IndexSet::with_capacity(len);
                for _ in 0..len {
                    let hash = Hash::read(reader)?;
                    if !allowed.insert(hash) {
                        return Err(ReaderError::InvalidValue);
                    }
                }

                Ok(InterContractPermission::Specific(allowed))
            }
            3 => {
                let len = reader.read_u8()? as usize;
                let mut excluded = IndexSet::with_capacity(len);
                for _ in 0..len {
                    let hash = Hash::read(reader)?;
                    if !excluded.insert(hash) {
                        return Err(ReaderError::InvalidValue);
                    }
                }

                Ok(InterContractPermission::Exclude(excluded))
            }
            _ => Err(ReaderError::InvalidValue),
        }
    }

    fn size(&self) -> usize {
        match self {
            InterContractPermission::None => 1,
            InterContractPermission::All => 1,
            InterContractPermission::Specific(allowed) => 1 + 1 + allowed.iter().map(|h| h.size()).sum::<usize>(),
            InterContractPermission::Exclude(excluded) => 1 + 1 + excluded.iter().map(|h| h.size()).sum::<usize>(),
        }
    }
}