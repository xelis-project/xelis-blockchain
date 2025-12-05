use std::{borrow::Borrow, hash};
use indexmap::{Equivalent, IndexSet};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{crypto::Hash, serializer::*};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContractCallChunk {
    // All chunks are allowed
    All,
    // Only the specified chunks are allowed
    Specific(IndexSet<u16>),
    // All chunks are allowed except the specified ones
    Exclude(IndexSet<u16>),
}

impl ContractCallChunk {
    pub fn allows(&self, chunk_id: u16) -> bool {
        match self {
            ContractCallChunk::All => true,
            ContractCallChunk::Specific(chunks) => chunks.contains(&chunk_id),
            ContractCallChunk::Exclude(chunks) => !chunks.contains(&chunk_id),
        }
    }
}

impl Serializer for ContractCallChunk {
    fn write(&self, writer: &mut Writer) {
        match self {
            ContractCallChunk::All => writer.write_u8(0),
            ContractCallChunk::Specific(chunks) => {
                writer.write_u8(1);
                writer.write_u8(chunks.len() as u8);
                for chunk in chunks {
                    writer.write_u16(*chunk);
                }
            }
            ContractCallChunk::Exclude(chunks) => {
                writer.write_u8(2);
                writer.write_u8(chunks.len() as u8);
                for chunk in chunks {
                    writer.write_u16(*chunk);
                }
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let tag = reader.read_u8()?;
        match tag {
            0 => Ok(ContractCallChunk::All),
            1 => {
                let len = reader.read_u8()? as usize;
                let mut chunks = IndexSet::with_capacity(len);
                for _ in 0..len {
                    let chunk = reader.read_u16()?;
                    if !chunks.insert(chunk) {
                        return Err(ReaderError::InvalidValue);
                    }
                }
                Ok(ContractCallChunk::Specific(chunks))
            }
            2 => {
                let len = reader.read_u8()? as usize;
                let mut chunks = IndexSet::with_capacity(len);
                for _ in 0..len {
                    let chunk = reader.read_u16()?;
                    if !chunks.insert(chunk) {
                        return Err(ReaderError::InvalidValue);
                    }
                }
                Ok(ContractCallChunk::Exclude(chunks))
            }
            _ => Err(ReaderError::InvalidValue),
        }
    }

    fn size(&self) -> usize {
        match self {
            ContractCallChunk::All => 1,
            ContractCallChunk::Specific(chunks) => 1 + 1 + chunks.len() * 2,
            ContractCallChunk::Exclude(chunks) => 1 + 1 + chunks.len() * 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ContractCall {
    pub contract: Hash,
    pub chunk: ContractCallChunk,
}

impl Serializer for ContractCall {
    fn write(&self, writer: &mut Writer) {
        self.contract.write(writer);
        self.chunk.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let contract = Hash::read(reader)?;
        let chunk = ContractCallChunk::read(reader)?;
        Ok(ContractCall { contract, chunk })
    }

    fn size(&self) -> usize {
        self.contract.size() + self.chunk.size()
    }
}

impl hash::Hash for ContractCall {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.contract.hash(state);
    }
}

impl PartialEq for ContractCall {
    fn eq(&self, other: &Self) -> bool {
        self.contract == other.contract
    }
}

impl Equivalent<Hash> for ContractCall {
    fn equivalent(&self, key: &Hash) -> bool {
        &self.contract == key
    }
}

impl Borrow<Hash> for ContractCall {
    fn borrow(&self) -> &Hash {
        &self.contract
    }
}

impl Eq for ContractCall {}

// Permission system for the smart contracts
// These permissions are used to restrict access to certain inter-contracts.
// This permission is checked when any contract tries to call another contract
// within the same transaction context.
// By default, the permission is None, meaning that the contract cannot call any other contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InterContractPermission {
    // Cannot call any external contract
    // in your name. Only delegation calls are allowed.
    None,
    // Can call any external contract
    All,
    // Can call only specific contracts
    Specific(IndexSet<ContractCall>),
    // Can call any contract except specific ones
    Exclude(IndexSet<ContractCall>),
}

impl Default for InterContractPermission {
    fn default() -> Self {
        InterContractPermission::None
    }
}

impl InterContractPermission {
    // Check if the permission allows calling the target contract
    pub fn allows(&self, target: &Hash, chunk_id: u16) -> bool {
        match self {
            InterContractPermission::None => false,
            InterContractPermission::All => true,
            InterContractPermission::Specific(allowed) => allowed.get(target)
                .map_or(false, |call| call.chunk.allows(chunk_id)),
            InterContractPermission::Exclude(excluded) => !excluded.get(target)
                .map_or(false, |call| call.chunk.allows(chunk_id)),
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
                    let call = ContractCall::read(reader)?;
                    if !allowed.insert(call) {
                        return Err(ReaderError::InvalidValue);
                    }
                }

                Ok(InterContractPermission::Specific(allowed))
            }
            3 => {
                let len = reader.read_u8()? as usize;
                let mut excluded = IndexSet::with_capacity(len);
                for _ in 0..len {
                    let call = ContractCall::read(reader)?;
                    if !excluded.insert(call) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_contract_call() {
        // Create a permission that allows calling specific contracts with specific chunks
        let permission = InterContractPermission::Specific(
            vec![
                ContractCall {
                    contract: Hash::new([1u8; 32]),
                    chunk: ContractCallChunk::All,
                },
                ContractCall {
                    contract: Hash::new([2u8; 32]),
                    chunk: ContractCallChunk::Specific(
                        vec![0, 1, 2].into_iter().collect()
                    ),
                },
                ContractCall {
                    contract: Hash::new([3u8; 32]),
                    chunk: ContractCallChunk::Exclude(
                        vec![5, 6].into_iter().collect()
                    ),
                },
            ].into_iter().collect()
        );

        // Allowed calls
        assert!(permission.allows(&Hash::new([1u8; 32]), 0));
        assert!(permission.allows(&Hash::new([1u8; 32]), 100));

        assert!(permission.allows(&Hash::new([2u8; 32]), 0));
        assert!(permission.allows(&Hash::new([2u8; 32]), 1));
        assert!(permission.allows(&Hash::new([2u8; 32]), 2));

        assert!(permission.allows(&Hash::new([3u8; 32]), 0));
        assert!(permission.allows(&Hash::new([3u8; 32]), 4));
        assert!(permission.allows(&Hash::new([3u8; 32]), 100));

        // Disallowed calls
        assert!(!permission.allows(&Hash::new([4u8; 32]), 0));
        assert!(!permission.allows(&Hash::new([4u8; 32]), 100));

        assert!(!permission.allows(&Hash::new([2u8; 32]), 3));
        assert!(!permission.allows(&Hash::new([2u8; 32]), 100));

        assert!(!permission.allows(&Hash::new([3u8; 32]), 5));
        assert!(!permission.allows(&Hash::new([3u8; 32]), 6));
    }
}