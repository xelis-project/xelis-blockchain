mod deploy;
mod invoke;

use anyhow::Context;
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use xelis_vm::{
    Chunk,
    Module,
    OpaqueWrapper,
    Primitive,
    ValueCell,
    U256
};
use crate::{
    crypto::{
        elgamal::{CompressedCommitment, CompressedHandle},
        proofs::CiphertextValidityProof
    },
    serializer::*
};

pub use deploy::*;
pub use invoke::*;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ContractDeposit {
    // Public deposit
    // The amount is the amount of the asset deposited
    // it is public and can be seen by anyone
    Public(u64),
    // Private deposit
    // The ciphertext represents the amount of the asset deposited
    Private {
        commitment: CompressedCommitment,
        // Sender handle is used to decrypt the commitment
        sender_handle: CompressedHandle,
        // Same as above, but for receiver
        receiver_handle: CompressedHandle,
        // The proof is a proof that the amount is a valid encryption
        // for the smart contract to be compatible with its encrypted balance.
        ct_validity_proof: CiphertextValidityProof,
    }
}

impl Serializer for ContractDeposit {
    fn write(&self, writer: &mut Writer) {
        match self {
            ContractDeposit::Public(amount) => {
                writer.write_u8(0);
                writer.write_u64(amount);
            },
            ContractDeposit::Private {
                commitment,
                sender_handle,
                receiver_handle,
                ct_validity_proof
            } => {
                writer.write_u8(1);
                commitment.write(writer);
                sender_handle.write(writer);
                receiver_handle.write(writer);
                ct_validity_proof.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<ContractDeposit, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => ContractDeposit::Public(reader.read_u64()?),
            1 => ContractDeposit::Private {
                commitment: CompressedCommitment::read(reader)?,
                sender_handle: CompressedHandle::read(reader)?,
                receiver_handle: CompressedHandle::read(reader)?,
                ct_validity_proof: CiphertextValidityProof::read(reader)?
            },
            _ => return Err(ReaderError::InvalidValue)
        })
    }

    fn size(&self) -> usize {
        1 + match self {
            ContractDeposit::Public(amount) => amount.size(),
            ContractDeposit::Private {
                commitment,
                sender_handle,
                receiver_handle,
                ct_validity_proof
            } => {
                commitment.size() + sender_handle.size() + receiver_handle.size() + ct_validity_proof.size()
            }
        }
    }
}

impl Serializer for U256 {
    fn write(&self, writer: &mut Writer) {
        writer.write_bytes(&self.to_be_bytes());
    }

    fn read(reader: &mut Reader) -> Result<U256, ReaderError> {
        Ok(U256::from_be_bytes(reader.read_bytes(32)?))
    }

    fn size(&self) -> usize {
        32
    }
}

impl Serializer for Primitive {
    fn write(&self, writer: &mut Writer) {
        match self {
            Primitive::Null => writer.write_u8(0),
            Primitive::U8(value) => {
                writer.write_u8(1);
                writer.write_u8(*value);
            },
            Primitive::U16(value) => {
                writer.write_u8(2);
                writer.write_u16(*value);
            },
            Primitive::U32(value) => {
                writer.write_u8(3);
                writer.write_u32(value);
            },
            Primitive::U64(value) => {
                writer.write_u8(4);
                writer.write_u64(value);
            },
            Primitive::U128(value) => {
                writer.write_u8(5);
                writer.write_u128(value);
            },
            Primitive::U256(value) => {
                writer.write_u8(6);
                value.write(writer);
            },
            Primitive::Boolean(value) => {
                writer.write_u8(7);
                writer.write_bool(*value);
            },
            Primitive::String(value) => {
                writer.write_u8(8);
                let bytes = value.as_bytes();
                writer.write_u16(bytes.len() as u16);
                writer.write_bytes(bytes);
            }
            Primitive::Range(range) => {
                writer.write_u8(9);
                range.0.write(writer);
                range.1.write(writer);
            },
            Primitive::Opaque(opaque) => {
                writer.write_u8(10);
                opaque.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Primitive, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => Primitive::Null,
            1 => Primitive::U8(reader.read_u8()?),
            2 => Primitive::U16(reader.read_u16()?),
            3 => Primitive::U32(reader.read_u32()?),
            4 => Primitive::U64(reader.read_u64()?),
            5 => Primitive::U128(reader.read_u128()?),
            6 => Primitive::U256(U256::read(reader)?),
            7 => Primitive::Boolean(reader.read_bool()?),
            8 => {
                let len = reader.read_u16()? as usize;
                Primitive::String(reader.read_string_with_size(len)?)
            },
            9 => {
                let left = Primitive::read(reader)?;
                if !left.is_number() {
                    return Err(ReaderError::InvalidValue);
                }

                let right = Primitive::read(reader)?;
                if !right.is_number() {
                    return Err(ReaderError::InvalidValue);
                }

                let left_type = left.get_type().context("left range type")?;
                let right_type = right.get_type().context("right range type")?;
                if left_type != right_type {
                    return Err(ReaderError::InvalidValue);
                }

                Primitive::Range(Box::new((left, right)))
            },
            10 => Primitive::Opaque(OpaqueWrapper::read(reader)?),
            _ => return Err(ReaderError::InvalidValue)
        })
    }

    fn size(&self) -> usize {
        1 + match self {
            Primitive::Null => 0,
            Primitive::U8(_) => 1,
            Primitive::U16(_) => 2,
            Primitive::U32(_) => 4,
            Primitive::U64(_) => 8,
            Primitive::U128(_) => 16,
            Primitive::U256(value) => value.size(),
            Primitive::Boolean(_) => 1,
            Primitive::String(value) => 2 + value.as_bytes().len(),
            Primitive::Range(range) => range.0.size() + range.1.size(),
            Primitive::Opaque(opaque) => opaque.size()
        }
    }
}

impl Serializer for ValueCell {
    // Serialize a value cell
    // ValueCell with more than one value are serialized in reverse order
    // This help us to save a reverse operation when deserializing
    fn write(&self, writer: &mut Writer) {
        match self {
            ValueCell::Default(value) => {
                writer.write_u8(0);
                value.write(writer);
            },
            ValueCell::Bytes(bytes) => {
                writer.write_u8(1);
                let len = bytes.len() as u32;
                writer.write_u32(&len);
                writer.write_bytes(bytes);
            }
            ValueCell::Array(values) => {
                writer.write_u8(2);
                let len = values.len() as u32;
                writer.write_u32(&len);
                for value in values.iter() {
                    value.write(writer);
                }
            },
            ValueCell::Map(map) => {
                writer.write_u8(3);
                let len = map.len() as u32;
                writer.write_u32(&len);
                for (key, value) in map.iter() {
                    key.write(writer);
                    value.write(writer);
                }
            }
        };
    }

    // No deserialization can occurs here as we're missing context
    fn read(reader: &mut Reader) -> Result<ValueCell, ReaderError> {
        // TODO: make it iterative and not recursive to prevent stack overflow attacks!!!!
        Ok(match reader.read_u8()? {
            0 => ValueCell::Default(Primitive::read(reader)?),
            1 => {
                let len = reader.read_u32()? as usize;
                ValueCell::Bytes(reader.read_bytes(len)?)
            },
            2 => {
                let len = reader.read_u32()? as usize;
                let mut values = Vec::new();
                for _ in 0..len {
                    values.push(ValueCell::read(reader)?);
                }
                ValueCell::Array(values)
            },
            3 => {
                let len = reader.read_u32()? as usize;
                let mut map = IndexMap::new();
                for _ in 0..len {
                    let key = ValueCell::read(reader)?;
                    let value = ValueCell::read(reader)?;
                    map.insert(key, value);
                }
                ValueCell::Map(map)
            },
            _ => return Err(ReaderError::InvalidValue)
        })
    }

    fn size(&self) -> usize {
        let mut total = 0;
        let mut stack = vec![self];

        while let Some(cell) = stack.pop() {
            // variant id
            total += 1;
            match cell {
                ValueCell::Default(value) => total += value.size(),
                ValueCell::Bytes(bytes) => {
                    // u32 len
                    total += 4;
                    total += bytes.len();
                },
                ValueCell::Array(values) => {
                    // u32 len
                    total += 4;
                    for value in values {
                        stack.push(value);
                    }
                },
                ValueCell::Map(map) => {
                    // u32 len
                    total += 4;
                    for (key, value) in map {
                        stack.push(value);
                        stack.push(key);
                    }
                }
            }
        }

        total
    }
}

impl Serializer for Module {
    fn write(&self, writer: &mut Writer) {
        let constants = self.constants();
        writer.write_u16(constants.len() as u16);
        for constant in constants {
            constant.write(writer);
        }

        let chunks = self.chunks();
        writer.write_u16(chunks.len() as u16);
        for chunk in chunks {
            let instructions = chunk.get_instructions();
            let len = instructions.len() as u32;
            writer.write_u32(&len);
            writer.write_bytes(instructions);
        }

        // Write entry ids
        let entry_ids = self.chunks_entry_ids();
        // We can have only up to u16::MAX chunks, so same for entry ids
        let len = entry_ids.len() as u16;
        writer.write_u16(len);

        for entry_id in entry_ids {
            writer.write_u16(*entry_id as u16);
        }

        let hooks = self.hook_chunk_ids();
        // We have only up to 255 hooks
        writer.write_u8(hooks.len() as u8);

        for (hook, chunk) in hooks {
            writer.write_u8(*hook);
            writer.write_u16(*chunk as u16);
        }
    }

    fn read(reader: &mut Reader) -> Result<Module, ReaderError> {
        let constants_len = reader.read_u16()?;
        let mut constants = IndexSet::with_capacity(constants_len as usize);

        for _ in 0..constants_len {
            let c = ValueCell::read(reader)?;
            if !constants.insert(c) {
                return Err(ReaderError::InvalidValue);
            }
        }

        let chunks_len = reader.read_u16()?;
        let mut chunks = Vec::with_capacity(chunks_len as usize);

        for _ in 0..chunks_len {
            let instructions_len = reader.read_u32()? as usize;
            let instructions: Vec<u8> = reader.read_bytes(instructions_len)?;
            chunks.push(Chunk::from_instructions(instructions));
        }

        let entry_ids_len = reader.read_u16()?;
        if entry_ids_len > chunks_len {
            return Err(ReaderError::InvalidValue);
        }

        let mut entry_ids = IndexSet::with_capacity(entry_ids_len as usize);
        for _ in 0..entry_ids_len {
            let id = reader.read_u16()?;
            if id > chunks_len {
                return Err(ReaderError::InvalidValue);
            }

            if !entry_ids.insert(id as usize) {
                return Err(ReaderError::InvalidValue);
            }
        }

        let hooks_len = reader.read_u8()?;
        let mut hooks = IndexMap::with_capacity(hooks_len as usize);
        for _ in 0..hooks_len {
            let hook_id = reader.read_u8()?;
            let chunk_id = reader.read_u16()?;

            // Hook can be registered one time only
            if hooks.insert(hook_id, chunk_id as usize).is_some() {
                return Err(ReaderError::InvalidValue);
            }
        }

        Ok(Module::with(constants, chunks, entry_ids, hooks))
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::Hash;
    use super::*;

    #[test]
    fn test_serde_module() {
        let hex = "000302000000020008000b48656c6c6f20576f726c64020000000102000000060004000000000000000000040000000000000001000400000000000000020004000000000000000300040000000000000004000400000000000000050008000568656c6c6f000400000000000000000001000000211874000000020000000000020100010000000100010100187700010207000200140001000000";
        let module = Module::from_hex(hex).unwrap();
        assert_eq!(module.chunks_entry_ids().len(), 1);
        assert_eq!(module.constants().len(), 3);

        assert_eq!(hex.len() / 2, module.size());
    }

    #[track_caller]
    fn test_serde_cell(cell: ValueCell) {
        let bytes = cell.to_bytes();
        let v = ValueCell::from_bytes(&bytes).unwrap();

        assert_eq!(v, cell);
    }

    #[test]
    fn test_serde_primitive() {
        test_serde_cell(ValueCell::Default(Primitive::Null));
        test_serde_cell(ValueCell::Default(Primitive::Boolean(false)));
        test_serde_cell(ValueCell::Default(Primitive::U8(42)));
        test_serde_cell(ValueCell::Default(Primitive::U32(42)));
        test_serde_cell(ValueCell::Default(Primitive::U64(42)));
        test_serde_cell(ValueCell::Default(Primitive::U128(42)));
        test_serde_cell(ValueCell::Default(Primitive::U256(42u64.into())));
        test_serde_cell(ValueCell::Default(Primitive::Range(Box::new((Primitive::U128(42), Primitive::U128(420))))));
        test_serde_cell(ValueCell::Default(Primitive::String("hello world!!!".to_owned())));

        test_serde_cell(ValueCell::Default(Primitive::Opaque(OpaqueWrapper::new(Hash::zero()))));
    }

    #[test]
    fn test_serde_value_cell() {
        test_serde_cell(ValueCell::Bytes(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]));
        test_serde_cell(ValueCell::Array(vec![
            ValueCell::Default(Primitive::U64(42)),
            ValueCell::Default(Primitive::U64(42)),
            ValueCell::Default(Primitive::U64(42)),
            ValueCell::Default(Primitive::U64(42)),
            ValueCell::Default(Primitive::U64(42))
        ]));
        test_serde_cell(ValueCell::Map([
            (ValueCell::Default(Primitive::U64(42)), ValueCell::Default(Primitive::String("Hello World!".to_owned())),)
        ].into_iter().collect()));
    }
}