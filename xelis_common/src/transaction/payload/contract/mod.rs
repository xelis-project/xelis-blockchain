mod deploy;
mod invoke;
mod deposits;

use anyhow::Context;
use indexmap::{IndexMap, IndexSet};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use xelis_vm::{
    Access,
    Chunk,
    ModuleChunk,
    Module,
    OpaqueWrapper,
    Primitive,
    TypePacked,
    ValueCell,
    ValuePointer,
    U256,
};
use crate::{
    contract::ContractVersion,
    crypto::{
        elgamal::{CompressedCommitment, CompressedHandle},
        proofs::CiphertextValidityProof,
    },
    serializer::*
};

pub use deploy::*;
pub use invoke::*;
pub use deposits::*;

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
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
                amount.write(writer);
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
                value.write(writer);
            },
            Primitive::U64(value) => {
                writer.write_u8(4);
                value.write(writer);
            },
            Primitive::U128(value) => {
                writer.write_u8(5);
                value.write(writer);
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
                DynamicLen(bytes.len()).write(writer);
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
        fn read_range_boundary(reader: &mut Reader) -> Result<Primitive, ReaderError> {
            Ok(match reader.read_u8()? {
                1 => Primitive::U8(reader.read_u8()?),
                2 => Primitive::U16(reader.read_u16()?),
                3 => Primitive::U32(reader.read_u32()?),
                4 => Primitive::U64(reader.read_u64()?),
                5 => Primitive::U128(reader.read_u128()?),
                6 => Primitive::U256(U256::read(reader)?),
                _ => return Err(ReaderError::InvalidValue)
            })
        }

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
                let len = DynamicLen::read(reader)?.0;
                Primitive::String(reader.read_string_with_size(len)?)
            },
            9 => {
                let left = read_range_boundary(reader)?;
                let right = read_range_boundary(reader)?;

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
            Primitive::String(value) => DynamicLen(value.as_bytes().len()).size() + value.as_bytes().len(),
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
        let mut stack = vec![self];
        while let Some(cell) = stack.pop() {
            match cell {
                ValueCell::Primitive(value) => {
                    writer.write_u8(0);
                    value.write(writer);
                },
                ValueCell::Bytes(bytes) => {
                    writer.write_u8(1);
                    DynamicLen(bytes.len()).write(writer);
                    writer.write_bytes(bytes);
                }
                ValueCell::Object(values) => {
                    writer.write_u8(2);
                    DynamicLen(values.len()).write(writer);
                    for value in values.iter().rev() {
                        stack.push(value.as_ref());
                    }
                },
                ValueCell::Map(map) => {
                    writer.write_u8(3);
                    DynamicLen(map.len()).write(writer);
                    for (key, value) in map.iter().rev() {
                        stack.push(value.as_ref());
                        stack.push(key);
                    }
                }
            }
        }
    }

    // No deserialization can occurs here as we're missing context
    fn read(reader: &mut Reader) -> Result<ValueCell, ReaderError> {
        // Iterative approach to prevent stack overflow attacks
        // Maximum nesting depth allowed
        const MAX_DEPTH: usize = 16;

        enum Pending {
            Object { remaining: usize, values: Vec<ValuePointer> },
            Map { remaining: usize, map: IndexMap<ValueCell, ValuePointer>, pending_key: Option<ValueCell> },
        }

        let mut stack: Vec<Pending> = Vec::new();
        let mut result: Option<ValueCell> = None;

        loop {
            // If we have a result, process it
            if let Some(value) = result.take() {
                let Some(last) = stack.last_mut() else {
                    return Ok(value);
                };

                // Add the value to the parent container
                match last {
                    Pending::Object { remaining, values } => {
                        values.push(value.into());
                        *remaining -= 1;
                    }
                    Pending::Map { remaining, map, pending_key } => {
                        if let Some(key) = pending_key.take() {
                            map.insert(key, value.into());
                            *remaining -= 1;
                        } else {
                            *pending_key = Some(value);
                        }
                    }
                }

                // Check if completed containers can be popped
                while let Some(top) = stack.last() {
                    let is_complete = match top {
                        Pending::Object { remaining, .. } => *remaining == 0,
                        Pending::Map { remaining, pending_key, .. } => *remaining == 0 && pending_key.is_none(),
                    };

                    if is_complete {
                        let completed = stack.pop().unwrap();
                        result = Some(match completed {
                            Pending::Object { values, .. } => ValueCell::Object(values),
                            Pending::Map { map, .. } => ValueCell::Map(Box::new(map)),
                        });
                    } else {
                        break;
                    }
                }

                if result.is_some() {
                    continue;
                }
            }

            // Read the next value
            match reader.read_u8()? {
                0 => result = Some(ValueCell::Primitive(Primitive::read(reader)?)),
                1 => {
                    let len = DynamicLen::read(reader)?.0;
                    result = Some(ValueCell::Bytes(reader.read_bytes(len)?));
                }
                2 => {
                    let len = DynamicLen::read(reader)?.0;
                    if len == 0 {
                        result = Some(ValueCell::Object(Vec::new()));
                    } else {
                        if stack.len() >= MAX_DEPTH {
                            return Err(ReaderError::InvalidValue);
                        }
                        stack.push(Pending::Object { remaining: len, values: Vec::with_capacity(len) });
                    }
                }
                3 => {
                    let len = DynamicLen::read(reader)?.0;
                    if len == 0 {
                        result = Some(ValueCell::Map(Box::new(IndexMap::new())));
                    } else {
                        if stack.len() >= MAX_DEPTH {
                            return Err(ReaderError::InvalidValue);
                        }
                        stack.push(Pending::Map { remaining: len, map: IndexMap::new(), pending_key: None });
                    }
                }
                _ => return Err(ReaderError::InvalidValue)
            }
        }
    }

    fn size(&self) -> usize {
        let mut total = 0;
        let mut stack = vec![self];

        while let Some(cell) = stack.pop() {
            // variant id
            total += 1;
            match cell {
                ValueCell::Primitive(value) => total += value.size(),
                ValueCell::Bytes(bytes) => {
                    // u32 len
                    total += DynamicLen(bytes.len()).size();
                    total += bytes.len();
                },
                ValueCell::Object(values) => {
                    // u32 len
                    total += DynamicLen(values.len()).size();
                    for value in values {
                        stack.push(value.as_ref());
                    }
                },
                ValueCell::Map(map) => {
                    // u32 len
                    total += DynamicLen(map.len()).size();
                    for (key, value) in map.iter() {
                        stack.push(value.as_ref());
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
        DynamicLen(constants.len()).write(writer);
        for constant in constants {
            constant.write(writer);
        }

        let version = writer.context()
            .get_optional::<ContractVersion>()
            .cloned()
            .unwrap_or(ContractVersion::V0);

        fn write_parameters(writer: &mut Writer, parameters: &Option<Vec<TypePacked>>, version: ContractVersion) {
            if version >= ContractVersion::V1 {
                if let Some(params) = parameters {
                    writer.write_bool(true);                                
                    writer.write_u8(params.len() as u8);
                    for param in params {
                        param.write(writer);
                    }
                } else {
                    writer.write_bool(false);
                }
            }
        }

         // Function helper to write parameters based on contract version
        let chunks = self.chunks();
        writer.write_u16(chunks.len() as u16);
        for entry in chunks {
            let instructions = entry.chunk.get_instructions();
            DynamicLen(instructions.len()).write(writer);
            writer.write_bytes(instructions);
            match &entry.access {
                Access::All { parameters } => {
                    writer.write_u8(0);
                    write_parameters(writer, parameters, version);
                },
                Access::Internal => writer.write_u8(1),
                Access::Entry { parameters } => {
                    writer.write_u8(2);
                    write_parameters(writer, parameters, version);
                },
                Access::Hook { id } => {
                    writer.write_u8(3);
                    writer.write_u8(*id);
                }
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Module, ReaderError> {
        let constants_len = DynamicLen::read(reader)?.0;
        let mut constants = IndexSet::new();

        for _ in 0..constants_len {
            let c = ValueCell::read(reader)?;
            if !constants.insert(c) {
                return Err(ReaderError::InvalidValue);
            }
        }

        let chunks_len = reader.read_u16()?;
        let mut chunks = Vec::with_capacity(chunks_len as usize);
        let mut hooks = IndexMap::new();

        let version = reader.context()
            .get_optional::<ContractVersion>()
            .cloned()
            .unwrap_or(ContractVersion::V0);

        // Function helper to read parameters based on contract version
        fn read_parameters(reader: &mut Reader, version: ContractVersion) -> Result<Option<Vec<TypePacked>>, ReaderError> {
            if version >= ContractVersion::V1 {
                let params_len = Option::<u8>::read(reader)?;
                if let Some(len) = params_len {
                    let mut params = Vec::with_capacity(len as usize);
                    for _ in 0..len {
                        params.push(TypePacked::read(reader)?);
                    }

                    return Ok(Some(params))
                }
            }

            Ok(None)
        }

        for i in 0..chunks_len {
            let instructions_len = DynamicLen::read(reader)?.0;
            let instructions = reader.read_bytes(instructions_len)?;
            let chunk = Chunk::from_instructions(instructions);

            let access = match reader.read_u8()? {
                0 => Access::All { parameters: read_parameters(reader, version)? },
                1 => Access::Internal,
                2 => Access::Entry { parameters: read_parameters(reader, version)? },
                3 => {
                    let id = reader.read_u8()?;

                    hooks.insert(id, i as _);
                    Access::Hook { id }
                }
                _ => return Err(ReaderError::InvalidValue)
            };

            chunks.push(ModuleChunk { chunk, access });
        }

        Ok(Module::with(constants, chunks, hooks))
    }

    fn size(&self) -> usize {
        // 2 for constants len
        let mut size = DynamicLen(self.constants().len()).size() + self.constants()
            .iter()
            .map(Serializer::size)
            .sum::<usize>();
        // 2 for chunks len u16
        // 4 for instructions len u32 per chunk
        size += 2 + self.chunks()
            .iter()
            .map(|entry| {
                let instructions = entry.chunk.get_instructions();
                DynamicLen(instructions.len()).size() + instructions.len() + match &entry.access {
                    Access::Internal => 1,
                    Access::All { parameters } | Access::Entry { parameters } => parameters.as_ref().map_or(1, |v| 2 + v.iter().map(Serializer::size).sum::<usize>()),
                    Access::Hook { id } => 1 + id.size(),
                }
        })
            .sum::<usize>();

        size
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::crypto::Hash;
    use super::*;

    #[test]
    fn test_serde_module() {
        let hex = "0200080d48656c6c6f2c20576f726c64210004000000000000000000010a00000018ef000001001402";
        let module = Module::from_hex(hex).unwrap();
        assert_eq!(module.constants().len(), 2);

        assert_eq!(hex.len() / 2, module.size());
    }

    #[test]
    fn test_contract_module_size_with_type_packed_parameters() {
        let mut module = Module::new();
        module.add_entry_chunk(Chunk::new(), Some(vec![
            TypePacked::Opaque(42),
            TypePacked::Tuples(vec![
                TypePacked::String,
                TypePacked::Optional(Box::new(TypePacked::Number(xelis_vm::NumberType::U64))),
            ]),
        ]));

        let contract = crate::contract::ContractModule {
            version: ContractVersion::V1,
            module: Arc::new(module),
        };

        assert_eq!(contract.size(), contract.to_bytes().len());
    }

    #[track_caller]
    fn test_serde_cell(cell: ValueCell) {
        let bytes = cell.to_bytes();
        let v = ValueCell::from_bytes(&bytes).unwrap();

        assert_eq!(v, cell);
    }

    #[test]
    fn test_serde_primitive() {
        test_serde_cell(ValueCell::Primitive(Primitive::Null));
        test_serde_cell(ValueCell::Primitive(Primitive::Boolean(false)));
        test_serde_cell(ValueCell::Primitive(Primitive::U8(42)));
        test_serde_cell(ValueCell::Primitive(Primitive::U32(42)));
        test_serde_cell(ValueCell::Primitive(Primitive::U64(42)));
        test_serde_cell(ValueCell::Primitive(Primitive::U128(42)));
        test_serde_cell(ValueCell::Primitive(Primitive::U256(42u64.into())));
        test_serde_cell(ValueCell::Primitive(Primitive::Range(Box::new((Primitive::U128(42), Primitive::U128(420))))));
        test_serde_cell(ValueCell::Primitive(Primitive::String("hello world!!!".to_owned())));

        test_serde_cell(ValueCell::Primitive(Primitive::Opaque(OpaqueWrapper::new(Hash::zero()))));
    }

    #[test]
    fn test_serde_nested_range_is_rejected() {
        let bytes: [u8; 9] = [
            0, // ValueCell::Primitive
            9, // Primitive::Range
            9, // invalid nested Primitive::Range as left boundary
            1, 0,
            1, 1,
            1, 2,
        ];

        assert!(ValueCell::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_serde_value_cell() {
        test_serde_cell(ValueCell::Bytes(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]));
        test_serde_cell(ValueCell::Bytes(vec![0; u16::MAX as usize + 10]));
        test_serde_cell(ValueCell::Object(vec![
            Primitive::U64(42).into(),
            Primitive::U64(23).into(),
            Primitive::U64(42).into(),
            Primitive::U64(57).into(),
            Primitive::U64(10).into()
        ]));
        test_serde_cell(ValueCell::Map(Box::new([
            (Primitive::U64(42).into(), Primitive::String("Hello World!".to_owned()).into())
        ].into_iter().collect())));
    }

    #[test]
    fn test_serde_empty_containers() {
        // Empty object
        test_serde_cell(ValueCell::Object(vec![]));
        // Empty map
        test_serde_cell(ValueCell::Map(Box::new(IndexMap::new())));
        // Empty bytes
        test_serde_cell(ValueCell::Bytes(vec![]));
        // Empty string
        test_serde_cell(ValueCell::Primitive(Primitive::String(String::new())));
    }

    #[test]
    fn test_serde_nested_objects() {
        // Object containing objects
        test_serde_cell(ValueCell::Object(vec![
            ValueCell::Object(vec![
                Primitive::U64(1).into(),
                Primitive::U64(2).into(),
            ]).into(),
            ValueCell::Object(vec![
                Primitive::U64(3).into(),
                Primitive::U64(4).into(),
            ]).into(),
        ]));

        // Deeply nested object (3 levels)
        test_serde_cell(ValueCell::Object(vec![
            ValueCell::Object(vec![
                ValueCell::Object(vec![
                    Primitive::String("deep".to_owned()).into(),
                ]).into(),
            ]).into(),
        ]));
    }

    #[test]
    fn test_serde_nested_maps() {
        // Map containing maps
        let inner_map: IndexMap<ValueCell, ValuePointer> = [
            (Primitive::U64(1).into(), ValueCell::Primitive(Primitive::String("one".to_owned())).into()),
            (Primitive::U64(2).into(), ValueCell::Primitive(Primitive::String("two".to_owned())).into()),
        ].into_iter().collect();

        let outer_map: IndexMap<ValueCell, ValuePointer> = [
            (Primitive::String("inner".to_owned()).into(), ValueCell::Map(Box::new(inner_map)).into()),
        ].into_iter().collect();

        test_serde_cell(ValueCell::Map(Box::new(outer_map)));
    }

    #[test]
    fn test_serde_mixed_nested() {
        // Object containing map containing object
        let inner_obj = ValueCell::Object(vec![
            Primitive::U64(42).into(),
            Primitive::Boolean(true).into(),
        ]);

        let map: IndexMap<ValueCell, ValuePointer> = [
            (Primitive::String("data".to_owned()).into(), inner_obj.into()),
        ].into_iter().collect();

        test_serde_cell(ValueCell::Object(vec![
            ValueCell::Map(Box::new(map)).into(),
            Primitive::U64(100).into(),
        ]));
    }

    #[test]
    fn test_serde_map_with_complex_keys() {
        // Map with object as key
        let key_obj = ValueCell::Object(vec![
            Primitive::U64(1).into(),
            Primitive::U64(2).into(),
        ]);

        let map: IndexMap<ValueCell, ValuePointer> = [
            (key_obj, ValueCell::Primitive(Primitive::String("value".to_owned())).into()),
        ].into_iter().collect();

        test_serde_cell(ValueCell::Map(Box::new(map)));
    }

    #[test]
    fn test_serde_large_flat_object() {
        // Object with many elements
        let values: Vec<ValuePointer> = (0..1000)
            .map(|i| Primitive::U64(i).into())
            .collect();
        test_serde_cell(ValueCell::Object(values));
    }

    #[test]
    fn test_serde_large_flat_map() {
        // Map with many entries
        let map: IndexMap<ValueCell, ValuePointer> = (0..500)
            .map(|i| (Primitive::U64(i).into(), ValueCell::Primitive(Primitive::String(format!("value_{}", i))).into()))
            .collect();
        test_serde_cell(ValueCell::Map(Box::new(map)));
    }

    #[test]
    fn test_serde_deep_nesting() {
        // Create a deeply nested structure (within 16 depth limit)
        let mut cell = ValueCell::Primitive(Primitive::U64(42));
        for _ in 0..16 {
            cell = ValueCell::Object(vec![cell.into()]);
        }
        test_serde_cell(cell);
    }

    #[test]
    fn test_serde_deep_nesting_exceeds_limit() {
        // Create a structure that exceeds the 16 depth limit
        let mut cell = ValueCell::Primitive(Primitive::U64(42));
        for _ in 0..17 {
            cell = ValueCell::Object(vec![cell.into()]);
        }
        let bytes = cell.to_bytes();
        assert!(ValueCell::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_serde_deep_map_nesting() {
        // Deeply nested maps (within 16 depth limit)
        let mut cell = ValueCell::Primitive(Primitive::String("innermost".to_owned()));
        for i in 0..16 {
            let map: IndexMap<ValueCell, ValuePointer> = [
                (Primitive::U64(i).into(), cell.into()),
            ].into_iter().collect();
            cell = ValueCell::Map(Box::new(map));
        }
        test_serde_cell(cell);
    }

    #[test]
    fn test_serde_deep_map_nesting_exceeds_limit() {
        // Deeply nested maps that exceed the 16 depth limit
        let mut cell = ValueCell::Primitive(Primitive::String("innermost".to_owned()));
        for i in 0..17 {
            let map: IndexMap<ValueCell, ValuePointer> = [
                (Primitive::U64(i).into(), cell.into()),
            ].into_iter().collect();
            cell = ValueCell::Map(Box::new(map));
        }
        let bytes = cell.to_bytes();
        assert!(ValueCell::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_serde_alternating_object_map() {
        // Alternating between objects and maps in nesting
        let inner = ValueCell::Primitive(Primitive::U64(999));
        
        let map: IndexMap<ValueCell, ValuePointer> = [
            (Primitive::U64(0).into(), inner.into()),
        ].into_iter().collect();
        
        let obj = ValueCell::Object(vec![ValueCell::Map(Box::new(map)).into()]);
        
        let outer_map: IndexMap<ValueCell, ValuePointer> = [
            (Primitive::String("nested".to_owned()).into(), obj.into()),
        ].into_iter().collect();
        
        test_serde_cell(ValueCell::Object(vec![
            ValueCell::Map(Box::new(outer_map)).into(),
        ]));
    }

    #[test]
    fn test_serde_object_with_all_primitive_types() {
        test_serde_cell(ValueCell::Object(vec![
            Primitive::Null.into(),
            Primitive::Boolean(true).into(),
            Primitive::Boolean(false).into(),
            Primitive::U8(255).into(),
            Primitive::U16(65535).into(),
            Primitive::U32(u32::MAX).into(),
            Primitive::U64(u64::MAX).into(),
            Primitive::U128(u128::MAX).into(),
            Primitive::U256(U256::MAX).into(),
            Primitive::String("test string".to_owned()).into(),
            Primitive::Range(Box::new((Primitive::U64(0), Primitive::U64(100)))).into(),
            Primitive::Opaque(OpaqueWrapper::new(Hash::zero())).into(),
        ]));
    }

    #[test]
    fn test_serde_map_multiple_entries() {
        // Map with multiple entries of different types
        let map: IndexMap<ValueCell, ValuePointer> = [
            (Primitive::U64(1).into(), ValueCell::Primitive(Primitive::String("one".to_owned())).into()),
            (Primitive::U64(2).into(), ValueCell::Primitive(Primitive::Boolean(true)).into()),
            (Primitive::U64(3).into(), ValueCell::Bytes(vec![1, 2, 3]).into()),
            (Primitive::String("key".to_owned()).into(), ValueCell::Primitive(Primitive::U128(12345)).into()),
        ].into_iter().collect();
        test_serde_cell(ValueCell::Map(Box::new(map)));
    }

    #[test]
    fn test_serde_bytes_in_containers() {
        // Bytes inside object
        test_serde_cell(ValueCell::Object(vec![
            ValueCell::Bytes(vec![1, 2, 3, 4, 5]).into(),
            ValueCell::Bytes(vec![]).into(),
            ValueCell::Bytes(vec![255; 100]).into(),
        ]));

        // Bytes as map value
        let map: IndexMap<ValueCell, ValuePointer> = [
            (Primitive::String("data".to_owned()).into(), ValueCell::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]).into()),
        ].into_iter().collect();
        test_serde_cell(ValueCell::Map(Box::new(map)));
    }
}