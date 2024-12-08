mod compressed;

use anyhow::Context;
use compressed::{decompress_constant, decompress_type};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use xelis_vm::{Chunk, Constant, EnumType, EnumVariant, Module, StructType, Type, Value, U256};
use crate::{
    crypto::{elgamal::CompressedCiphertext, Hash},
    serializer::{Reader, ReaderError, Serializer, Writer}
};

pub use compressed::CompressedConstant;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ContractDeposit {
    // Public deposit
    // The amount is the amount of the asset deposited
    // it is public and can be seen by anyone
    Public(u64),
    // Private deposit
    // The ciphertext represents the amount of the asset deposited
    Private(CompressedCiphertext)
}

// InvokeContractPayload is a public payload allowing to call a smart contract
// It contains all the assets deposited in the contract and the parameters to call the contract
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InvokeContractPayload {
    // The contract address
    // Contract are the TXID of the transaction that deployed the contract
    pub contract: Hash,
    // Assets deposited with this call
    pub assets: IndexMap<Hash, ContractDeposit>,
    // The chunk to invoke
    pub chunk_id: u16,
    // The parameters to call the contract
    pub parameters: Vec<CompressedConstant>
}

impl Serializer for ContractDeposit {
    fn write(&self, writer: &mut Writer) {
        match self {
            ContractDeposit::Public(amount) => {
                writer.write_u8(0);
                writer.write_u64(amount);
            },
            ContractDeposit::Private(ciphertext) => {
                writer.write_u8(1);
                ciphertext.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<ContractDeposit, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => ContractDeposit::Public(reader.read_u64()?),
            1 => ContractDeposit::Private(CompressedCiphertext::read(reader)?),
            _ => return Err(ReaderError::InvalidValue)
        })
    }

    fn size(&self) -> usize {
        match self {
            ContractDeposit::Public(_) => 1 + 8,
            ContractDeposit::Private(ciphertext) => 1 + ciphertext.size()
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

impl Serializer for Value {
    fn write(&self, writer: &mut Writer) {
        match self {
            Value::Null => writer.write_u8(0),
            Value::U8(value) => {
                writer.write_u8(1);
                writer.write_u8(*value);
            },
            Value::U16(value) => {
                writer.write_u8(2);
                writer.write_u16(*value);
            },
            Value::U32(value) => {
                writer.write_u8(3);
                writer.write_u32(value);
            },
            Value::U64(value) => {
                writer.write_u8(4);
                writer.write_u64(value);
            },
            Value::U128(value) => {
                writer.write_u8(5);
                writer.write_u128(value);
            },
            Value::U256(value) => {
                writer.write_u8(6);
                value.write(writer);
            },
            Value::Boolean(value) => {
                writer.write_u8(7);
                writer.write_bool(*value);
            },
            Value::Blob(value) => {
                writer.write_u8(8);
                let len = value.len() as u32;
                writer.write_u32(&len);
                writer.write_bytes(value);
            },
            Value::String(value) => {
                writer.write_u8(9);
                // TODO support > 255 length strings
                writer.write_string(value);
            }
            Value::Range(left, right, _) => {
                writer.write_u8(10);
                left.write(writer);
                right.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Value, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => Value::Null,
            1 => Value::U8(reader.read_u8()?),
            2 => Value::U16(reader.read_u16()?),
            3 => Value::U32(reader.read_u32()?),
            4 => Value::U64(reader.read_u64()?),
            5 => Value::U128(reader.read_u128()?),
            6 => Value::U256(U256::read(reader)?),
            7 => Value::Boolean(reader.read_bool()?),
            8 => {
                let len = reader.read_u32()? as usize;
                Value::Blob(reader.read_bytes(len)?)
            }
            9 => Value::String(reader.read_string()?),
            10 => {
                let left = Value::read(reader)?;
                if !left.is_number() {
                    return Err(ReaderError::InvalidValue);
                }

                let right = Value::read(reader)?;
                if !right.is_number() {
                    return Err(ReaderError::InvalidValue);
                }

                let left_type = left.get_type().context("left range type")?;
                let right_type = right.get_type().context("right range type")?;
                if left_type != right_type {
                    return Err(ReaderError::InvalidValue);
                }

                Value::Range(Box::new(left), Box::new(right), right_type)
            },
            _ => return Err(ReaderError::InvalidValue)
        })
    }

    fn size(&self) -> usize {
        1 + match self {
            Value::Null => 0,
            Value::U8(_) => 1,
            Value::U16(_) => 2,
            Value::U32(_) => 4,
            Value::U64(_) => 8,
            Value::U128(_) => 16,
            Value::U256(value) => value.size(),
            Value::Boolean(_) => 1,
            Value::Blob(value) => 4 + value.len(),
            Value::String(value) => 1 + value.len(),
            Value::Range(left, right, _) => left.size() + right.size()
        }
    }
}

impl Serializer for Constant {
    // Serialize a constant
    // Constant with more than one value are serialized in reverse order
    // This help us to save a reverse operation when deserializing
    fn write(&self, writer: &mut Writer) {
        match self {
            Constant::Default(value) => {
                writer.write_u8(0);
                value.write(writer);
            },
            Constant::Struct(values, struct_type) => {
                writer.write_u8(1);
                writer.write_u16(struct_type.id());
                for value in values.iter().rev() {
                    value.write(writer);
                }
            },
            Constant::Array(values) => {
                writer.write_u8(2);
                let len = values.len() as u32;
                writer.write_u32(&len);
                for value in values.iter().rev() {
                    value.write(writer);
                }
            },
            Constant::Optional(opt) => {
                writer.write_u8(3);
                opt.write(writer);
            },
            Constant::Map(map) => {
                writer.write_u8(4);
                let len = map.len() as u32;
                writer.write_u32(&len);
                for (key, value) in map.iter().rev() {
                    key.write(writer);
                    value.write(writer);
                }
            },
            Constant::Enum(values, enum_type) => {
                writer.write_u8(5);
                writer.write_u16(enum_type.id());
                writer.write_u8(enum_type.variant_id());
                for value in values.iter().rev() {
                    value.write(writer);
                }
            }
        };
    }

    // No deserialization can occurs here as we're missing context
    fn read(_: &mut Reader) -> Result<Constant, ReaderError> {
        Err(ReaderError::InvalidValue)
    }

    fn size(&self) -> usize {
        1 + match self {
            Constant::Default(value) => value.size(),
            Constant::Struct(values, _) => {
                // 2 bytes for the struct id
                2 + values.iter().map(|value| value.size()).sum::<usize>()
            },
            Constant::Array(values) => {
                // 4 bytes for the length
                4 + values.iter().map(|value| value.size()).sum::<usize>()
            },
            Constant::Optional(opt) => opt.size(),
            Constant::Map(map) => {
                // 4 bytes for the length
                4 + map.iter().map(|(key, value)| key.size() + value.size()).sum::<usize>()
            },
            Constant::Enum(values, _) => {
                // 2 bytes for the enum id and 1 byte for the variant id
                3 + values.iter().map(|value| value.size()).sum::<usize>()
            }
        }
    }
}

impl Serializer for Type {
    fn write(&self, writer: &mut Writer) {
        match self {
            Type::U8 => writer.write_u8(0),
            Type::U16 => writer.write_u8(1),
            Type::U32 => writer.write_u8(2),
            Type::U64 => writer.write_u8(3),
            Type::U128 => writer.write_u8(4),
            Type::U256 => writer.write_u8(5),
            Type::Bool => writer.write_u8(6),
            Type::Blob => writer.write_u8(7),
            Type::String => writer.write_u8(8),
            Type::Struct(struct_type) => {
                writer.write_u8(9);
                writer.write_u16(struct_type.id());
            },
            Type::Array(inner) => {
                writer.write_u8(10);
                inner.write(writer);
            },
            Type::Optional(inner) => {
                writer.write_u8(11);
                inner.write(writer);
            },
            Type::Map(key, value) => {
                writer.write_u8(12);
                key.write(writer);
                value.write(writer);
            },
            Type::Enum(enum_type) => {
                writer.write_u8(13);
                writer.write_u16(enum_type.id());
            },
            Type::Range(inner) => {
                writer.write_u8(14);
                inner.write(writer);
            },
            _ => {}
        }        
    }

    fn read(_: &mut Reader) -> Result<Self, ReaderError> {
        Err(ReaderError::InvalidValue)
    }

    fn size(&self) -> usize {
        1 + match self {
            Type::U8 | Type::U16 | Type::U32 | Type::U64 | Type::U128 | Type::U256 | Type::Bool | Type::Blob | Type::String => 0,
            Type::Struct(_) => 2, // 2 bytes for the struct id
            Type::Array(inner) => inner.size(),
            Type::Optional(inner) => inner.size(),
            Type::Map(key, value) => key.size() + value.size(),
            Type::Enum(_) => 2,
            Type::Range(inner) => inner.size(),
            _ => 0
        }
    }
}

impl Serializer for Module {
    fn write(&self, writer: &mut Writer) {
        let structs = self.structs();
        writer.write_u16(structs.len() as u16);

        for structure in structs {
            writer.write_u16(structure.id());
            for field in structure.fields() {
                field.write(writer);
            }
        }

        let enums = self.enums();
        writer.write_u16(enums.len() as u16);

        for enum_type in enums {
            writer.write_u16(enum_type.id());
            for (index, variant) in enum_type.variants().iter().enumerate() {
                writer.write_u8(index as u8);
                for field in variant.fields() {
                    field.write(writer);
                }
            }
        }

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
    }

    fn read(reader: &mut Reader) -> Result<Module, ReaderError> {
        let structs_len = reader.read_u16()?;
        let mut structures = IndexSet::with_capacity(structs_len as usize);
        let mut enums = IndexSet::new();

        for _ in 0..structs_len {
            let id = reader.read_u16()?;
            let fields_len = reader.read_u16()?;
            let mut fields = Vec::with_capacity(fields_len as usize);

            for _ in 0..fields_len {
                fields.push(decompress_type(reader, &structures, &enums)?);
            }

            let structure = StructType::new(id, fields);
            if !structures.insert(structure) {
                return Err(ReaderError::InvalidValue);
            }
        }

        let enums_len = reader.read_u16()?;
        for _ in 0..enums_len {
            let id = reader.read_u16()?;
            let variants_len = reader.read_u8()?;
            let mut variants = Vec::with_capacity(variants_len as usize);

            for _ in 0..variants_len {
                let mut fields = Vec::new();
                for _ in 0..reader.read_u8()? {
                    fields.push(decompress_type(reader, &structures, &enums)?);
                }

                variants.push(EnumVariant::new(fields));
            }

            let enum_type = EnumType::new(id, variants);
            if !enums.insert(enum_type) {
                return Err(ReaderError::InvalidValue);
            }
        }

        let constants_len = reader.read_u16()?;
        let mut constants = IndexSet::with_capacity(constants_len as usize);

        for _ in 0..constants_len {
            if !constants.insert(decompress_constant(reader, &structures, &enums)?) {
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

        Ok(Module::with(constants, chunks, entry_ids, structures, enums))
    }
}

impl Serializer for InvokeContractPayload {
    fn write(&self, writer: &mut Writer) {
        self.contract.write(writer);

        writer.write_u8(self.assets.len() as u8);
        for (asset, deposit) in &self.assets {
            asset.write(writer);
            deposit.write(writer);
        }

        writer.write_u16(self.chunk_id);

        writer.write_u8(self.parameters.len() as u8);
        for parameter in &self.parameters {
            parameter.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<InvokeContractPayload, ReaderError> {
        let contract = Hash::read(reader)?;

        let len = reader.read_u8()? as usize;
        let mut assets = IndexMap::new();
        for _ in 0..len {
            let asset = Hash::read(reader)?;
            let deposit = ContractDeposit::read(reader)?;
            assets.insert(asset, deposit);
        }

        let chunk_id = reader.read_u16()?;

        let len = reader.read_u8()? as usize;
        let mut parameters = Vec::with_capacity(len);
        for _ in 0..len {
            parameters.push(CompressedConstant::read(reader)?);
        }
        Ok(InvokeContractPayload { contract, assets, chunk_id, parameters })
    }

    fn size(&self) -> usize {
        let mut size = self.contract.size()
            + self.chunk_id.size()
        // 1 byte for the deposits length
            + 1;

        for (asset, deposit) in &self.assets {
            size += asset.size() + deposit.size();
        }

        size += 1;
        for parameter in &self.parameters {
            size += parameter.size();
        }
        size
    }
}