use anyhow::Context;
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use xelis_vm::{Constant, EnumType, EnumValueType, StructType, TypeId, Value, U256};

use crate::{
    crypto::{elgamal::CompressedCiphertext, Hash},
    serializer::{Reader, ReaderError, Serializer, Writer}
};

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
    pub parameters: Vec<xelis_vm::Constant>
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
}

fn read_constant_with(reader: &mut Reader, enums: &IndexSet<EnumType>, structures: &IndexSet<StructType>) -> Result<Constant, ReaderError> {
    Ok(match reader.read_u8()? {
        0 => Constant::Default(Value::read(reader)?),
        1 => {
            let len = reader.read_u8()? as usize;
            let mut values = Vec::with_capacity(len);
            for _ in 0..len {
                values.push(Constant::read(reader)?);
            }

            let struct_id = reader.read_u16()?;
            let struct_type = structures.get(&TypeId(struct_id)).context("struct type")?;
            Constant::Struct(values, struct_type.clone())
        },
        2 => {
            let len = reader.read_u32()? as usize;
            let mut values = Vec::with_capacity(len);
            for _ in 0..len {
                values.push(Constant::read(reader)?);
            }

            Constant::Array(values)
        },
        3 => Constant::Optional(Option::read(reader)?),
        4 => {
            let len = reader.read_u32()? as usize;
            let mut map = IndexMap::new();
            for _ in 0..len {
                let key = Constant::read(reader)?;
                let value = Constant::read(reader)?;
                map.insert(key, value);
            }

            Constant::Map(map)
        },
        5 => {
            let len = reader.read_u8()? as usize;
            let mut values = Vec::with_capacity(len);
            for _ in 0..len {
                values.push(Constant::read(reader)?);
            }

            let id = reader.read_u16()?;
            let variant_id = reader.read_u8()?;
            let enum_type = enums.get(&TypeId(id)).context("invalid enum type")?;
            if enum_type.get_variant(variant_id).is_none() {
                return Err(ReaderError::InvalidValue);
            }
            Constant::Enum(values, EnumValueType::new(enum_type.clone(), variant_id))
        },
        _ => return Err(ReaderError::InvalidValue)
    })
}

impl Serializer for Constant {
    fn write(&self, writer: &mut Writer) {
        match self {
            Constant::Default(value) => {
                writer.write_u8(0);
                value.write(writer);
            },
            Constant::Struct(values, struct_type) => {
                writer.write_u8(1);
                writer.write_u8(values.len() as u8);
                for value in values {
                    value.write(writer);
                }

                writer.write_u16(struct_type.id());
            },
            Constant::Array(values) => {
                writer.write_u8(2);
                let len = values.len() as u32;
                writer.write_u32(&len);
                for value in values {
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
                for (key, value) in map {
                    key.write(writer);
                    value.write(writer);
                }
            },
            Constant::Enum(values, enum_type) => {
                writer.write_u8(5);
                writer.write_u8(values.len() as u8);
                for value in values {
                    value.write(writer);
                }
                writer.write_u16(enum_type.id());
                writer.write_u8(enum_type.variant_id());
            }
        };
    }

    fn read(_: &mut Reader) -> Result<Constant, ReaderError> {
        Err(ReaderError::InvalidValue)
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
            parameters.push(Constant::read(reader)?);
        }
        Ok(InvokeContractPayload { contract, assets, chunk_id, parameters })
    }

    fn size(&self) -> usize {
        let mut size = self.contract.size() + 1;
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
