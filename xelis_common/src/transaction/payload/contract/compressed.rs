use anyhow::Context;
use log::warn;
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use xelis_vm::{
    Constant,
    EnumType,
    EnumValueType,
    StructType,
    Type,
    TypeId,
    Value
};
use crate::serializer::{
    Reader,
    ReaderError,
    Serializer,
    Writer
};

// CompressedConstant is a compressed version of a constant
// Because we can't directly deserialize a constant as its dependent on a Module
// We compress it and decompress it lazily when needed
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CompressedConstant(Vec<u8>);

impl CompressedConstant {
    // Create a new compressed constant
    pub fn new(constant: &Constant) -> Self {
        Self(constant.to_bytes())
    }

    // Decompress the compressed constant
    pub fn decompress(&self, structures: &IndexSet<StructType>, enums: &IndexSet<EnumType>) -> Result<Constant, ReaderError> {
        let mut reader = Reader::new(&self.0);
        decompress_constant(&mut reader, structures, enums)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Serializer for CompressedConstant {
    fn write(&self, writer: &mut Writer) {
        let len = self.0.len() as u32;
        writer.write_u32(&len);
        writer.write_bytes(&self.0);
    }

    fn read(reader: &mut Reader) -> Result<CompressedConstant, ReaderError> {
        let len = reader.read_u32()? as usize;
        Ok(CompressedConstant(reader.read_bytes(len)?))
    }

    fn size(&self) -> usize {
        self.0.len()
    }
}

// Simple enum helper for iterative constant reading
enum ConstantStep {
    ReadConstant,
    AssembleStruct {
        struct_type: StructType,
    },
    AssembleEnum {
        enum_type: EnumValueType,
        len: usize
    },
    AssembleArray {
        len: usize,
    },
    AssembleMap {
        len: usize,
    },
    AssembleOptional
}

// Read a constant from a reader iteratively
// Prevent any attack by limiting the stack size
pub fn decompress_constant(reader: &mut Reader, structures: &IndexSet<StructType>, enums: &IndexSet<EnumType>) -> Result<Constant, ReaderError> {
    let mut stack = vec![ConstantStep::ReadConstant];
    let mut values = Vec::new();
    while let Some(step) = stack.pop() {
        match step {
            ConstantStep::ReadConstant => {
                let id = reader.read_u8()?;
                match id {
                    0 => {
                        let value = Value::read(reader)?;
                        values.push(Constant::Default(value));
                    },
                    1 => {
                        let struct_type = reader.read_u16()?;
                        let struct_type = structures.get(&TypeId(struct_type))
                            .context("struct type")?
                            .clone();

                        let len = struct_type.fields().len();
                        stack.push(ConstantStep::AssembleStruct { struct_type });
                        for _ in 0..len {
                            stack.push(ConstantStep::ReadConstant);
                        }
                    },
                    2 => {
                        let len = reader.read_u32()? as usize;
                        stack.push(ConstantStep::AssembleArray { len });
                        for _ in 0..len {
                            stack.push(ConstantStep::ReadConstant);
                        }
                    },
                    3 => {
                        if reader.read_bool()? {
                            stack.push(ConstantStep::AssembleOptional);
                            stack.push(ConstantStep::ReadConstant);
                        } else {
                            values.push(Constant::Optional(None));
                        }
                    },
                    4 => {
                        let len = reader.read_u32()? as usize;
                        stack.push(ConstantStep::AssembleMap { len });
                        for _ in 0..len {
                            stack.push(ConstantStep::ReadConstant);
                            stack.push(ConstantStep::ReadConstant);
                        }
                    },
                    5 => {
                        let enum_id = reader.read_u16()?;
                        let variant_id = reader.read_u8()?;
                        let enum_type = enums.get(&TypeId(enum_id))
                            .context("enum type")?
                            .clone();

                        let variant = enum_type.get_variant(variant_id)
                            .context("enum variant")?;
                        let len = variant.fields().len();

                        let enum_type = EnumValueType::new(enum_type, variant_id);
                        stack.push(ConstantStep::AssembleEnum { enum_type, len });
                        for _ in 0..len {
                            stack.push(ConstantStep::ReadConstant);
                        }
                    },
                    _ => return Err(ReaderError::InvalidValue)
                }
            },
            ConstantStep::AssembleStruct { struct_type } => {
                let len = struct_type.fields().len();
                let mut struct_values = Vec::with_capacity(len);
                for _ in 0..len {
                    struct_values.push(values.pop().context("struct field")?);
                }

                values.push(Constant::Struct(struct_values, struct_type.clone()));
            },
            ConstantStep::AssembleArray { len } => {
                let mut array_values = Vec::with_capacity(len);
                for _ in 0..len {
                    array_values.push(values.pop().context("array value")?);
                }

                values.push(Constant::Array(array_values));
            },
            ConstantStep::AssembleMap { len } => {
                let mut map = IndexMap::new();
                for _ in 0..len {
                    let value = values.pop().context("map value")?;
                    let key = values.pop().context("map key")?;
                    map.insert(key, value);
                }

                values.push(Constant::Map(map));
            },
            ConstantStep::AssembleEnum { enum_type, len } => {
                let mut enum_values = Vec::with_capacity(len);
                for _ in 0..len {
                    enum_values.push(values.pop().context("enum field")?);
                }

                values.push(Constant::Enum(enum_values, enum_type));
            },
            ConstantStep::AssembleOptional => {
                let value = values.pop().context("optional value")?;
                values.push(Constant::Optional(Some(Box::new(value))));
            }
        }
    }

    if values.len() != 1 {
        return Err(ReaderError::InvalidSize);
    }

    values.pop().ok_or(ReaderError::InvalidValue)
}

pub enum TypeStep {
    ReadType,
    Array,
    AssembleOptional,
    AssembleMap,
    AssembleRange,
}

pub fn decompress_type(reader: &mut Reader, structures: &IndexSet<StructType>, enums: &IndexSet<EnumType>) -> Result<Type, ReaderError> {
    let mut stack = vec![TypeStep::ReadType];
    let mut values = Vec::new();

    while let Some(step) = stack.pop() {
        match step {
            TypeStep::ReadType => {
                let id = reader.read_u8()?;
                match id {
                    0 => {
                        values.push(Type::U8);
                    },
                    1 => {
                        values.push(Type::U16);
                    }
                    2 => {
                        values.push(Type::U32);
                    },
                    3 => {
                        values.push(Type::U64);
                    },
                    4 => {
                        values.push(Type::U128);
                    },
                    5 => {
                        values.push(Type::U256);
                    },
                    6 => {
                        values.push(Type::Bool);
                    },
                    7 => {
                        values.push(Type::Blob);
                    },
                    8 => {
                        values.push(Type::String);
                    },
                    9 => {
                        let struct_id = reader.read_u16()?;
                        let struct_type = structures.get(&TypeId(struct_id))
                            .context("struct type")?
                            .clone();

                        values.push(Type::Struct(struct_type));
                    },
                    10 => {
                        stack.push(TypeStep::Array);
                        stack.push(TypeStep::ReadType);
                    },
                    11 => {
                        stack.push(TypeStep::AssembleOptional);
                        stack.push(TypeStep::ReadType);
                    },
                    12 => {
                        stack.push(TypeStep::AssembleMap);
                        stack.push(TypeStep::ReadType);
                        stack.push(TypeStep::ReadType);
                    },
                    13 => {
                        let enum_id = reader.read_u16()?;
                        let enum_type = enums.get(&TypeId(enum_id))
                            .context("enum type")?
                            .clone();

                        values.push(Type::Enum(enum_type));
                    },
                    14 => {
                        stack.push(TypeStep::AssembleRange);
                        stack.push(TypeStep::ReadType);
                    }
                    _ => return Err(ReaderError::InvalidValue)
                }
            },
            TypeStep::Array => {
                let ty = values.pop().context("array type")?;
                values.push(Type::Array(Box::new(ty)));
            },
            TypeStep::AssembleOptional => {
                let ty = values.pop().context("optional type")?;
                values.push(Type::Optional(Box::new(ty)));
            },
            TypeStep::AssembleMap => {
                let value = values.pop().context("map value")?;
                let key = values.pop().context("map key")?;
                values.push(Type::Map(Box::new(key), Box::new(value)));
            },
            TypeStep::AssembleRange => {
                let inner = values.pop().context("range inner type")?;
                values.push(Type::Range(Box::new(inner)));
            }
        }
    }

    if !stack.is_empty() {
        warn!("Stack is not empty after reading type");
        return Err(ReaderError::InvalidSize);
    }

    values.pop().ok_or(ReaderError::InvalidValue)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xelis_vm::{EnumVariant, Type};

    fn test_serde_value(value: Constant) {
        let bytes = value.to_bytes();
        let len = bytes.len();
        let mut reader = Reader::new(&bytes);

        let structures = IndexSet::new();
        let enums = IndexSet::new();
        let result = decompress_constant(&mut reader, &structures, &enums).unwrap();
        assert_eq!(result, value);
        assert_eq!(result.size(), len);
    }

    #[test]
    fn test_string() {
        let string = Constant::Default(Value::String("Hello, World!".to_string()));
        test_serde_value(string);
    }

    #[test]
    fn test_double_map() {
        let mut inner_map = IndexMap::new();
        inner_map.insert(Constant::Default(Value::U32(1)), Constant::Default(Value::U32(2)));
        inner_map.insert(Constant::Default(Value::U32(3)), Constant::Default(Value::U32(4)));

        let mut map = IndexMap::new();
        map.insert(Constant::Default(Value::U32(5)), Constant::Map(inner_map));

        let map = Constant::Map(map);

        test_serde_value(map);
    }

    #[test]
    fn test_array() {
        let array = Constant::Array(vec![
            Constant::Default(Value::U32(1)),
            Constant::Default(Value::U32(2)),
            Constant::Default(Value::U32(3)),
            Constant::Default(Value::U32(4)),
        ]);

        test_serde_value(array);
    }

    #[test]
    fn test_enum() {
        let enum_type = EnumType::new(0, vec![
            EnumVariant::new(vec![
                Type::U32,
                Type::U32,
            ]),
        ]);

        let enum_value = Constant::Enum(vec![
            Constant::Default(Value::U32(1)),
            Constant::Default(Value::U32(2)),
        ], EnumValueType::new(enum_type.clone(), 0));

        let bytes = enum_value.to_bytes();
        let mut reader = Reader::new(&bytes);

        let structures = IndexSet::new();
        let mut enums = IndexSet::new();
        enums.insert(enum_type);
        let result = decompress_constant(&mut reader, &structures, &enums).unwrap();

        assert_eq!(result, enum_value);
    }

    #[test]
    fn test_optional() {
        let optional = Constant::Optional(Some(Box::new(Constant::Default(Value::U32(1)))));
        test_serde_value(optional);
    }

    #[test]
    fn test_optional_null() {
        let optional = Constant::Optional(None);
        test_serde_value(optional);
    }

    #[test]
    fn test_range() {
        let range = Constant::Default(
            Value::Range(
                Box::new(Value::U32(1)),
                Box::new(Value::U32(2)),
                Type::U32
            )
        );
        test_serde_value(range);
    }

    #[test]
    fn test_struct() {
        let struct_type = StructType::new(0, vec![
            Type::U32,
            Type::U32,
        ]);

        let struct_value = Constant::Struct(vec![
            Constant::Default(Value::U32(1)),
            Constant::Default(Value::U32(2)),
        ], struct_type.clone());

        let bytes = struct_value.to_bytes();
        let mut reader = Reader::new(&bytes);

        let mut structures = IndexSet::new();
        structures.insert(struct_type);
        let enums = IndexSet::new();
        let result = decompress_constant(&mut reader, &structures, &enums).unwrap();

        assert_eq!(result, struct_value);
    }

    #[test]
    fn test_type() {
        let type_ = Type::Array(Box::new(Type::Array(Box::new(Type::U32))));
        let bytes = type_.to_bytes();
        let len = bytes.len();
        let mut reader = Reader::new(&bytes);

        let structures = IndexSet::new();
        let enums = IndexSet::new();
        let result = decompress_type(&mut reader, &structures, &enums).unwrap();
        assert_eq!(result, type_);
        assert_eq!(result.size(), len);
    }
}