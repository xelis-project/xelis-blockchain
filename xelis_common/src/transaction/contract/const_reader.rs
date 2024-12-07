use anyhow::Context;
use indexmap::{IndexMap, IndexSet};
use xelis_vm::{Constant, EnumType, EnumValueType, StructType, TypeId, Value};

use crate::serializer::{Reader, ReaderError, Serializer};

enum Step {
    ReadConstant,
    AssembleStruct {
        len: usize,
    },
    AssembleArray {
        len: usize,
    },
    AssembleMap {
        len: usize,
    },
    AssembleEnum {
        len: usize,
    },
    AssembleOptional
}

fn read_constant_iterative(reader: &mut Reader, structures: &IndexSet<StructType>, enums: &IndexSet<EnumType>) -> Result<Constant, ReaderError> {
    let mut stack = vec![Step::ReadConstant];
    let mut values = Vec::new();
    while let Some(step) = stack.pop() {
        match step {
            Step::ReadConstant => {
                let id = reader.read_u8()?;
                match id {
                    0 => {
                        let value = Value::read(reader)?;
                        values.push(Constant::Default(value));
                    },
                    1 => {
                        let len = reader.read_u8()? as usize;
                        stack.push(Step::AssembleStruct { len });
                        for _ in 0..len {
                            stack.push(Step::ReadConstant);
                        }
                    },
                    2 => {
                        let len = reader.read_u32()? as usize;
                        stack.push(Step::AssembleArray { len });
                        for _ in 0..len {
                            stack.push(Step::ReadConstant);
                        }
                    },
                    3 => {
                        if reader.read_bool()? {
                            stack.push(Step::AssembleOptional);
                            stack.push(Step::ReadConstant);
                        } else {
                            values.push(Constant::Optional(None));
                        }
                    },
                    4 => {
                        let len = reader.read_u32()? as usize;
                        stack.push(Step::AssembleMap { len });
                        for _ in 0..len {
                            stack.push(Step::ReadConstant);
                            stack.push(Step::ReadConstant);
                        }
                    },
                    5 => {
                        let len = reader.read_u8()? as usize;
                        stack.push(Step::AssembleEnum { len });
                        for _ in 0..len {
                            stack.push(Step::ReadConstant);
                        }
                    },
                    _ => return Err(ReaderError::InvalidValue)
                }
            },
            Step::AssembleStruct { len } => {
                let struct_id = reader.read_u16()?;
                let struct_type = structures.get(&TypeId(struct_id)).context("struct type")?;
                let mut struct_values = Vec::with_capacity(len);
                for _ in 0..len {
                    struct_values.push(values.pop().context("struct field")?);
                }

                values.push(Constant::Struct(struct_values, struct_type.clone()));
            },
            Step::AssembleArray { len } => {
                let mut array_values = Vec::with_capacity(len);
                for _ in 0..len {
                    array_values.push(values.pop().context("array value")?);
                }

                values.push(Constant::Array(array_values));
            },
            Step::AssembleMap { len } => {
                let mut map = IndexMap::new();
                for _ in 0..len {
                    let value = values.pop().context("map value")?;
                    let key = values.pop().context("map key")?;
                    map.insert(key, value);
                }

                values.push(Constant::Map(map));
            },
            Step::AssembleEnum { len } => {
                let id = reader.read_u16().context("enum type id")?;
                let variant_id = reader.read_u8().context("enum variant id")?;
                let enum_type = enums.get(&TypeId(id)).context("invalid enum type")?;
                if !enum_type.get_variant(variant_id).is_some() {
                    return Err(ReaderError::InvalidValue);
                }

                let mut enum_values = Vec::with_capacity(len);
                for _ in 0..len {
                    enum_values.push(values.pop().context("enum field")?);
                }

                values.push(Constant::Enum(enum_values, EnumValueType::new(enum_type.clone(), variant_id)));
            },
            Step::AssembleOptional => {
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

#[cfg(test)]
mod tests {
    use xelis_vm::EnumVariant;

    use super::*;

    #[test]
    fn test_double_map() {
        let mut inner_map = IndexMap::new();
        inner_map.insert(Constant::Default(Value::U32(1)), Constant::Default(Value::U32(2)));
        inner_map.insert(Constant::Default(Value::U32(3)), Constant::Default(Value::U32(4)));

        let mut map = IndexMap::new();
        map.insert(Constant::Default(Value::U32(5)), Constant::Map(inner_map));

        let map = Constant::Map(map);

        let bytes = map.to_bytes();
        let mut reader = Reader::new(&bytes);

        let structures = IndexSet::new();
        let enums = IndexSet::new();
        let result = read_constant_iterative(&mut reader, &structures, &enums).unwrap();

        assert_eq!(result, map);
    }

    #[test]
    fn test_array() {
        let array = Constant::Array(vec![
            Constant::Default(Value::U32(1)),
            Constant::Default(Value::U32(2)),
            Constant::Default(Value::U32(3)),
            Constant::Default(Value::U32(4)),
        ]);

        let bytes = array.to_bytes();
        let mut reader = Reader::new(&bytes);

        let structures = IndexSet::new();
        let enums = IndexSet::new();
        let result = read_constant_iterative(&mut reader, &structures, &enums).unwrap();

        assert_eq!(result, array);
    }

    #[test]
    fn test_enum() {
        let enum_type = EnumType::new(0, vec![
            EnumVariant::new(vec![]),
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
        let result = read_constant_iterative(&mut reader, &structures, &enums).unwrap();

        assert_eq!(result, enum_value);
    }
}