use anyhow::Context;
use indexmap::{IndexMap, IndexSet};
use xelis_vm::{Constant, EnumType, EnumValueType, StructType, TypeId, Value};

use crate::serializer::{Reader, ReaderError, Serializer};

enum Step {
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
                        let struct_type = reader.read_u16()?;
                        let struct_type = structures.get(&TypeId(struct_type))
                            .context("struct type")?
                            .clone();

                        let len = struct_type.fields().len();
                        stack.push(Step::AssembleStruct { struct_type });
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
                        let enum_id = reader.read_u16()?;
                        let variant_id = reader.read_u8()?;
                        let enum_type = enums.get(&TypeId(enum_id))
                            .context("enum type")?
                            .clone();

                        let variant = enum_type.get_variant(variant_id)
                            .context("enum variant")?;
                        let len = variant.fields().len();

                        let enum_type = EnumValueType::new(enum_type, variant_id);
                        stack.push(Step::AssembleEnum { enum_type, len });
                        for _ in 0..len {
                            stack.push(Step::ReadConstant);
                        }
                    },
                    _ => return Err(ReaderError::InvalidValue)
                }
            },
            Step::AssembleStruct { struct_type } => {
                let len = struct_type.fields().len();
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
            Step::AssembleEnum { enum_type, len } => {
                let mut enum_values = Vec::with_capacity(len);
                for _ in 0..len {
                    enum_values.push(values.pop().context("enum field")?);
                }

                values.push(Constant::Enum(enum_values, enum_type));
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
    use super::*;
    use xelis_vm::{EnumVariant, Type};

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
        let result = read_constant_iterative(&mut reader, &structures, &enums).unwrap();

        assert_eq!(result, enum_value);
    }
}