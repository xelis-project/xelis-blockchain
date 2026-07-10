use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use xelis_vm::{Access, NumberType, TypePacked};
use crate::serializer::*;
use super::ContractVersion;

pub use xelis_vm::Module;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ContractModule {
    pub version: ContractVersion,
    // keep it behind Arc to reduce cloning overhead
    pub module: Arc<Module>,
}

impl Serializer for ContractModule {
    fn write(&self, writer: &mut Writer) {
        self.version.write(writer);

        writer.context_mut().store(self.version);
        self.module.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let version = ContractVersion::read(reader)?;

        // Store the version in the context for later use
        reader.context_mut().store(version);

        let module = Module::read(reader)?;

        Ok(Self {
            version,
            module: Arc::new(module),
        })
    }

    fn size(&self) -> usize {
        let mut size = self.version.size();

        size += DynamicLen(self.module.constants().len()).size() + self.module.constants()
            .iter()
            .map(Serializer::size)
            .sum::<usize>();

        size += 2 + self.module.chunks()
            .iter()
            .map(|entry| {
                let instructions = entry.chunk.get_instructions();
                DynamicLen(instructions.len()).size() + instructions.len() + match &entry.access {
                    Access::Internal => 1,
                    Access::All { parameters } | Access::Entry { parameters } => {
                        if self.version >= ContractVersion::V1 {
                            parameters.as_ref()
                                .map_or(2, |v| 3 + v.iter().map(Serializer::size).sum::<usize>())
                        } else {
                            1
                        }
                    },
                    Access::Hook { id } => 1 + id.size(),
                }
            })
            .sum::<usize>();

        size
    }
}

impl Serializer for TypePacked {
    fn write(&self, writer: &mut Writer) {
        match self {
            TypePacked::Number(NumberType::U8) => writer.write_u8(0),
            TypePacked::Number(NumberType::U16) => writer.write_u8(1),
            TypePacked::Number(NumberType::U32) => writer.write_u8(2),
            TypePacked::Number(NumberType::U64) => writer.write_u8(3),
            TypePacked::Number(NumberType::U128) => writer.write_u8(4),
            TypePacked::Number(NumberType::U256) => writer.write_u8(5),
            TypePacked::Bool => writer.write_u8(6),
            TypePacked::Bytes => writer.write_u8(7),
            TypePacked::String => writer.write_u8(8),
            TypePacked::Opaque(id) => {
                writer.write_u8(9);
                writer.write_u16(*id);
            },
            TypePacked::Range(inner) => match **inner {
                NumberType::U8 => writer.write_u8(10),
                NumberType::U16 => writer.write_u8(11),
                NumberType::U32 => writer.write_u8(12),
                NumberType::U64 => writer.write_u8(13),
                NumberType::U128 => writer.write_u8(14),
                NumberType::U256 => writer.write_u8(15),
            },
            TypePacked::Array(inner) => {
                writer.write_u8(16);
                inner.write(writer);
            },
            TypePacked::Tuples(fields) => {
                writer.write_u8(17);
                writer.write_u8(fields.len() as u8);
                for field in fields {
                    field.write(writer);
                }
            },
            TypePacked::Map(key, value) => {
                writer.write_u8(18);
                key.write(writer);
                value.write(writer);
            },
            TypePacked::Optional(inner) => {
                writer.write_u8(19);
                inner.write(writer);
            },
            TypePacked::Any => writer.write_u8(20),
            TypePacked::OneOf(variants) => {
                writer.write_u8(21);
                writer.write_u8(variants.len() as u8);
                for variant in variants {
                    writer.write_u8(variant.len() as u8);
                    for v in variant {
                        v.write(writer);
                    }
                }
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        enum WorkItem {
            ReadType,
            BuildArray,
            BuildTuples { remaining: usize, fields: Vec<TypePacked> },
            BuildMapKey,
            BuildMapValue { key: TypePacked },
            BuildOptional,
            BuildOneOf { 
                remaining_variants: usize, 
                variants: Vec<Vec<TypePacked>>,
                current_variant_remaining: Option<usize>,
                current_variant: Vec<TypePacked>
            },
        }

        const MAX_DEPTH: usize = 16;
        let mut stack = vec![(WorkItem::ReadType, 0)];
        let mut tmp = Vec::new();

        while let Some((work, depth)) = stack.pop() {
            match work {
                WorkItem::ReadType => {
                    if depth > MAX_DEPTH {
                        return Err(ReaderError::InvalidSize);
                    }

                    let tag = reader.read_u8()?;
                    match tag {
                        0 => tmp.push(TypePacked::Number(NumberType::U8)),
                        1 => tmp.push(TypePacked::Number(NumberType::U16)),
                        2 => tmp.push(TypePacked::Number(NumberType::U32)),
                        3 => tmp.push(TypePacked::Number(NumberType::U64)),
                        4 => tmp.push(TypePacked::Number(NumberType::U128)),
                        5 => tmp.push(TypePacked::Number(NumberType::U256)),
                        6 => tmp.push(TypePacked::Bool),
                        7 => tmp.push(TypePacked::Bytes),
                        8 => tmp.push(TypePacked::String),
                        9 => {
                            let id = reader.read_u16()?;
                            tmp.push(TypePacked::Opaque(id));
                        },
                        10 => tmp.push(TypePacked::Range(Box::new(NumberType::U8))),
                        11 => tmp.push(TypePacked::Range(Box::new(NumberType::U16))),
                        12 => tmp.push(TypePacked::Range(Box::new(NumberType::U32))),
                        13 => tmp.push(TypePacked::Range(Box::new(NumberType::U64))),
                        14 => tmp.push(TypePacked::Range(Box::new(NumberType::U128))),
                        15 => tmp.push(TypePacked::Range(Box::new(NumberType::U256))),
                        16 => {
                            stack.push((WorkItem::BuildArray, depth));
                            stack.push((WorkItem::ReadType, depth + 1));
                        },
                        17 => {
                            let len = reader.read_u8()? as usize;
                            if len == 0 {
                                tmp.push(TypePacked::Tuples(Vec::new()));
                            } else {
                                stack.push((WorkItem::BuildTuples { remaining: len, fields: Vec::with_capacity(len) }, depth));
                                stack.push((WorkItem::ReadType, depth + 1));
                            }
                        },
                        18 => {
                            stack.push((WorkItem::BuildMapKey, depth));
                            stack.push((WorkItem::ReadType, depth + 1));
                        },
                        19 => {
                            stack.push((WorkItem::BuildOptional, depth));
                            stack.push((WorkItem::ReadType, depth + 1));
                        },
                        20 => tmp.push(TypePacked::Any),
                        21 => {
                            let len = reader.read_u8()? as usize;
                            if len == 0 {
                                tmp.push(TypePacked::OneOf(Vec::new()));
                            } else {
                                let first_variant_len = reader.read_u8()? as usize;
                                if first_variant_len == 0 {
                                    stack.push((WorkItem::BuildOneOf {
                                        remaining_variants: len - 1,
                                        variants: Vec::with_capacity(len),
                                        current_variant_remaining: None,
                                        current_variant: Vec::new()
                                    }, depth));
                                } else {
                                    stack.push((WorkItem::BuildOneOf {
                                        remaining_variants: len - 1,
                                        variants: Vec::with_capacity(len),
                                        current_variant_remaining: Some(first_variant_len),
                                        current_variant: Vec::with_capacity(first_variant_len)
                                    }, depth));
                                    stack.push((WorkItem::ReadType, depth + 1));
                                }
                            }
                        },
                        _ => return Err(ReaderError::InvalidValue),
                    }
                },
                WorkItem::BuildArray => {
                    let inner = tmp.pop().ok_or(ReaderError::InvalidValue)?;
                    tmp.push(TypePacked::Array(Box::new(inner)));
                },
                WorkItem::BuildTuples { remaining, mut fields } => {
                    let field = tmp.pop().ok_or(ReaderError::InvalidValue)?;
                    fields.push(field);
                    
                    if remaining > 1 {
                        stack.push((WorkItem::BuildTuples { remaining: remaining - 1, fields }, depth));
                        stack.push((WorkItem::ReadType, depth + 1));
                    } else {
                        tmp.push(TypePacked::Tuples(fields));
                    }
                },
                WorkItem::BuildMapKey => {
                    let key = tmp.pop().ok_or(ReaderError::InvalidValue)?;
                    stack.push((WorkItem::BuildMapValue { key }, depth));
                    stack.push((WorkItem::ReadType, depth + 1));
                },
                WorkItem::BuildMapValue { key } => {
                    let value = tmp.pop().ok_or(ReaderError::InvalidValue)?;
                    tmp.push(TypePacked::Map(Box::new(key), Box::new(value)));
                },
                WorkItem::BuildOptional => {
                    let inner = tmp.pop().ok_or(ReaderError::InvalidValue)?;
                    tmp.push(TypePacked::Optional(Box::new(inner)));
                },
                WorkItem::BuildOneOf { remaining_variants, mut variants, current_variant_remaining, mut current_variant } => {
                    if let Some(remaining) = current_variant_remaining {
                        let field = tmp.pop().ok_or(ReaderError::InvalidValue)?;
                        current_variant.push(field);
                        
                        if remaining > 1 {
                            stack.push((WorkItem::BuildOneOf {
                                remaining_variants,
                                variants,
                                current_variant_remaining: Some(remaining - 1),
                                current_variant
                            }, depth));
                            stack.push((WorkItem::ReadType, depth + 1));
                        } else {
                            variants.push(current_variant);
                            
                            if remaining_variants > 0 {
                                let next_variant_len = reader.read_u8()? as usize;
                                if next_variant_len == 0 {
                                    stack.push((WorkItem::BuildOneOf {
                                        remaining_variants: remaining_variants - 1,
                                        variants,
                                        current_variant_remaining: None,
                                        current_variant: Vec::new()
                                    }, depth));
                                } else {
                                    stack.push((WorkItem::BuildOneOf {
                                        remaining_variants: remaining_variants - 1,
                                        variants,
                                        current_variant_remaining: Some(next_variant_len),
                                        current_variant: Vec::with_capacity(next_variant_len)
                                    }, depth));
                                    stack.push((WorkItem::ReadType, depth + 1));
                                }
                            } else {
                                tmp.push(TypePacked::OneOf(variants));
                            }
                        }
                    } else {
                        variants.push(current_variant);
                        
                        if remaining_variants > 0 {
                            let next_variant_len = reader.read_u8()? as usize;
                            if next_variant_len == 0 {
                                stack.push((WorkItem::BuildOneOf {
                                    remaining_variants: remaining_variants - 1,
                                    variants,
                                    current_variant_remaining: None,
                                    current_variant: Vec::new()
                                }, depth));
                            } else {
                                stack.push((WorkItem::BuildOneOf {
                                    remaining_variants: remaining_variants - 1,
                                    variants,
                                    current_variant_remaining: Some(next_variant_len),
                                    current_variant: Vec::with_capacity(next_variant_len)
                                }, depth));
                                stack.push((WorkItem::ReadType, depth + 1));
                            }
                        } else {
                            tmp.push(TypePacked::OneOf(variants));
                        }
                    }
                },
            }
        }

        tmp.pop().ok_or(ReaderError::InvalidValue)
    }

    fn size(&self) -> usize {
        let mut size = 0;
        let mut stack = vec![self];

        while let Some(value) = stack.pop() {
            match value {
                TypePacked::Number(_)
                | TypePacked::Bool
                | TypePacked::Bytes
                | TypePacked::String
                | TypePacked::Range(_)
                | TypePacked::Any => size += 1,
                TypePacked::Opaque(_) => size += 3,
                TypePacked::Array(inner)
                | TypePacked::Optional(inner) => {
                    size += 1;
                    stack.push(inner);
                },
                TypePacked::Tuples(fields) => {
                    size += 2;
                    stack.extend(fields);
                },
                TypePacked::Map(key, value) => {
                    size += 1;
                    stack.push(key);
                    stack.push(value);
                },
                TypePacked::OneOf(variants) => {
                    size += 2 + variants.len();
                    stack.extend(variants.iter().flatten());
                }
            }
        }

        size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(value: TypePacked) -> TypePacked {
        let bytes = value.to_bytes();
        let mut reader = Reader::new(&bytes);
        TypePacked::read(&mut reader).expect("Deserialization failed")
    }

    #[track_caller]
    fn assert_type_packed_size(value: &TypePacked) {
        assert_eq!(value.size(), value.to_bytes().len());
    }

    fn nested_array(depth: usize) -> TypePacked {
        let mut value = TypePacked::Bool;
        for _ in 0..depth {
            value = TypePacked::Array(Box::new(value));
        }
        value
    }

    fn nested_optional(depth: usize) -> TypePacked {
        let mut value = TypePacked::Number(NumberType::U64);
        for _ in 0..depth {
            value = TypePacked::Optional(Box::new(value));
        }
        value
    }

    fn nested_map_value(depth: usize) -> TypePacked {
        let mut value = TypePacked::String;
        for _ in 0..depth {
            value = TypePacked::Map(
                Box::new(TypePacked::Number(NumberType::U8)),
                Box::new(value),
            );
        }
        value
    }

    #[test]
    fn test_complex_type_packed_serialization() {
        let original = TypePacked::OneOf(vec![
            vec![
                TypePacked::Number(NumberType::U8),
                TypePacked::String,
            ],
            vec![
                TypePacked::Array(Box::new(TypePacked::Bool)),
            ],
            vec![],
        ]);

        let deserialized = roundtrip(original.clone());

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_type_packed_roundtrip_variants() {
        let opaque = TypePacked::Opaque(42);
        let range = TypePacked::Range(Box::new(NumberType::U128));
        let tuples = TypePacked::Tuples(vec![
            TypePacked::Number(NumberType::U16),
            TypePacked::Bytes,
            TypePacked::Optional(Box::new(TypePacked::Bool)),
        ]);
        let map = TypePacked::Map(
            Box::new(TypePacked::String),
            Box::new(TypePacked::Array(Box::new(TypePacked::Number(NumberType::U32)))),
        );
        let one_of = TypePacked::OneOf(vec![
            vec![TypePacked::Any],
            vec![TypePacked::Bool, TypePacked::String],
        ]);

        let variants = vec![
            TypePacked::Number(NumberType::U256),
            TypePacked::Bool,
            TypePacked::Bytes,
            TypePacked::String,
            opaque,
            range,
            tuples,
            map,
            TypePacked::Optional(Box::new(TypePacked::Number(NumberType::U8))),
            one_of,
        ];

        for original in variants {
            assert_type_packed_size(&original);
            let deserialized = roundtrip(original.clone());
            assert_eq!(original, deserialized);
        }
    }

    #[test]
    fn test_type_packed_size_matches_serialized_len_for_composites() {
        let values = vec![
            TypePacked::Opaque(42),
            TypePacked::Array(Box::new(TypePacked::Bool)),
            TypePacked::Optional(Box::new(TypePacked::Opaque(7))),
            TypePacked::Tuples(vec![
                TypePacked::Number(NumberType::U16),
                TypePacked::Bytes,
                TypePacked::Optional(Box::new(TypePacked::Bool)),
            ]),
            TypePacked::Map(
                Box::new(TypePacked::String),
                Box::new(TypePacked::Array(Box::new(TypePacked::Number(NumberType::U32)))),
            ),
            TypePacked::OneOf(vec![
                vec![TypePacked::Any],
                vec![TypePacked::Bool, TypePacked::Opaque(9)],
                vec![],
            ]),
        ];

        for value in values {
            assert_type_packed_size(&value);
        }
    }

    #[test]
    fn test_max_depth_limit_ok_for_variants() {
        let values = vec![
            nested_array(16),
            nested_optional(16),
            nested_map_value(16),
        ];

        for original in values {
            let result = roundtrip(original.clone());
            assert_eq!(original, result);
        }
    }

    #[test]
    fn test_max_depth_limit_exceeded_for_variants() {
        let values = vec![
            nested_array(17),
            nested_optional(17),
            nested_map_value(17),
        ];

        for original in values {
            let bytes = original.to_bytes();
            let mut reader = Reader::new(&bytes);
            let result = TypePacked::read(&mut reader);
            assert!(result.is_err(), "Depth 17 should be rejected");
        }
    }

    #[test]
    fn test_complex_nesting_within_limit() {
        // Test tuple with nested arrays, accounting for the tuple adding 1 depth level
        let complex = TypePacked::Tuples(vec![
            nested_array(14),
            TypePacked::Optional(Box::new(nested_array(13))),
            TypePacked::Map(
                Box::new(TypePacked::String),
                Box::new(nested_optional(14)),
            ),
        ]);

        let result = roundtrip(complex.clone());
        assert_eq!(complex, result);
    }

    #[test]
    fn test_oneof_with_nested_variants() {
        // Test OneOf with variants containing nested structures
        let one_of = TypePacked::OneOf(vec![
            vec![nested_array(10)],
            vec![TypePacked::String, nested_optional(10)],
            vec![],
        ]);

        let result = roundtrip(one_of.clone());
        assert_eq!(one_of, result);
    }

    #[test]
    fn test_type_packed_order_of_inner_items_is_respected() {
        let first = TypePacked::Tuples(vec![
            TypePacked::Number(NumberType::U8),
            TypePacked::String,
            TypePacked::Bool,
        ]);
        let second = TypePacked::Tuples(vec![
            TypePacked::String,
            first.clone(),
            TypePacked::Number(NumberType::U8),
        ]);

        let first_bytes = first.to_bytes();
        let second_bytes = second.to_bytes();

        assert_ne!(first_bytes, second_bytes, "Tuple order should change serialization");
        assert_eq!(roundtrip(first.clone()), first);
        assert_eq!(roundtrip(second.clone()), second);
    }
}