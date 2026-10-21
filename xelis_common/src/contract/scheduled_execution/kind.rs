use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use xelis_vm::ValueCell;
use crate::{
    block::TopoHeight,
    crypto::{Hash, hash_multiple},
    serializer::{Error as SerializationError, *},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledExecutionKind {
    TopoHeight {
        execution_topoheight: TopoHeight,
        registration_topoheight: TopoHeight
    },
    BlockEnd
}

impl ScheduledExecutionKind {
    pub fn id(&self) -> u8 {
        match self {
            ScheduledExecutionKind::TopoHeight { .. } => 0,
            ScheduledExecutionKind::BlockEnd => 1
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(ScheduledExecutionKind::TopoHeight {
                execution_topoheight: TopoHeight::default(),
                registration_topoheight: TopoHeight::default()
            }),
            1 => Some(ScheduledExecutionKind::BlockEnd),
            _ => None
        }
    }

    // Returns a hash of the scheduled execution kind and the executor's hash
    pub fn get_hash(&self, executor: &Hash) -> Hash {
        match self {
            ScheduledExecutionKind::TopoHeight { execution_topoheight, .. } => {
                hash_multiple(&[
                    executor.as_bytes(),
                    &[self.id()],
                    &execution_topoheight.to_be_bytes(),
                ])
            },
            ScheduledExecutionKind::BlockEnd => hash_multiple(&[executor.as_bytes(), &[self.id()]])
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledExecutionKindLog {
    TopoHeight {
        execution_topoheight: TopoHeight,
        registration_topoheight: TopoHeight,
    },
    // Inlined execution into the log
    BlockEnd {
        chunk_id: u16,
        max_gas: u64,
        params: Vec<ValueCell>,
    },
}

impl Serializer for ScheduledExecutionKind {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let tag = u8::read(reader)?;
            match tag {
                0 => Ok(ScheduledExecutionKind::TopoHeight {
                    execution_topoheight: TopoHeight::read(reader)?,
                    registration_topoheight: TopoHeight::read(reader)?,
                }),
                1 => Ok(ScheduledExecutionKind::BlockEnd),
                tag => Err(SerializationError::new(DecodeError::InvalidValue).context(format!("unknown scheduled execution kind tag {tag}")))
            }
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            match self {
                ScheduledExecutionKind::TopoHeight { execution_topoheight, registration_topoheight } => {
                    0u8.write(writer)?;
                    execution_topoheight.write(writer)?;
                    registration_topoheight.write(writer)
                },
                ScheduledExecutionKind::BlockEnd => 1u8.write(writer),
            }
        })
    }

    fn size(&self) -> usize {
        1 + match self {
            ScheduledExecutionKind::TopoHeight { execution_topoheight, registration_topoheight } => execution_topoheight.size() + registration_topoheight.size(),
            ScheduledExecutionKind::BlockEnd => 0
        }
    }
}

impl Serializer for ScheduledExecutionKindLog {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let tag = u8::read(reader)?;
            match tag {
                0 => Ok(ScheduledExecutionKindLog::TopoHeight { execution_topoheight: TopoHeight::read(reader)?, registration_topoheight: TopoHeight::read(reader)? }),
                1 => Ok(ScheduledExecutionKindLog::BlockEnd {
                    chunk_id: u16::read(reader)?,
                    max_gas: u64::read(reader)?,
                    params: Vec::read(reader)?,
                }),
                tag => Err(SerializationError::new(DecodeError::InvalidValue).context(format!("unknown scheduled execution log kind tag {tag}")))
            }
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            match self {
                ScheduledExecutionKindLog::TopoHeight { execution_topoheight, registration_topoheight } => {
                    0u8.write(writer)?;
                    execution_topoheight.write(writer)?;
                    registration_topoheight.write(writer)
                },
                ScheduledExecutionKindLog::BlockEnd { chunk_id, max_gas, params }=> {
                    1u8.write(writer)?;
                    chunk_id.write(writer)?;
                    max_gas.write(writer)?;
                    params.write(writer)
                }
            }
        })
    }

    fn size(&self) -> usize {
        1 + match self {
            ScheduledExecutionKindLog::TopoHeight { execution_topoheight, registration_topoheight } => execution_topoheight.size() + registration_topoheight.size(),
            ScheduledExecutionKindLog::BlockEnd {
                chunk_id,
                max_gas,
                params
            } => chunk_id.size() + max_gas.size() + params.size()
        }
    }
}
