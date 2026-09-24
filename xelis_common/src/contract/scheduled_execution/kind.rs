use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use xelis_vm::{traits::{JSONHelper, Serializable}, ValueCell};
use crate::{block::TopoHeight, serializer::*};

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

impl Serializable for ScheduledExecutionKind {}

impl JSONHelper for ScheduledExecutionKind {}

impl Serializer for ScheduledExecutionKind {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let tag = reader.read_u8()?;
        match tag {
            0 => Ok(ScheduledExecutionKind::TopoHeight {
                execution_topoheight: TopoHeight::read(reader)?,
                registration_topoheight: TopoHeight::read(reader)?,
            }),
            1 => Ok(ScheduledExecutionKind::BlockEnd),
            _ => Err(ReaderError::InvalidValue)
        }
    }

    fn write(&self, writer: &mut Writer) {
        match self {
            ScheduledExecutionKind::TopoHeight { execution_topoheight, registration_topoheight } => {
                writer.write_u8(0);
                execution_topoheight.write(writer);
                registration_topoheight.write(writer);
            },
            ScheduledExecutionKind::BlockEnd => {
                writer.write_u8(1);
            }
        }
    }

    fn size(&self) -> usize {
        1 + match self {
            ScheduledExecutionKind::TopoHeight { execution_topoheight, registration_topoheight } => execution_topoheight.size() + registration_topoheight.size(),
            ScheduledExecutionKind::BlockEnd => 0
        }
    }
}

impl Serializer for ScheduledExecutionKindLog {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let tag = reader.read_u8()?;
        match tag {
            0 => Ok(ScheduledExecutionKindLog::TopoHeight { execution_topoheight: TopoHeight::read(reader)?, registration_topoheight: TopoHeight::read(reader)? }),
            1 => Ok(ScheduledExecutionKindLog::BlockEnd {
                chunk_id: u16::read(reader)?,
                max_gas: u64::read(reader)?,
                params: Vec::read(reader)?,
            }),
            _ => Err(ReaderError::InvalidValue)
        }
    }

    fn write(&self, writer: &mut Writer) {
        match self {
            ScheduledExecutionKindLog::TopoHeight { execution_topoheight, registration_topoheight } => {
                writer.write_u8(0);
                execution_topoheight.write(writer);
                registration_topoheight.write(writer);
            },
            ScheduledExecutionKindLog::BlockEnd { chunk_id, max_gas, params }=> {
                writer.write_u8(1);
                chunk_id.write(writer);
                max_gas.write(writer);
                params.write(writer);
            }
        }
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
