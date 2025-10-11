use serde::{Deserialize, Serialize};
use xelis_vm::traits::{JSONHelper, Serializable};
use crate::{block::TopoHeight, serializer::*};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledExecutionKind {
    TopoHeight(TopoHeight),
    BlockEnd
}

impl ScheduledExecutionKind {
    pub fn id(&self) -> u8 {
        match self {
            ScheduledExecutionKind::TopoHeight(_) => 0,
            ScheduledExecutionKind::BlockEnd => 1
        }
    }
}

impl Serializable for ScheduledExecutionKind {}

impl JSONHelper for ScheduledExecutionKind {}

impl Serializer for ScheduledExecutionKind {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let tag = reader.read_u8()?;
        match tag {
            0 => Ok(ScheduledExecutionKind::TopoHeight(u64::read(reader)?)),
            1 => Ok(ScheduledExecutionKind::BlockEnd),
            _ => Err(ReaderError::InvalidValue)
        }
    }

    fn write(&self, writer: &mut Writer) {
        match self {
            ScheduledExecutionKind::TopoHeight(topoheight) => {
                writer.write_u8(0);
                topoheight.write(writer);
            },
            ScheduledExecutionKind::BlockEnd => {
                writer.write_u8(1);
            }
        }
    }

    fn size(&self) -> usize {
        1 + match self {
            ScheduledExecutionKind::TopoHeight(topoheight) => topoheight.size(),
            ScheduledExecutionKind::BlockEnd => 0
        }
    }
}
