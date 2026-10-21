use crate::serializer::{
    Error as SerializationError,
    OptionNonZero,
    Readable,
    Reader,
    ReaderError,
    Serializer,
    Writable,
    Writer,
};
use xelis_vm::ValueCell;

use super::{Node, NodeHeader};

#[derive(Debug, Clone)]
pub struct NodeRecord {
    pub key: Vec<u8>,
    pub value: ValueCell,
    pub parent: Option<u64>,
    pub left: Option<u64>,
    pub right: Option<u64>,
}

impl From<&Node> for NodeRecord {
    fn from(node: &Node) -> Self {
        Self {
            key: node.key.clone(),
            value: node.value.clone(),
            parent: node.parent,
            left: node.left,
            right: node.right,
        }
    }
}

impl NodeRecord {
    pub fn into_node(self, id: u64) -> Node {
        Node {
            id,
            key: self.key,
            value: self.value,
            parent: self.parent,
            left: self.left,
            right: self.right,
        }
    }
}

impl Serializer for NodeRecord {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let (parent, left, right, key) = read_node_header_parts(reader)?;
            let value = ValueCell::read(reader)?;
            Ok(Self { key, value, parent, left, right })
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            debug_assert!(self.key.len() <= u32::MAX as usize);
            OptionNonZero(self.parent).write(writer)?;
            OptionNonZero(self.left).write(writer)?;
            OptionNonZero(self.right).write(writer)?;
            (self.key.len() as u32).write(writer)?;
            writer.extend_bytes(&self.key)?;
            self.value.write(writer)
        })
    }

    fn size(&self) -> usize {
        8 * 3 + 4 + self.key.len() + self.value.size()
    }
}

pub fn read_node_header_from_reader<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>, id: u64) -> Result<NodeHeader, ReaderError> {
    let (parent, left, right, key) = read_node_header_parts(reader)?;
    Ok(NodeHeader { id, key, parent, left, right })
}

pub fn read_node_header_parts<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<(Option<u64>, Option<u64>, Option<u64>, Vec<u8>), ReaderError> {
    let parent = OptionNonZero::<u64>::read(reader)?.0;
    let left = OptionNonZero::<u64>::read(reader)?.0;
    let right = OptionNonZero::<u64>::read(reader)?.0;

    let key_len = u32::read(reader)? as usize;
    let key = reader.read_vec(key_len)?;

    Ok((parent, left, right, key))
}
