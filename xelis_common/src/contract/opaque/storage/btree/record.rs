use xelis_vm::ValueCell;

use crate::serializer::{Reader, ReaderError, Serializer, Writer};

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
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let (parent, left, right, key) = read_node_header_parts(reader)?;
        let value = ValueCell::read(reader)?;
        Ok(Self { key, value, parent, left, right })
    }

    fn write(&self, writer: &mut Writer) {
        debug_assert!(self.key.len() <= u32::MAX as usize);
        writer.write_optional_non_zero_u64(self.parent);
        writer.write_optional_non_zero_u64(self.left);
        writer.write_optional_non_zero_u64(self.right);
        writer.write_u32(self.key.len() as u32);
        writer.write_bytes(&self.key);
        self.value.write(writer);
    }

    fn size(&self) -> usize {
        8 * 3 + 4 + self.key.len() + self.value.size()
    }
}

pub fn read_node_header_from_reader(reader: &mut Reader, id: u64) -> Result<NodeHeader, ReaderError> {
    let (parent, left, right, key) = read_node_header_parts(reader)?;
    Ok(NodeHeader { id, key, parent, left, right })
}

pub fn read_node_header_parts(reader: &mut Reader) -> Result<(Option<u64>, Option<u64>, Option<u64>, Vec<u8>), ReaderError> {
    let parent = reader.read_optional_non_zero_u64()?;
    let left = reader.read_optional_non_zero_u64()?;
    let right = reader.read_optional_non_zero_u64()?;

    let key_len = reader.read_u32()? as usize;
    let key = reader.read_bytes_ref(key_len)?.to_vec();

    Ok((parent, left, right, key))
}
