use crate::serializer::{Error as SerializationError, *};

pub struct Count(pub usize);

impl Serializer for Count {
    fn write<'ty, 'r, W: Writable>(&self, _: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> { Ok(()) }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(Self(reader.read_all_bytes()?.len()))
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ReaderError> {
        Ok(Self(bytes.len()))
    }
}