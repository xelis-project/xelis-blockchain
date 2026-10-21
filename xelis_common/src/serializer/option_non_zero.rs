use crate::serializer::{
    Error as SerializationError,
    Readable,
    Reader,
    ReaderError,
    Serializer,
    Writable,
    Writer,
};

/// An optional number encoded as a single `T`, with zero representing `None`.
/// `Some(0)` has the same encoding as `None` and decodes as `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionNonZero<T>(pub Option<T>);

impl<T: Serializer + From<u8> + PartialEq> Serializer for OptionNonZero<T> {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            match &self.0 {
                Some(value) => value.write(writer),
                None => T::from(0u8).write(writer),
            }
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let value = T::read(reader)?;
            Ok(Self((value != T::from(0u8)).then_some(value)))
        })
    }

    fn size(&self) -> usize {
        match &self.0 {
            Some(value) => value.size(),
            None => T::from(0u8).size(),
        }
    }
}
