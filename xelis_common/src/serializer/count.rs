use super::*;

pub struct Count(pub usize);

impl Serializer for Count {
    fn write(&self, _: &mut Writer) {}

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self(reader.total_size()))
    }
}