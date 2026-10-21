use octet::Serializable as OctetSerializable;
use crate::serializer::{
    DecodeError,
    Error as SerializationError,
    Readable,
    Reader,
    ReaderError,
    Serializer,
    Writable,
    Writer,
};

impl Serializer for u8 {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        OctetSerializable::write(self, writer)
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        <u8 as OctetSerializable>::read(reader)
    }

    fn size(&self) -> usize {
        1
    }
}

impl Serializer for u16 {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        OctetSerializable::write(self, writer)
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        <u16 as OctetSerializable>::read(reader)
    }

    fn size(&self) -> usize {
        2
    }
}

impl Serializer for u32 {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        OctetSerializable::write(self, writer)
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        <u32 as OctetSerializable>::read(reader)
    }

    fn size(&self) -> usize {
        4
    }
}

impl Serializer for u64 {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        OctetSerializable::write(self, writer)
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        <u64 as OctetSerializable>::read(reader)
    }

    fn size(&self) -> usize {
        8
    }
}

impl Serializer for u128 {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        OctetSerializable::write(self, writer)
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        <u128 as OctetSerializable>::read(reader)
    }

    fn size(&self) -> usize {
        16
    }
}

impl Serializer for bool {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        OctetSerializable::write(self, writer)
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let tag = <u8 as OctetSerializable>::read(reader)?;
            match tag {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(SerializationError::new(DecodeError::InvalidValue)
                    .context(format!("invalid boolean byte {tag}; expected 0 or 1"))),
            }
        })
    }

    fn size(&self) -> usize {
        1
    }
}
