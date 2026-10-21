use crate::serializer::{Error as SerializationError, *};

// Dynamic length encoding
// It can encode lengths up to u32::MAX
// Encoding:
// - If length <= 0xFC: 1 byte (length)
// - If length <= 0xFFFF: 1 byte (0xFD) + 2 bytes (length)
// - If length <= 0xFFFFFFFF: 1 byte (0xFE) + 4 bytes (length)
// - 0xFF is reserved for future use
pub struct DynamicLen(pub usize);

impl Serializer for DynamicLen {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let tag = u8::read(reader)?;
            let len = match tag {
                n @ 0x00..=0xFC => n as usize,
                0xFD => u16::read(reader)? as usize,
                0xFE => u32::read(reader)? as usize,
                _ => return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("unsupported dynamic length tag {tag:#04x}; 0xff is reserved"))),
            };
            Ok(Self(len))
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            let len = self.0;
            if len <= 0xFC {
                (len as u8).write(writer)
            } else if len <= 0xFFFF {
                0xFDu8.write(writer)?;
                (len as u16).write(writer)
            } else {
                0xFEu8.write(writer)?;
                (len as u32).write(writer)
            }
        })
    }

    fn size(&self) -> usize {
        let len = self.0;
        if len <= 0xFC {
            1
        } else if len <= 0xFFFF {
            3
        } else {
            5
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serializer::Reader;

    #[test]
    fn test_dynamic_len_serialization() {
        let lengths = [0, 1, 252, 253, 254, 255, 256, 65535, 65536, 1_000_000, u32::MAX as usize];

        for &len in lengths.iter() {
            let dynamic_len = DynamicLen(len);

            let mut bytes = Vec::new();
            let mut writer = Writer::new(&mut bytes);
            dynamic_len.write(&mut writer).unwrap();

            let mut reader = Reader::new(&bytes);
            let decoded = DynamicLen::read(&mut reader).unwrap();

            assert_eq!(dynamic_len.0, decoded.0);
        }
    }
}