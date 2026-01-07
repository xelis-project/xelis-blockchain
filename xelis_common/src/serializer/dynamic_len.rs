use super::*;

// Dynamic length encoding
// It can encode lengths up to u32::MAX
// Encoding:
// - If length <= 0xFC: 1 byte (length)
// - If length <= 0xFFFF: 1 byte (0xFD) + 2 bytes (length)
// - If length <= 0xFFFFFFFF: 1 byte (0xFE) + 4 bytes (length)
// - 0xFF is reserved for future use
pub struct DynamicLen(pub usize);

impl Serializer for DynamicLen {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let tag = reader.read_u8()?;
        let len = match tag {
            n @ 0x00..=0xFC => n as usize,
            0xFD => reader.read_u16()? as usize,
            0xFE => reader.read_u32()? as usize,
            _ => return Err(ReaderError::InvalidValue),
        };
        Ok(Self(len))
    }

    fn write(&self, writer: &mut Writer) {
        let len = self.0;
        if len <= 0xFC {
            writer.write_u8(len as u8);
        } else if len <= 0xFFFF {
            writer.write_u8(0xFD);
            writer.write_u16(len as u16);
        } else {
            writer.write_u8(0xFE);
            writer.write_u32(len as u32);
        }
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
            dynamic_len.write(&mut writer);

            let mut reader = Reader::new(&bytes);
            let decoded = DynamicLen::read(&mut reader).unwrap();

            assert_eq!(dynamic_len.0, decoded.0);
        }
    }
}