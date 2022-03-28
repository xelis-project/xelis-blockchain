use crate::core::writer::Writer;
use crate::core::reader::{Reader, ReaderError};

pub trait Packet {
    fn write_packet(&self, writer: &mut Writer);
    fn read_packet(reader: &mut Reader) -> Result<(), ReaderError>;
    fn get_id() -> u8;
}