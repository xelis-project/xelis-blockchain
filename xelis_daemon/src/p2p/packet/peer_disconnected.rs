use xelis_common::serializer::{
    Error as SerializationError,
    Readable,
    Reader,
    ReaderError,
    Serializer,
    Writable,
    Writer,
};
use std::net::SocketAddr;


// this packet is sent when a peer disconnects from one of our peer
// it is used to continue to track common peers between us and our peers
// This is used to avoid the problem of not broadcasting a Block propagation
// when we are broadcasting blocks and that we have him in common but that we
// are not connected anymore to it.
#[derive(Debug)]
pub struct PacketPeerDisconnected {
    addr: SocketAddr // outgoing address
}

impl PacketPeerDisconnected {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr
        }
    }

    pub fn to_addr(self) -> SocketAddr {
        self.addr
    }
}

impl Serializer for PacketPeerDisconnected {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let addr = SocketAddr::read(reader)?;
            Ok(Self::new(addr))
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| self.addr.write(writer))
    }

    fn size(&self) -> usize {
        self.addr.size()
    }
}