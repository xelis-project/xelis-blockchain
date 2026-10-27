mod handshake;
mod chain;
mod ping;
mod object;
mod inventory;
mod bootstrap;
mod peer_disconnected;
mod flags;

use std::borrow::Cow;
use log::{debug, trace, warn};
use xelis_common::{
    block::BlockHeader,
    crypto::Hash,
    serializer::{
        DecodeError,
        Error as SerializationError,
        Readable,
        Reader,
        ReaderError,
        Serializer,
        Writable,
        Writer,
    },
};
use super::{EncryptionKey, error::P2pError};

pub use bootstrap::*;
pub use inventory::*;
pub use object::*;
pub use chain::*;
pub use handshake::*;
pub use peer_disconnected::*;
pub use ping::Ping;
pub use flags::Flags;

// All registered packet ids
const KEY_EXCHANGE_ID: u8 = 0;
const HANDSHAKE_ID: u8 = 1;
const TX_PROPAGATION_ID: u8 = 2;
const BLOCK_PROPAGATION_ID: u8 = 3;
const CHAIN_REQUEST_ID: u8 = 4;
const CHAIN_RESPONSE_ID: u8 = 5;
const PING_ID: u8 = 6;
const OBJECT_REQUEST_ID: u8 = 7;
const OBJECT_RESPONSE_ID: u8 = 8;
const NOTIFY_INV_REQUEST_ID: u8 = 9;
const NOTIFY_INV_RESPONSE_ID: u8 = 10;
const BOOTSTRAP_CHAIN_REQUEST_ID: u8 = 11;
const BOOTSTRAP_CHAIN_RESPONSE_ID: u8 = 12;
const PEER_DISCONNECTED_ID: u8 = 13;

// Outbound packets carry values; inbound packets retain serialized payloads
// until the handler has checked whether they are accepted in the peer context.
#[derive(Debug)]
pub enum PacketMode<T> {
    Opened(T),
    Unopened(Box<[u8]>),
}

impl<T: Serializer> PacketMode<T> {
    pub fn open(self) -> Result<T, P2pError> {
        match self {
            Self::Opened(packet) => Ok(packet),
            Self::Unopened(bytes) => {
                let mut reader = Reader::new(bytes.as_ref());
                let packet = T::read(&mut reader)?;
                if reader.total_read() != bytes.len() {
                    warn!("read packet payload only {}/{} bytes", reader.total_read(), bytes.len());
                    return Err(P2pError::InvalidPacketNotFullRead)
                }
                Ok(packet)
            }
        }
    }
}

impl<T> From<T> for PacketMode<T> {
    fn from(packet: T) -> Self {
        Self::Opened(packet)
    }
}

impl<T: Serializer> Serializer for PacketMode<T> {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        Ok(Self::Unopened(bytes.into()))
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        match self {
            Self::Opened(packet) => packet.write(writer),
            Self::Unopened(bytes) => writer.extend_bytes(bytes),
        }
    }

    fn size(&self) -> usize {
        match self {
            Self::Opened(packet) => packet.size(),
            Self::Unopened(bytes) => bytes.len(),
        }
    }
}

// PacketWrapper allows us to link any Packet to a Ping
#[derive(Debug)]
pub struct PacketWrapper<'a, T: Serializer + Clone> {
    packet: Cow<'a, T>,
    ping: Cow<'a, Ping<'a>>
}

impl<'a, T: Serializer + Clone> PacketWrapper<'a, T> {
    pub fn new(packet: Cow<'a, T>, ping: Cow<'a, Ping<'a>>) -> Self {
        Self {
            packet,
            ping
        }
    }

    pub fn consume(self) -> (Cow<'a, T>, Cow<'a, Ping<'a>>) {
        (self.packet, self.ping)
    }
}

impl<'a, T: Serializer + Clone> Serializer for PacketWrapper<'a, T> {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let packet = T::read(reader)?;
            let packet = Cow::Owned(packet);
            let ping = Cow::Owned(Ping::read(reader)?);

            Ok(Self::new(packet, ping))
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.packet.write(writer)?;   
            self.ping.write(writer)
        })
    }

    fn size(&self) -> usize {
        self.packet.size() + self.ping.size()
    }
}

#[derive(Debug)]
pub enum Packet<'a> {
    Handshake(PacketMode<Cow<'a, Handshake<'a>>>), // first packet to connect to a node
    // packet contains tx hash, view this packet as a "notification"
    // instead of sending the TX directly, we notify our peers
    // so the peer that already have this TX in mempool don't have to read it again
    // imo: can be useful when the network is spammed by alot of txs
    TransactionPropagation(PacketMode<PacketWrapper<'a, Hash>>),
    BlockPropagation(PacketMode<PacketWrapper<'a, BlockHeader>>),
    ChainRequest(PacketMode<PacketWrapper<'a, ChainRequest>>),
    ChainResponse(PacketMode<ChainResponse>),
    Ping(PacketMode<Cow<'a, Ping<'a>>>),
    ObjectRequest(PacketMode<Cow<'a, ObjectRequest>>),
    ObjectResponse(PacketMode<ObjectResponse<'a>>),
    NotifyInventoryRequest(PacketMode<PacketWrapper<'a, NotifyInventoryRequest>>),
    NotifyInventoryResponse(PacketMode<NotifyInventoryResponse<'a>>),
    BootstrapChainRequest(PacketMode<BootstrapChainRequest<'a>>),
    BootstrapChainResponse(PacketMode<BootstrapChainResponse>),
    PeerDisconnected(PacketMode<PacketPeerDisconnected>),
    // Encryption
    KeyExchange(PacketMode<Cow<'a, EncryptionKey>>),
}

impl Packet<'_> {
    pub fn get_id(&self) -> u8 {
        match self {
            Self::KeyExchange(_) => KEY_EXCHANGE_ID,
            Self::Handshake(_) => HANDSHAKE_ID,
            Self::TransactionPropagation(_) => TX_PROPAGATION_ID,
            Self::BlockPropagation(_) => BLOCK_PROPAGATION_ID,
            Self::ChainRequest(_) => CHAIN_REQUEST_ID,
            Self::ChainResponse(_) => CHAIN_RESPONSE_ID,
            Self::Ping(_) => PING_ID,
            Self::ObjectRequest(_) => OBJECT_REQUEST_ID,
            Self::ObjectResponse(_) => OBJECT_RESPONSE_ID,
            Self::NotifyInventoryRequest(_) => NOTIFY_INV_REQUEST_ID,
            Self::NotifyInventoryResponse(_) => NOTIFY_INV_RESPONSE_ID,
            Self::BootstrapChainRequest(_) => BOOTSTRAP_CHAIN_REQUEST_ID,
            Self::BootstrapChainResponse(_) => BOOTSTRAP_CHAIN_RESPONSE_ID,
            Self::PeerDisconnected(_) => PEER_DISCONNECTED_ID,
        }
    }

    pub fn is_order_dependent(&self) -> bool {
        match self {
            Self::ObjectRequest(_)
            | Self::ObjectResponse(_)
            | Self::ChainRequest(_)
            | Self::ChainResponse(_)
            | Self::NotifyInventoryRequest(_)
            | Self::PeerDisconnected(_)
            | Self::Ping(_)
            | Self::BootstrapChainRequest(_)
            | Self::BootstrapChainResponse(_) => false,
            _ => true,
        }
    }

    pub fn is_response(&self) -> bool {
        matches!(self, Self::ObjectResponse(_) | Self::ChainResponse(_) | Self::BootstrapChainResponse(_))
    }
}

impl<'a> Packet<'a> {
    // Reuse the frame allocation and retain only the payload slice, without
    // copying it or deserializing anything beyond the packet ID.
    pub fn from_frame(bytes: Vec<u8>) -> Result<Self, ReaderError> {
        let mut reader = Reader::new(&bytes);
        let id = u8::read(&mut reader)?;
        Self::from_payload(id, bytes[1..].into())
    }

    fn from_payload(id: u8, bytes: Box<[u8]>) -> Result<Self, ReaderError> {
        trace!("Packet ID received: {}", id);
        let packet = match id {
            KEY_EXCHANGE_ID => Self::KeyExchange(PacketMode::Unopened(bytes)),
            HANDSHAKE_ID => Self::Handshake(PacketMode::Unopened(bytes)),
            TX_PROPAGATION_ID => Self::TransactionPropagation(PacketMode::Unopened(bytes)),
            BLOCK_PROPAGATION_ID => Self::BlockPropagation(PacketMode::Unopened(bytes)),
            CHAIN_REQUEST_ID => Self::ChainRequest(PacketMode::Unopened(bytes)),
            CHAIN_RESPONSE_ID => Self::ChainResponse(PacketMode::Unopened(bytes)),
            PING_ID => Self::Ping(PacketMode::Unopened(bytes)),
            OBJECT_REQUEST_ID => Self::ObjectRequest(PacketMode::Unopened(bytes)),
            OBJECT_RESPONSE_ID => Self::ObjectResponse(PacketMode::Unopened(bytes)),
            NOTIFY_INV_REQUEST_ID => Self::NotifyInventoryRequest(PacketMode::Unopened(bytes)),
            NOTIFY_INV_RESPONSE_ID => Self::NotifyInventoryResponse(PacketMode::Unopened(bytes)),
            BOOTSTRAP_CHAIN_REQUEST_ID => Self::BootstrapChainRequest(PacketMode::Unopened(bytes)),
            BOOTSTRAP_CHAIN_RESPONSE_ID => Self::BootstrapChainResponse(PacketMode::Unopened(bytes)),
            PEER_DISCONNECTED_ID => Self::PeerDisconnected(PacketMode::Unopened(bytes)),
            id => {
                debug!("invalid packet id received: {}", id);
                return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("unknown P2P packet ID {id}")))
            }
        };
        Ok(packet)
    }
}

impl<'a> Serializer for Packet<'a> {
    // A packet occupies a complete frame. Its payload is opened by the handler.
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let id = u8::read(reader)?;
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes)?;
            Self::from_payload(id, bytes.into())
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.get_id().write(writer)?;
            match self {
                Self::KeyExchange(key) => key.write(writer),
                Self::Handshake(handshake) => handshake.write(writer),
                Self::TransactionPropagation(tx) => tx.write(writer),
                Self::BlockPropagation(block) => block.write(writer),
                Self::ChainRequest(request) => request.write(writer),
                Self::ChainResponse(response) => response.write(writer),
                Self::Ping(ping) => ping.write(writer),
                Self::ObjectRequest(request) => request.write(writer),
                Self::ObjectResponse(response) => response.write(writer),
                Self::NotifyInventoryRequest(request) => request.write(writer),
                Self::NotifyInventoryResponse(inventory) => inventory.write(writer),
                Self::BootstrapChainRequest(request) => request.write(writer),
                Self::BootstrapChainResponse(response) => response.write(writer),
                Self::PeerDisconnected(disconnected) => disconnected.write(writer),
            }
        })
    }

    fn size(&self) -> usize {
        let payload_size = match self {
            Self::KeyExchange(key) => key.size(),
            Self::Handshake(handshake) => handshake.size(),
            Self::TransactionPropagation(tx) => tx.size(),
            Self::BlockPropagation(block) => block.size(),
            Self::ChainRequest(request) => request.size(),
            Self::ChainResponse(response) => response.size(),
            Self::Ping(ping) => ping.size(),
            Self::ObjectRequest(request) => request.size(),
            Self::ObjectResponse(response) => response.size(),
            Self::NotifyInventoryRequest(request) => request.size(),
            Self::NotifyInventoryResponse(inventory) => inventory.size(),
            Self::BootstrapChainRequest(request) => request.size(),
            Self::BootstrapChainResponse(response) => response.size(),
            Self::PeerDisconnected(disconnected) => disconnected.size(),
        };
        1 + payload_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unopened_packet_defers_payload_validation() {
        // Reading and forwarding every registered packet succeeds even when
        // its entire payload is missing. Opening still validates the payload.
        for id in 0..=13 {
            let packet = Packet::from_frame(vec![id]).unwrap();
            assert_eq!(packet.get_id(), id);
            assert_eq!(packet.to_bytes().unwrap(), vec![id]);
            let packet = Packet::from_bytes(&[id]).unwrap();
            let result = match packet {
                Packet::KeyExchange(payload) => payload.open().map(drop),
                Packet::Handshake(payload) => payload.open().map(drop),
                Packet::TransactionPropagation(payload) => payload.open().map(drop),
                Packet::BlockPropagation(payload) => payload.open().map(drop),
                Packet::ChainRequest(payload) => payload.open().map(drop),
                Packet::ChainResponse(payload) => payload.open().map(drop),
                Packet::Ping(payload) => payload.open().map(drop),
                Packet::ObjectRequest(payload) => payload.open().map(drop),
                Packet::ObjectResponse(payload) => payload.open().map(drop),
                Packet::NotifyInventoryRequest(payload) => payload.open().map(drop),
                Packet::NotifyInventoryResponse(payload) => payload.open().map(drop),
                Packet::BootstrapChainRequest(payload) => payload.open().map(drop),
                Packet::BootstrapChainResponse(payload) => payload.open().map(drop),
                Packet::PeerDisconnected(payload) => payload.open().map(drop),
            };
            assert!(matches!(result, Err(P2pError::ReaderError(_))));
        }
    }

    #[test]
    fn unopened_packet_rejects_missing_or_unknown_id() {
        assert!(Packet::from_frame(Vec::new()).is_err());
        assert!(Packet::from_bytes(&[]).is_err());
        for id in 14..=255 {
            assert!(Packet::from_frame(vec![id]).is_err());
            assert!(Packet::from_bytes(&[id]).is_err());
        }
    }

    #[test]
    fn packet_mode_opened_returns_value() {
        // Opening an already decoded payload returns the original value.
        let key = [42; 32];
        let decoded = PacketMode::Opened(key).open().unwrap();
        assert_eq!(decoded, key);
    }

    #[test]
    fn unopened_packet_preserves_wire_encoding() {
        let key = [42; 32];
        let bytes = Packet::KeyExchange(Cow::Borrowed(&key).into()).to_bytes().unwrap();
        assert_eq!(bytes[0], 0);
        assert_eq!(&bytes[1..], &key);
        let packet = Packet::from_frame(bytes).unwrap();
        match packet {
            Packet::KeyExchange(payload) => assert_eq!(payload.open().unwrap().as_ref(), &key),
            packet => panic!("unexpected packet: {:?}", packet),
        }
    }

    #[test]
    fn unopened_packet_rejects_trailing_bytes_when_opened() {
        let mut bytes = Packet::KeyExchange(PacketMode::Opened(Cow::Owned([42; 32]))).to_bytes().unwrap();
        bytes.push(0);
        match Packet::from_frame(bytes).unwrap() {
            Packet::KeyExchange(payload) => assert!(matches!(payload.open(), Err(P2pError::InvalidPacketNotFullRead))),
            packet => panic!("unexpected packet: {:?}", packet),
        }
    }
}
