pub mod handshake;
pub mod chain;
pub mod ping;
pub mod object;

use crate::core::reader::{Reader, ReaderError};
use crate::core::serializer::Serializer;
use crate::core::block::CompleteBlock;
use crate::core::writer::Writer;
use crate::crypto::hash::Hash;
use self::object::{ObjectRequest, ObjectResponse};
use self::chain::{ChainRequest, ChainResponse};
use self::handshake::Handshake;
use self::ping::Ping;
use std::borrow::Cow;
use log::{debug, error};

// All registered packet ids
const HANDSHAKE_ID: u8 = 0;
const TX_PROPAGATION_ID: u8 = 1;
const BLOCK_PROPAGATION_ID: u8 = 2;
const CHAIN_REQUEST_ID: u8 = 3;
const CHAIN_RESPONSE_ID: u8 = 4;
const PING_ID: u8 = 5;
const OBJECT_REQUEST_ID: u8 = 6;
const OBJECT_RESPONSE_ID: u8 = 7;

// PacketWrapper allows us to link any Packet to a Ping
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
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let packet = T::read(reader)?;
        let packet = Cow::Owned(packet);
        let ping = Cow::Owned(Ping::read(reader)?);

        Ok(Self::new(packet, ping))
    }

    fn write(&self, writer: &mut Writer) {
        self.packet.write(writer);   
        self.ping.write(writer);
    }
}

pub enum Packet<'a> {
    Handshake(Cow<'a, Handshake>), // first packet to connect to a node
    // packet contains tx hash, view this packet as a "notification"
    // instead of sending the TX directly, we notify our peers
    // so the peer that already have this TX in mempool don't have to read it again
    // imo: can be useful when the network is spammed by alot of txs
    TransactionPropagation(PacketWrapper<'a, Hash>),
    BlockPropagation(PacketWrapper<'a, CompleteBlock>),
    ChainRequest(PacketWrapper<'a, ChainRequest>),
    ChainResponse(ChainResponse<'a>),
    Ping(Cow<'a, Ping<'a>>),
    ObjectRequest(PacketWrapper<'a, ObjectRequest>),
    ObjectResponse(ObjectResponse<'a>)
}

impl<'a> Serializer for Packet<'a> {
    fn read(reader: &mut Reader) -> Result<Packet<'a>, ReaderError> {
        let id = reader.read_u8()?;
        debug!("Packet ID received: {}, size: {}", id, reader.total_size());
        Ok(match id {
            HANDSHAKE_ID => Packet::Handshake(Cow::Owned(Handshake::read(reader)?)),
            TX_PROPAGATION_ID => Packet::TransactionPropagation(PacketWrapper::read(reader)?),
            BLOCK_PROPAGATION_ID => Packet::BlockPropagation(PacketWrapper::read(reader)?),
            CHAIN_REQUEST_ID => Packet::ChainRequest(PacketWrapper::read(reader)?),
            CHAIN_RESPONSE_ID => Packet::ChainResponse(ChainResponse::read(reader)?),
            PING_ID => Packet::Ping(Cow::Owned(Ping::read(reader)?)),
            OBJECT_REQUEST_ID => Packet::ObjectRequest(PacketWrapper::read(reader)?),
            OBJECT_RESPONSE_ID => Packet::ObjectResponse(ObjectResponse::read(reader)?),
            id => {
                error!("Received a invalid packet id: {}", id);
                return Err(ReaderError::InvalidValue)
            }
        })
    }

    fn write(&self, writer: &mut Writer) {
        let (id, packet) = match self { // TODO optimize to_bytes()
            Packet::Handshake(handshake) => (HANDSHAKE_ID, handshake.to_bytes()),
            Packet::TransactionPropagation(tx) => (TX_PROPAGATION_ID, tx.to_bytes()),
            Packet::BlockPropagation(block) => (BLOCK_PROPAGATION_ID, block.to_bytes()),
            Packet::ChainRequest(request) => (CHAIN_REQUEST_ID, request.to_bytes()),
            Packet::ChainResponse(response) => (CHAIN_RESPONSE_ID, response.to_bytes()),
            Packet::Ping(ping) => (PING_ID, ping.to_bytes()),
            Packet::ObjectRequest(request) => (OBJECT_REQUEST_ID, request.to_bytes()),
            Packet::ObjectResponse(response) => (OBJECT_RESPONSE_ID, response.to_bytes())
        };

        let packet_len: u32 = packet.len() as u32 + 1;
        writer.write_u32(&packet_len);
        writer.write_u8(id);
        writer.write_bytes(&packet);
    }
}