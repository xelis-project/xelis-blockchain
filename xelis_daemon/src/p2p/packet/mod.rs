pub mod handshake;
pub mod chain;
pub mod ping;
pub mod object;
pub mod inventory;
pub mod bootstrap_chain;
pub mod peer_disconnected;

use self::bootstrap_chain::{BootstrapChainRequest, BootstrapChainResponse};
use self::inventory::{NotifyInventoryResponse, NotifyInventoryRequest};
use self::object::{ObjectRequest, ObjectResponse};
use self::chain::{ChainRequest, ChainResponse};
use self::handshake::Handshake;
use self::peer_disconnected::PacketPeerDisconnected;
use self::ping::Ping;
use std::borrow::Cow;
use log::{debug, trace};
use xelis_common::{
    serializer::{Serializer, Reader, ReaderError, Writer},
    block::BlockHeader,
    crypto::Hash
};

use super::EncryptionKey;

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

    fn size(&self) -> usize {
        self.packet.size() + self.ping.size()
    }
}

#[derive(Debug)]
pub enum Packet<'a> {
    Handshake(Cow<'a, Handshake<'a>>), // first packet to connect to a node
    // packet contains tx hash, view this packet as a "notification"
    // instead of sending the TX directly, we notify our peers
    // so the peer that already have this TX in mempool don't have to read it again
    // imo: can be useful when the network is spammed by alot of txs
    TransactionPropagation(PacketWrapper<'a, Hash>),
    BlockPropagation(PacketWrapper<'a, BlockHeader>),
    ChainRequest(PacketWrapper<'a, ChainRequest>),
    ChainResponse(ChainResponse),
    Ping(Cow<'a, Ping<'a>>),
    ObjectRequest(Cow<'a, ObjectRequest>),
    ObjectResponse(ObjectResponse<'a>),
    NotifyInventoryRequest(PacketWrapper<'a, NotifyInventoryRequest>),
    NotifyInventoryResponse(NotifyInventoryResponse<'a>),
    BootstrapChainRequest(BootstrapChainRequest<'a>),
    BootstrapChainResponse(BootstrapChainResponse),
    PeerDisconnected(PacketPeerDisconnected),
    // Encryption
    KeyExchange(Cow<'a, EncryptionKey>),
}

impl Packet<'_> {
    pub fn get_id(&self) -> u8 {
        match self {
            Packet::Handshake(_) => HANDSHAKE_ID,
            Packet::TransactionPropagation(_) => TX_PROPAGATION_ID,
            Packet::BlockPropagation(_) => BLOCK_PROPAGATION_ID,
            Packet::ChainRequest(_) => CHAIN_REQUEST_ID,
            Packet::ChainResponse(_) => CHAIN_RESPONSE_ID,
            Packet::Ping(_) => PING_ID,
            Packet::ObjectRequest(_) => OBJECT_REQUEST_ID,
            Packet::ObjectResponse(_) => OBJECT_RESPONSE_ID,
            Packet::NotifyInventoryRequest(_) => NOTIFY_INV_REQUEST_ID,
            Packet::NotifyInventoryResponse(_) => NOTIFY_INV_RESPONSE_ID,
            Packet::BootstrapChainRequest(_) => BOOTSTRAP_CHAIN_REQUEST_ID,
            Packet::BootstrapChainResponse(_) => BOOTSTRAP_CHAIN_RESPONSE_ID,
            Packet::PeerDisconnected(_) => PEER_DISCONNECTED_ID,
            Packet::KeyExchange(_) => KEY_EXCHANGE_ID,
        }
    }
}

impl<'a> Serializer for Packet<'a> {
    fn read(reader: &mut Reader) -> Result<Packet<'a>, ReaderError> {
        let id = reader.read_u8()?;
        trace!("Packet ID received: {}, size: {}", id, reader.total_size());
        let packet = match id {
            KEY_EXCHANGE_ID => Packet::KeyExchange(Cow::Owned(EncryptionKey::read(reader)?)),
            HANDSHAKE_ID => Packet::Handshake(Cow::Owned(Handshake::read(reader)?)),
            TX_PROPAGATION_ID => Packet::TransactionPropagation(PacketWrapper::read(reader)?),
            BLOCK_PROPAGATION_ID => Packet::BlockPropagation(PacketWrapper::read(reader)?),
            CHAIN_REQUEST_ID => Packet::ChainRequest(PacketWrapper::read(reader)?),
            CHAIN_RESPONSE_ID => Packet::ChainResponse(ChainResponse::read(reader)?),
            PING_ID => Packet::Ping(Cow::Owned(Ping::read(reader)?)),
            OBJECT_REQUEST_ID => Packet::ObjectRequest(Cow::Owned(ObjectRequest::read(reader)?)),
            OBJECT_RESPONSE_ID => Packet::ObjectResponse(ObjectResponse::read(reader)?),
            NOTIFY_INV_REQUEST_ID => Packet::NotifyInventoryRequest(PacketWrapper::read(reader)?), 
            NOTIFY_INV_RESPONSE_ID => Packet::NotifyInventoryResponse(NotifyInventoryResponse::read(reader)?),
            BOOTSTRAP_CHAIN_REQUEST_ID => Packet::BootstrapChainRequest(BootstrapChainRequest::read(reader)?),
            BOOTSTRAP_CHAIN_RESPONSE_ID => Packet::BootstrapChainResponse(BootstrapChainResponse::read(reader)?),
            PEER_DISCONNECTED_ID => Packet::PeerDisconnected(PacketPeerDisconnected::read(reader)?),
            id => {
                debug!("invalid packet id received: {}", id);
                return Err(ReaderError::InvalidValue)
            }
        };

        if reader.total_read() != reader.total_size() {
            debug!("Packet: {:?}", packet);
        }

        Ok(packet)
    }

    fn write(&self, writer: &mut Writer) {
        let (id, serializer): (u8, &dyn Serializer) = match self {
            Packet::KeyExchange(key) => (KEY_EXCHANGE_ID, key),
            Packet::Handshake(handshake) => (HANDSHAKE_ID, handshake.as_ref()),
            Packet::TransactionPropagation(tx) => (TX_PROPAGATION_ID, tx),
            Packet::BlockPropagation(block) => (BLOCK_PROPAGATION_ID, block),
            Packet::ChainRequest(request) => (CHAIN_REQUEST_ID, request),
            Packet::ChainResponse(response) => (CHAIN_RESPONSE_ID, response),
            Packet::Ping(ping) => (PING_ID, ping.as_ref()),
            Packet::ObjectRequest(request) => (OBJECT_REQUEST_ID, request.as_ref()),
            Packet::ObjectResponse(response) => (OBJECT_RESPONSE_ID, response),
            Packet::NotifyInventoryRequest(request) => (NOTIFY_INV_REQUEST_ID, request),
            Packet::NotifyInventoryResponse(inventory) => (NOTIFY_INV_RESPONSE_ID, inventory),
            Packet::BootstrapChainRequest(request) => (BOOTSTRAP_CHAIN_REQUEST_ID, request),
            Packet::BootstrapChainResponse(response) => (BOOTSTRAP_CHAIN_RESPONSE_ID, response),
            Packet::PeerDisconnected(disconnected) => (PEER_DISCONNECTED_ID, disconnected),
        };

        let packet = serializer.to_bytes();
        writer.write_u8(id);
        writer.write_bytes(&packet);
    }
}