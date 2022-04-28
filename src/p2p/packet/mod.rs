pub mod handshake;
pub mod chain;
pub mod ping;
pub mod object;

use crate::core::reader::{Reader, ReaderError};
use crate::core::transaction::Transaction;
use crate::core::serializer::Serializer;
use crate::core::block::CompleteBlock;
use crate::core::writer::Writer;
use self::object::{ObjectRequest, ObjectResponse};
use self::chain::{ChainRequest, ChainResponse};
use self::handshake::Handshake;
use self::ping::Ping;
use std::borrow::Cow;


// All registered packet ids
const HANDSHAKE_ID: u8 = 0;
const TX_PROPAGATION_ID: u8 = 1;
const BLOCK_PROPAGATION_ID: u8 = 2;
const CHAIN_REQUEST_ID: u8 = 3;
const CHAIN_RESPONSE_ID: u8 = 4;
const PING_ID: u8 = 5;
const OBJECT_REQUEST_ID: u8 = 6;
const OBJECT_RESPONSE_ID: u8 = 7;

pub enum Packet<'a> {
    Handshake(Cow<'a, Handshake>),
    TransactionPropagation(Cow<'a, Transaction>),
    BlockPropagation(Cow<'a, CompleteBlock>),
    ChainRequest(Cow<'a, ChainRequest>),
    ChainResponse(ChainResponse<'a>),
    Ping(Cow<'a, Ping>),
    ObjectRequest(Cow<'a, ObjectRequest>),
    ObjectResponse(ObjectResponse<'a>)
}

impl<'a> Serializer for Packet<'a> {
    fn read(reader: &mut Reader) -> Result<Packet<'a>, ReaderError> {
        Ok(match reader.read_u8()? {
            HANDSHAKE_ID => Packet::Handshake(Cow::Owned(Handshake::read(reader)?)),
            TX_PROPAGATION_ID => Packet::TransactionPropagation(Cow::Owned(Transaction::read(reader)?)),
            BLOCK_PROPAGATION_ID => Packet::BlockPropagation(Cow::Owned(CompleteBlock::read(reader)?)),
            CHAIN_REQUEST_ID => Packet::ChainRequest(Cow::Owned(ChainRequest::read(reader)?)),
            CHAIN_RESPONSE_ID => Packet::ChainResponse(ChainResponse::read(reader)?),
            PING_ID => Packet::Ping(Cow::Owned(Ping::read(reader)?)),
            OBJECT_REQUEST_ID => Packet::ObjectRequest(Cow::Owned(ObjectRequest::read(reader)?)),
            OBJECT_RESPONSE_ID => Packet::ObjectResponse(ObjectResponse::read(reader)?),
            _ => return Err(ReaderError::InvalidValue)
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