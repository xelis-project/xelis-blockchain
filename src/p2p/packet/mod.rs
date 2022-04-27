pub mod handshake;
pub mod chain;
pub mod ping;
pub mod packet;

use crate::core::reader::{Reader, ReaderError};
use crate::core::transaction::Transaction;
use crate::core::serializer::Serializer;
use crate::core::block::CompleteBlock;
use crate::core::writer::Writer;
use super::packet::handshake::Handshake;
use super::packet::chain::{ChainRequest, ChainResponse};
use super::packet::ping::Ping;
use std::borrow::Cow;

const HANDSHAKE_ID: u8 = 0;
const TX_ID: u8 = 1;
const BLOCK_ID: u8 = 2;
const CHAIN_REQUEST_ID: u8 = 3;
const CHAIN_RESPONSE_ID: u8 = 4;
const PING_ID: u8 = 5;

pub enum Packet<'a> {
    Handshake(Cow<'a, Handshake>),
    Transaction(Cow<'a, Transaction>),
    Block(Cow<'a, CompleteBlock>),
    ChainRequest(Cow<'a, ChainRequest>),
    ChainResponse(ChainResponse<'a>),
    Ping(Cow<'a, Ping>)
}

impl<'a> Serializer for Packet<'a> {
    fn read(reader: &mut Reader) -> Result<Packet<'a>, ReaderError> {
        let res = match reader.read_u8()? {
            HANDSHAKE_ID => Packet::Handshake(Cow::Owned(Handshake::read(reader)?)),
            TX_ID => Packet::Transaction(Cow::Owned(Transaction::read(reader)?)),
            BLOCK_ID => Packet::Block(Cow::Owned(CompleteBlock::read(reader)?)),
            CHAIN_REQUEST_ID => Packet::ChainRequest(Cow::Owned(ChainRequest::read(reader)?)),
            CHAIN_RESPONSE_ID => Packet::ChainResponse(ChainResponse::read(reader)?),
            PING_ID => Packet::Ping(Cow::Owned(Ping::read(reader)?)),
            _ => return Err(ReaderError::InvalidValue)
        };
        Ok(res)
    }

    fn write(&self, writer: &mut Writer) {
        let (id, packet) = match self { // TODO optimize to_bytes()
            Packet::Handshake(handshake) => (HANDSHAKE_ID, handshake.to_bytes()),
            Packet::Transaction(tx) => (TX_ID, tx.to_bytes()),
            Packet::Block(block) => (BLOCK_ID, block.to_bytes()),
            Packet::ChainRequest(request) => (CHAIN_REQUEST_ID, request.to_bytes()),
            Packet::ChainResponse(response) => (CHAIN_RESPONSE_ID, response.to_bytes()),
            Packet::Ping(ping) => (PING_ID, ping.to_bytes()),
        };

        let packet_len: u32 = packet.len() as u32 + 1;
        writer.write_u32(&packet_len);
        writer.write_u8(id);
        writer.write_bytes(&packet);
    }
}