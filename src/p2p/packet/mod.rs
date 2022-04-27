pub mod handshake;
pub mod request_chain;
pub mod ping;
pub mod packet;

use crate::core::reader::{Reader, ReaderError};
use crate::core::transaction::Transaction;
use crate::core::serializer::Serializer;
use crate::core::block::CompleteBlock;
use crate::core::writer::Writer;
use super::packet::handshake::Handshake;
use super::packet::request_chain::RequestChain;
use super::packet::ping::Ping;
use std::borrow::Cow;
use log::debug;

const HANDSHAKE_ID: u8 = 0;
const TX_ID: u8 = 1;
const BLOCK_ID: u8 = 2;
const REQUEST_CHAIN_ID: u8 = 3;
const PING_ID: u8 = 4;

pub enum Packet<'a> {
    Handshake(Cow<'a, Handshake>),
    Transaction(Cow<'a, Transaction>),
    Block(Cow<'a, CompleteBlock>),
    RequestChain(Cow<'a, RequestChain>),
    Ping(Cow<'a, Ping>)
}

impl<'a> Serializer for Packet<'a> {
    fn read(reader: &mut Reader) -> Result<Packet<'a>, ReaderError> {
        let res = match reader.read_u8()? {
            HANDSHAKE_ID => Packet::Handshake(Cow::Owned(Handshake::read(reader)?)),
            TX_ID => Packet::Transaction(Cow::Owned(Transaction::read(reader)?)),
            BLOCK_ID => Packet::Block(Cow::Owned(CompleteBlock::read(reader)?)),
            REQUEST_CHAIN_ID => Packet::RequestChain(Cow::Owned(RequestChain::read(reader)?)),
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
            Packet::RequestChain(request) => (REQUEST_CHAIN_ID, request.to_bytes()),
            Packet::Ping(ping) => (PING_ID, ping.to_bytes())
        };

        let packet_len: u32 = packet.len() as u32 + 1;
        writer.write_u32(&packet_len);
        writer.write_u8(id);
        writer.write_bytes(&packet);
    }
}