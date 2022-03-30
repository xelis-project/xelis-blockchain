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
use log::debug;

const HANDSHAKE_ID: u8 = 0;
const TX_ID: u8 = 1;
const BLOCK_ID: u8 = 2;
const REQUEST_CHAIN_ID: u8 = 3;
const PING_ID: u8 = 4;

// TODO Rework this

pub enum PacketOut<'a> { // Outgoing Packet
    Handshake(&'a Handshake),
    Transaction(&'a Transaction),
    Block(&'a CompleteBlock),
    RequestChain(&'a RequestChain),
    Ping(&'a Ping)
}

impl<'a> Serializer for PacketOut<'a> {
    fn read(_: &mut Reader) -> Result<PacketOut<'a>, ReaderError> {
        Err(ReaderError::InvalidValue)
    }

    fn write(&self, writer: &mut Writer) {
        let (id, packet) = match self { // TODO optimize to_bytes()
            PacketOut::Handshake(handshake) => (HANDSHAKE_ID, handshake.to_bytes()),
            PacketOut::Transaction(tx) => (TX_ID, tx.to_bytes()),
            PacketOut::Block(block) => (BLOCK_ID, block.to_bytes()),
            PacketOut::RequestChain(request) => (REQUEST_CHAIN_ID, request.to_bytes()),
            PacketOut::Ping(ping) => (PING_ID, ping.to_bytes())
        };

        let packet_len: u32 = packet.len() as u32 + 1;
        debug!("Packet ID: {}, size: {}", id, packet_len);
        writer.write_u32(&packet_len);
        writer.write_u8(id);
        writer.write_bytes(&packet);
    }
}

pub enum PacketIn { // Incoming Packet
    Handshake(Handshake),
    Transaction(Transaction),
    Block(CompleteBlock),
    RequestChain(RequestChain),
    Ping(Ping)
}

impl Serializer for PacketIn {
    fn read(reader: &mut Reader) -> Result<PacketIn, ReaderError> {
        let res = match reader.read_u8()? {
            HANDSHAKE_ID => PacketIn::Handshake(Handshake::read(reader)?),
            TX_ID => PacketIn::Transaction(Transaction::read(reader)?),
            BLOCK_ID => PacketIn::Block(CompleteBlock::read(reader)?),
            REQUEST_CHAIN_ID => PacketIn::RequestChain(RequestChain::read(reader)?),
            PING_ID => PacketIn::Ping(Ping::read(reader)?),
            _ => return Err(ReaderError::InvalidValue)
        };
        Ok(res)
    }

    // not serializable
    fn write(&self, writer: &mut Writer) {}
}