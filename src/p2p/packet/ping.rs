use crate::core::reader::{Reader, ReaderError};
use crate::core::serializer::Serializer;
use crate::globals::{ip_to_bytes, ip_from_bytes};
use crate::p2p::peer::Peer;
use crate::core::writer::Writer;
use crate::crypto::hash::Hash;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct Ping {
    block_top_hash: Hash,
    block_height: u64,
    peer_list: Vec<SocketAddr>
}

impl Ping {
    pub fn new(block_top_hash: Hash, block_height: u64, peer_list: Vec<SocketAddr>) -> Self {
        Self {
            block_top_hash,
            block_height,
            peer_list
        }
    }

    pub async fn update_peer(self, peer: &Arc<Peer>) {
        peer.set_block_top_hash(self.block_top_hash).await;
        peer.set_block_height(self.block_height);

        let mut peers = peer.get_peers().lock().await;
        for peer in self.peer_list {
            if !peers.contains(&peer) {
                peers.insert(peer);
            }
        }
    }

    pub fn get_peers(&self) -> &Vec<SocketAddr> {
        &self.peer_list
    }
}

impl Serializer for Ping {
    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.block_top_hash);
        writer.write_u64(&self.block_height);
        writer.write_u8(self.peer_list.len() as u8);
        for peer in &self.peer_list {
            writer.write_bytes(&ip_to_bytes(peer));
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let block_top_hash = reader.read_hash()?;
        let block_height = reader.read_u64()?;
        let peers_len = reader.read_u8()? as usize;
        let mut peer_list = Vec::with_capacity(peers_len);
        for _ in 0..peers_len {
            let peer = ip_from_bytes(reader)?;
            peer_list.push(peer);
        }

        Ok(Self { block_top_hash, block_height, peer_list })
    }
}