use xelis_common::{
    config::P2P_PING_PEER_LIST_LIMIT,
    crypto::hash::Hash,
    serializer::{
        Writer,
        Serializer,
        ReaderError,
        Reader
    },
    globals::{
        ip_to_bytes,
        ip_from_bytes
    }, block::Difficulty
};
use crate::p2p::{peer::Peer, error::P2pError};
use std::{
    fmt::Display,
    borrow::Cow,
    net::SocketAddr,
    sync::Arc
};
use log::{error, trace};


#[derive(Clone, Debug)]
pub struct Ping<'a> {
    top_hash: Cow<'a, Hash>,
    topoheight: u64,
    height: u64,
    pruned_topoheight: Option<u64>,
    cumulative_difficulty: Difficulty,
    peer_list: Vec<SocketAddr>
}

impl<'a> Ping<'a> {
    pub fn new(top_hash: Cow<'a, Hash>, topoheight: u64, height: u64, pruned_topoheight: Option<u64>, cumulative_difficulty: u64, peer_list: Vec<SocketAddr>) -> Self {
        Self {
            top_hash,
            topoheight,
            height,
            pruned_topoheight,
            cumulative_difficulty,
            peer_list
        }
    }

    pub async fn update_peer(self, peer: &Arc<Peer>) -> Result<(), P2pError> {
        trace!("Updating {} with {}", peer, self);
        peer.set_block_top_hash(self.top_hash.into_owned()).await;
        peer.set_topoheight(self.topoheight);
        peer.set_height(self.height);

        if peer.is_pruned() && self.pruned_topoheight.is_none() {
            error!("Invalid protocol rules: impossible to change the pruned state (), from {} in ping packet", peer);
            return Err(P2pError::InvalidProtocolRules)
        }

        if let Some(pruned_topoheight) = self.pruned_topoheight {
            if pruned_topoheight > self.topoheight {
                error!("Invalid protocol rules: pruned topoheight {} is greater than height {} in ping packet", pruned_topoheight, self.height);
                return Err(P2pError::InvalidProtocolRules)
            }

            if let Some(old_pruned_topoheight) = peer.get_pruned_topoheight() {
                if pruned_topoheight < old_pruned_topoheight {
                    error!("Invalid protocol rules: pruned topoheight {} is less than old pruned topoheight {} in ping packet", pruned_topoheight, old_pruned_topoheight);
                    return Err(P2pError::InvalidProtocolRules)
                }
            }
        }

        peer.set_pruned_topoheight(self.pruned_topoheight);
        peer.set_cumulative_difficulty(self.cumulative_difficulty);

        let mut peers = peer.get_peers().lock().await;
        for addr in self.peer_list {
            if peers.contains(&addr) {
                error!("Invalid protocol rules: received duplicated peer {} from {} in ping packet", peer, addr);
                return Err(P2pError::InvalidProtocolRules)
            }
            peers.insert(addr);
        }
        Ok(())
    }

    pub fn get_height(&self) -> u64 {
        self.height
    }

    pub fn get_topoheight(&self) -> u64 {
        self.topoheight
    }

    pub fn set_peers(&mut self, peers: Vec<SocketAddr>) {
        self.peer_list = peers;
    }

    pub fn get_peers(&self) -> &Vec<SocketAddr> {
        &self.peer_list
    }
}

impl Serializer for Ping<'_> {
    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.top_hash);
        writer.write_u64(&self.topoheight);
        writer.write_u64(&self.height);
        writer.write_optional_non_zero_u64(&self.pruned_topoheight);
        writer.write_u64(&self.cumulative_difficulty);
        writer.write_u8(self.peer_list.len() as u8);
        for peer in &self.peer_list {
            writer.write_bytes(&ip_to_bytes(peer));
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let top_hash = Cow::Owned(reader.read_hash()?);
        let topoheight = reader.read_u64()?;
        let height = reader.read_u64()?;
        let pruned_topoheight = reader.read_optional_non_zero_u64()?;
        let cumulative_difficulty = reader.read_u64()?;
        let peers_len = reader.read_u8()? as usize;
        if peers_len > P2P_PING_PEER_LIST_LIMIT {
            return Err(ReaderError::InvalidValue)
        }

        let mut peer_list = Vec::with_capacity(peers_len);
        for _ in 0..peers_len {
            let peer = ip_from_bytes(reader)?;
            peer_list.push(peer);
        }

        Ok(Self { top_hash, topoheight, height, pruned_topoheight, cumulative_difficulty, peer_list })
    }
}

impl Display for Ping<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ping[top_hash: {}, topoheight: {}, height: {}, pruned topoheight: {:?}, peers length: {}]", self.top_hash, self.topoheight, self.height, self.pruned_topoheight, self.peer_list.len())
    }
}