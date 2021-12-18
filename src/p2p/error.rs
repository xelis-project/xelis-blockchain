use std::fmt::{Display, Error, Formatter};

pub enum P2pError {
    InvalidHandshake,
    InvalidPeerAddress(String), // peer address from handshake
    InvalidNetworkID,
    ChannelNotFound(u64),
    PeerNotFound(u64),
    PeerIdAlreadyUsed(u64),
    OnWrite(String),
    OnLock(String),
    OnStreamBlocking(bool, String),
    OnConnectionClose(String),
    OnChannelMessage(u64, String),
    // Handshake
    InvalidMinSize(usize),
    InvalidVersionSize(usize),
    InvalidTagSize(usize),
    InvalidPeerSize(usize),
    InvalidUtf8Sequence(String)
}

impl Display for P2pError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        use P2pError::*;
        match self {
            InvalidHandshake => write!(f, "Invalid handshake"),
            InvalidPeerAddress(msg) => write!(f, "Invalid peer address, {}", msg),
            InvalidNetworkID => write!(f, "Invalid network ID"),
            ChannelNotFound(peer_id) => write!(f, "No channel found for peer {}", peer_id),
            PeerNotFound(peer_id) => write!(f, "Peer {} not found", peer_id),
            PeerIdAlreadyUsed(id) => write!(f, "Peer id {} is already used!", id),
            InvalidMinSize(got) => write!(f, "Invalid minimum handshake bytes size, got {} bytes", got),
            OnWrite(msg) => write!(f, "Bytes were not sent, error: {}", msg),
            OnLock(msg) => write!(f, "Error while trying to lock: {}", msg),
            OnStreamBlocking(value, msg) => write!(f, "Error while trying to set stream blocking mode to {}: {}", value, msg),
            OnConnectionClose(msg) => write!(f, "Error while trying to close connection: {}", msg),
            OnChannelMessage(peer, msg) => write!(f, "Error while trying to send message for peer {} through channel: {}", peer, msg),
            InvalidVersionSize(got) => write!(f, "Invalid version size, got {} bytes", got),
            InvalidTagSize(got) => write!(f, "Invalid tag size, got {} bytes", got),
            InvalidPeerSize(got) => write!(f, "Invalid peer size, got {} bytes", got),
            InvalidUtf8Sequence(msg) => write!(f, "Invalid bytes for Utf8, {}", msg),
        }
    }
}