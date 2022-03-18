use std::fmt::{Display, Error, Formatter};

pub enum P2pError {
    InvalidHandshake,
    InvalidPeerAddress(String), // peer address from handshake
    InvalidNetworkID,
    ErrorOnLock,
    TryInto(String),
    ChannelNotFound(u64),
    PeerNotFound(u64),
    PeerIdAlreadyUsed(u64),
    OnWrite(String),
    OnLock(String),
    OnStreamBlocking(bool, String),
    OnConnectionClose(String),
    OnChannelMessage(u64, String)
}

impl Display for P2pError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        use P2pError::*;
        match self {
            InvalidHandshake => write!(f, "Invalid handshake"),
            InvalidPeerAddress(msg) => write!(f, "Invalid peer address, {}", msg),
            InvalidNetworkID => write!(f, "Invalid network ID"),
            TryInto(err) => write!(f, "Error on try into: {}", err),
            ChannelNotFound(peer_id) => write!(f, "No channel found for peer {}", peer_id),
            PeerNotFound(peer_id) => write!(f, "Peer {} not found", peer_id),
            PeerIdAlreadyUsed(id) => write!(f, "Peer id {} is already used!", id),
            OnWrite(msg) => write!(f, "Bytes were not sent, error: {}", msg),
            OnLock(msg) => write!(f, "Error while trying to lock: {}", msg),
            OnStreamBlocking(value, msg) => write!(f, "Error while trying to set stream blocking mode to {}: {}", value, msg),
            OnConnectionClose(msg) => write!(f, "Error while trying to close connection: {}", msg),
            OnChannelMessage(peer, msg) => write!(f, "Error while trying to send message for peer {} through channel: {}", peer, msg),
            ErrorOnLock => write!(f, "Error on lock")
        }
    }
}