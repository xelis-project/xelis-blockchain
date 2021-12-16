pub enum P2pError {
    InvalidHandshake,
    InvalidPeerAddress(String), // peer address from handshake
    InvalidNetworkID,
    PeerIdAlreadyUsed(u64),
    // Handshake
    InvalidMinSize(usize),
    InvalidVersionSize(usize),
    InvalidTagSize(usize),
    InvalidPeerSize(usize),
    InvalidUtf8Sequence(String)
}


use std::fmt::{Display, Error, Formatter};

impl Display for P2pError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        use P2pError::*;
        match self {
            InvalidHandshake => write!(f, "Invalid handshake"),
            InvalidPeerAddress(msg) => write!(f, "Invalid peer address, {}", msg),
            InvalidNetworkID => write!(f, "Invalid network ID"),
            PeerIdAlreadyUsed(id) => write!(f, "Peer id {} is already used!", id),
            InvalidMinSize(got) => write!(f, "Invalid minimum handshake bytes size, got {} bytes", got),
            InvalidVersionSize(got) => write!(f, "Invalid version size, got {} bytes", got),
            InvalidTagSize(got) => write!(f, "Invalid tag size, got {} bytes", got),
            InvalidPeerSize(got) => write!(f, "Invalid peer size, got {} bytes", got),
            InvalidUtf8Sequence(msg) => write!(f, "Invalid bytes for Utf8, {}", msg),
        }
    }
}