pub enum P2pError {
    AcceptingConnection,
    ConnectToPeer,
    InvalidHandshake,
    RetrievePeerAddress,
    InvalidPeerAddress, // peer address from handshake
    InvalidNetworkID,
}