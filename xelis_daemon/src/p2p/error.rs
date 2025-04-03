use crate::{
    core::error::BlockchainError,
    config::{CHAIN_SYNC_RESPONSE_MAX_BLOCKS, CHAIN_SYNC_RESPONSE_MIN_BLOCKS}
};
use anyhow::Error;
use tokio::{
    sync::{
        AcquireError,
        mpsc::error::SendError as TSendError,
        oneshot::error::RecvError,
    },
    time::error::Elapsed
};
use xelis_common::{
    api::daemon::TimedDirection,
    crypto::Hash,
    serializer::ReaderError,
};
use std::{
    array::TryFromSliceError,
    net::{AddrParseError, SocketAddr},
    sync::{
        mpsc::SendError,
        PoisonError,
    },
    io::Error as IOError
};
use thiserror::Error;
use super::{
    disk_cache::DiskError,
    encryption::EncryptionError,
    packet::{
        bootstrap_chain::StepKind,
        object::{ObjectRequest, OwnedObjectResponse},
    }
};

#[derive(Error, Debug)]
pub enum P2pError {
    #[error("Invalid Diffie-Hellman key")]
    InvalidDHKey,
    #[error("Invalid local port, it must be greater than 0")]
    InvalidLocalPort,
    #[error("disk error: {0}")]
    DiskError(#[from] DiskError),
    #[error("Invalid P2P version: {}", _0)]
    InvalidP2pVersion(String),
    #[error("Invalid tag, it must be greater than 0 and maximum 16 chars")]
    InvalidTag,
    #[error("Invalid max chain response size, it must be between {} and {}", CHAIN_SYNC_RESPONSE_MIN_BLOCKS, CHAIN_SYNC_RESPONSE_MAX_BLOCKS)]
    InvalidMaxChainResponseSize,
    #[error("Invalid max peers, it must be greater than 0")]
    InvalidMaxPeers,
    #[error("Already closed")]
    AlreadyClosed,
    #[error("Incompatible with configured exclusive nodes")]
    ExclusiveNode,
    #[error("Address is not allowed to connect")]
    NotAllowed,
    #[error("Peer list is full")]
    PeerListFull,
    #[error("Tracker request has expired, we didn't received a valid response in time")]
    TrackerRequestExpired,
    #[error("Peer not found by id {}", _0)]
    PeerNotFoundById(u64),
    #[error("Invalid pop count, got {} with only {} blocks", _0, _1)]
    InvalidPopCount(u64, u64),
    #[error("Block id list is malformed")]
    InvalidBlockIdList,
    #[error("Incompatible direction received")]
    InvalidDirection,
    #[error("Invalid merkle hash")]
    InvalidMerkleHash,
    #[error("Duplicated peer {} received from {} received in ping packet (direction = {:?})", _0, _1, _2)]
    DuplicatedPeer(SocketAddr, SocketAddr, TimedDirection),
    #[error("Pruned topoheight {} is greater than topoheight {} in ping packet", _0, _1)]
    InvalidPrunedTopoHeight(u64, u64),
    #[error("Pruned topoheight {} is less than old pruned topoheight {} in ping packet", _0, _1)]
    InvalidNewPrunedTopoHeight(u64, u64),
    #[error("impossible to change the pruned state")]
    InvalidPrunedTopoHeightChange,
    #[error("Peer {} send us its own socket address", _0)]
    OwnSocketAddress(SocketAddr),
    #[error("Local socket address {} received from peer", _0)]
    LocalSocketAddress(SocketAddr),
    #[error("Invalid list size in pagination with a next page")]
    InvalidInventoryPagination,
    #[error("unknown peer {} disconnected from {}", _0, _1)]
    UnknownPeerReceived(SocketAddr, SocketAddr),
    #[error("Block {} at height {} propagated is under our stable height", _0, _1)]
    BlockPropagatedUnderStableHeight(Hash, u64),
    #[error("Block {} propagated is already tracked with direction {:?}", _0, _1)]
    AlreadyTrackedBlock(Hash, TimedDirection),
    #[error("Transaction {} propagated is already tracked", _0)]
    AlreadyTrackedTx(Hash),
    #[error("Malformed chain request, received {} blocks id", _0)]
    MalformedChainRequest(usize),
    #[error("Received a unrequested chain response")]
    UnrequestedChainResponse,
    #[error("Invalid chain response size, got {} blocks while maximum set was {}", _0, _1)]
    InvalidChainResponseSize(usize, usize),
    #[error("Received a unrequested bootstrap chain response")]
    UnrequestedBootstrapChainResponse,
    #[error("Invalid common point at topoheight {}", _0)]
    InvalidCommonPoint(u64),
    #[error("Peer disconnected")]
    Disconnected,
    #[error("Invalid handshake")]
    InvalidHandshake,
    #[error("Expected Handshake packet")]
    ExpectedHandshake,
    #[error("Invalid peer address, {}", _0)]
    InvalidPeerAddress(String), // peer address from handshake
    #[error("Invalid network")]
    InvalidNetwork,
    #[error("Invalid network ID")]
    InvalidNetworkID,
    #[error("Peer id {} is already used!", _0)]
    PeerIdAlreadyUsed(u64),
    #[error("Peer already connected: {}", _0)]
    PeerAlreadyConnected(SocketAddr),
    #[error(transparent)]
    ErrorStd(#[from] IOError),
    #[error("Poison Error: {}", _0)]
    PoisonError(String),
    #[error("Send Error: {}", _0)]
    SendError(String),
    #[error(transparent)]
    TryInto(#[from] TryFromSliceError),
    #[error(transparent)]
    ReaderError(#[from] ReaderError),
    #[error(transparent)]
    ParseAddressError(#[from] AddrParseError),
    #[error("Invalid packet ID")]
    InvalidPacket,
    #[error("Peer topoheight is higher than our")]
    InvalidRequestedTopoheight,
    #[error("Packet size exceed limit")]
    InvalidPacketSize,
    #[error("Received valid packet with not used bytes")]
    InvalidPacketNotFullRead,
    #[error("Request sync chain too fast")]
    RequestSyncChainTooFast,
    #[error(transparent)]
    AsyncTimeOut(#[from] Elapsed),
    #[error("No response received from peer")]
    NoResponse,
    #[error("Invalid object hash, expected: {}, got: {}", _0, _1)]
    InvalidObjectHash(Hash, Hash),
    #[error("Object requested {} not found", _0)]
    ObjectNotFound(ObjectRequest),
    #[error("Object not requested {}", _0)]
    ObjectNotRequested(ObjectRequest),
    #[error("Object requested {} is not present any more in queue", _0)]
    ObjectNotPresentInQueue(Hash),
    #[error("Object requested {} already requested", _0)]
    ObjectAlreadyRequested(ObjectRequest),
    #[error("Invalid object response for request, received hash: {}", _0)]
    InvalidObjectResponse(Hash),
    #[error("Invalid object response type for request")]
    InvalidObjectResponseType,
    #[error("Error while receiving blocker response in boost sync mode: {}", _0)]
    BoostSyncModeBlockerResponseError(#[from] RecvError),
    #[error("Error while waiting on blocker in boost sync mode")]
    BoostSyncModeBlockerError,
    #[error("Boost sync mode failed: {}", _0)]
    BoostSyncModeFailed(Box<P2pError>),
    #[error("Expected a block type got {0}")]
    ExpectedBlock(OwnedObjectResponse),
    #[error("Expected a transaction type got {0}")]
    ExpectedTransaction(OwnedObjectResponse),
    #[error("Peer sent us a peerlist faster than protocol rules, expected to wait {} seconds more", _0)]
    PeerInvalidPeerListCountdown(u64),
    #[error("Peer sent us a ping packet faster than protocol rules")]
    PeerInvalidPingCoutdown,
    #[error(transparent)]
    BlockchainError(#[from] Box<BlockchainError>),
    #[error("Invalid content in peerlist shared")]
    InvalidPeerlist,
    #[error("Invalid bootstrap chain step, expected {:?}, got {:?}", _0, _1)]
    InvalidBootstrapStep(StepKind, StepKind),
    #[error("Error while serde JSON: {}", _0)]
    JsonError(#[from] serde_json::Error),
    #[error(transparent)]
    SemaphoreAcquireError(#[from] AcquireError),
    #[error(transparent)]
    EncryptionError(#[from] EncryptionError),
    #[error(transparent)]
    Any(#[from] Error)
}

impl From<BlockchainError> for P2pError {
    fn from(err: BlockchainError) -> Self {
        Self::BlockchainError(Box::new(err))
    }
}


impl<T> From<PoisonError<T>> for P2pError {
    fn from(err: PoisonError<T>) -> Self {
        Self::PoisonError(format!("{}", err))
    }
}

impl<T> From<SendError<T>> for P2pError {
    fn from(err: SendError<T>) -> Self {
        Self::SendError(format!("{}", err))
    }
}

impl<T> From<TSendError<T>> for P2pError {
    fn from(err: TSendError<T>) -> Self {
        Self::SendError(format!("{}", err))
    }
}