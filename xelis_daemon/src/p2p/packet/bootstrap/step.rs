use std::borrow::Cow;
use indexmap::{IndexMap, IndexSet};
use log::debug;
use xelis_common::{
    account::{AccountSummary, Balance, Nonce},
    asset::AssetData,
    block::TopoHeight,
    contract::{ContractModule, EventCallbackRegistration},
    crypto::{
        Hash,
        PublicKey
    },
    serializer::{
        DecodeError,
        Error as SerializationError,
        Readable,
        Reader,
        ReaderError,
        Serializer,
        Writable,
        Writer,
    },
    transaction::MultiSigPayload,
    versioned::State
};
use xelis_vm::ValueCell;
use crate::{
    config::{CHAIN_SYNC_REQUEST_MAX_BLOCKS, PRUNE_SAFETY_LIMIT},
    p2p::packet::{
        bootstrap::{types::ScheduledExecutionMetadata, BlockMetadata},
        chain::{BlockId, CommonPoint}
    }
};

// this file implements the protocol for the fast sync (bootstrapped chain)
// You will have to request through StepRequest::FetchAssets all the registered assets
// based on the size of the chain, you can have pagination or not.
// With the set of assets, you can retrieve all registered keys for it and then its balances
// Nonces need to be retrieve only one time because its common for all assets.
// The protocol is based on
// how many items we can answer per request

pub const MAX_ITEMS_PER_PAGE: usize = 1024; // 1k items per page

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum StepKind {
    ChainInfo,
    Assets,
    Keys,
    KeyBalances,
    Accounts,
    MultiSigs,
    Contracts,
    BlocksMetadata
}

impl StepKind {
    pub fn next(&self) -> Option<Self> {
        Some(match self {
            Self::ChainInfo => Self::Assets,
            Self::Assets => Self::Keys,
            Self::Keys => Self::KeyBalances,
            Self::KeyBalances => Self::Accounts,
            Self::Accounts => Self::MultiSigs,
            Self::MultiSigs => Self::Contracts,
            Self::Contracts => Self::BlocksMetadata,
            Self::BlocksMetadata => return None
        })
    }
}

#[derive(Debug)]
pub enum StepRequest<'a> {
    // Request chain info (top topoheight, top height, top hash)
    ChainInfo(IndexSet<BlockId>),
    // Min topoheight, Max topoheight, Pagination
    Assets(TopoHeight, TopoHeight, Option<u64>),
    // stable topoheight, assets (grouped by 1024) Pagination
    AssetsSupply(TopoHeight, Cow<'a, IndexSet<Hash>>),
    // Min topoheight, Max topoheight, pagination
    Keys(TopoHeight, TopoHeight, Option<u64>),
    // Request the assets for a public key
    // Can request up to 1024 keys per page
    // Key, min topoheight, max topoheight, pagination
    KeyBalances(Cow<'a, PublicKey>, TopoHeight, TopoHeight, Option<u64>),
    // Request the spendable balances of a public key
    // Can request up to 1024 keys per page
    // Key, Asset, min topoheight, max topoheight (exclusive range)
    SpendableBalances(Cow<'a, PublicKey>, Cow<'a, Hash>, TopoHeight, TopoHeight),
    // Request the nonces of a list of public key
    // min TopoHeight, max Topoheight, List of public keys
    Accounts(TopoHeight, TopoHeight, Cow<'a, IndexSet<PublicKey>>),
    // Min topoheight, Max topoheight, pagination
    Contracts(TopoHeight, TopoHeight, Option<u64>),
    // Request the contract module and its metadata
    // min TopoHeight, max Topoheight, Hash of the contract
    ContractModule(TopoHeight, TopoHeight, Cow<'a, Hash>),
    // Request the contract balances
    // Hash of the contract, topoheight, page
    ContractBalances(Cow<'a, Hash>, TopoHeight, Option<u64>),
    // Request the contract stores
    // Hash of the contract, topoheight, skip count (how many entries to skip)
    ContractStores(Cow<'a, Hash>, TopoHeight, u64),
    // Min topoheight, Max topoheight, pagination
    ContractsExecutions(TopoHeight, TopoHeight, Option<u64>),
    // Request the contracts events registered for a given contract
    ContractsEvents(Cow<'a, Hash>, TopoHeight, TopoHeight, Option<u64>),
    // Request blocks metadata starting topoheight
    BlocksMetadata(TopoHeight)
}

impl<'a> StepRequest<'a> {
    pub fn kind(&self) -> StepKind {
        match self {
            Self::ChainInfo(_) => StepKind::ChainInfo,
            Self::Assets(_, _, _) => StepKind::Assets,
            Self::AssetsSupply(_, _) => StepKind::Assets,
            Self::Keys(_, _, _) => StepKind::Keys,
            Self::KeyBalances(_, _, _, _) => StepKind::KeyBalances,
            Self::SpendableBalances(_, _, _, _) => StepKind::KeyBalances,
            Self::Accounts(_, _, _) => StepKind::Accounts,
            Self::Contracts(_, _, _) => StepKind::Contracts,
            Self::ContractModule(_, _, _) => StepKind::Contracts,
            Self::ContractBalances(_, _, _) => StepKind::Contracts,
            Self::ContractStores(_, _, _) => StepKind::Contracts,
            Self::ContractsExecutions(_, _, _) => StepKind::Contracts,
            Self::ContractsEvents(_, _, _, _) => StepKind::Contracts,
            Self::BlocksMetadata(_) => StepKind::BlocksMetadata
        }
    }

    pub fn get_requested_topoheight(&self) -> Option<u64> {
        Some(*match self {
            Self::ChainInfo(_) => return None,
            Self::Assets(_, topo, _) => topo,
            Self::AssetsSupply(topo, _) => topo,
            Self::Keys(_, topo, _) => topo,
            Self::KeyBalances(_, _, topo, _) => topo,
            Self::SpendableBalances(_, _, _, topo) => topo,
            Self::Accounts(_, topo, _) => topo,
            Self::Contracts(_, topo, _) => topo,
            Self::ContractModule(_, topo, _) => topo,
            Self::ContractBalances(_, topo, _) => topo,
            Self::ContractStores(_, topo, _) => topo,
            Self::ContractsExecutions(_, topo, _) => topo,
            Self::ContractsEvents(_, _, topo, _) => topo,
            Self::BlocksMetadata(topo) => topo,
        })
    }
}

impl Serializer for StepRequest<'_> {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(match u8::read(reader)? {
                0 => {
                    let len = u8::read(reader)?;
                    if len == 0 || len > CHAIN_SYNC_REQUEST_MAX_BLOCKS as u8 {
                        debug!("Invalid chain info request length: {}", len);
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap chain info request contains {len} block IDs; expected 1..={CHAIN_SYNC_REQUEST_MAX_BLOCKS}")))
                    }

                    let mut blocks = IndexSet::with_capacity(len as usize);
                    for _ in 0..len {
                        if !blocks.insert(BlockId::read(reader)?) {
                            debug!("Duplicated block id for chain info request");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("duplicate block ID in bootstrap chain info request"))
                        }
                    }
                    Self::ChainInfo(blocks)
                }
                1 => {
                    let min_topoheight = u64::read(reader)?;
                    let topoheight = u64::read(reader)?;
                    if min_topoheight > topoheight {
                        debug!("Invalid min topoheight in Step Request");
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap assets request minimum topoheight {min_topoheight} exceeds maximum {topoheight}")))
                    }

                    let page = Option::read(reader)?;
                    if let Some(page_number) = &page {
                        if *page_number == 0 {
                            debug!("Invalid page number (0) in Step Request");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("bootstrap assets request page number must be nonzero when present"))
                        }
                    }
                    Self::Assets(min_topoheight, topoheight, page)
                },
                2 => {
                    let topoheight = u64::read(reader)?;
                    let len = u16::read(reader)?;
                    if len == 0 || len > MAX_ITEMS_PER_PAGE as u16 {
                        debug!("Invalid assets request length: {}", len);
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap asset supply request contains {len} assets; expected 1..={MAX_ITEMS_PER_PAGE}")))
                    }

                    let mut assets = IndexSet::with_capacity(len as usize);
                    for _ in 0..len {
                        if !assets.insert(Hash::read(reader)?) {
                            debug!("Duplicated asset id for assets supply request");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("duplicate asset hash in bootstrap asset supply request"))
                        }
                    }

                    Self::AssetsSupply(topoheight, Cow::Owned(assets))
                },
                3 => {
                    let min = u64::read(reader)?;
                    let max = u64::read(reader)?;
                    if min > max {
                        debug!("Invalid min topoheight in Step Request");
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap keys request minimum topoheight {min} exceeds maximum {max}")))
                    }

                    let page = Option::read(reader)?;
                    if let Some(page_number) = &page {
                        if *page_number == 0 {
                            debug!("Invalid page number (0) in Step Request");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("bootstrap keys request page number must be nonzero when present"))
                        }
                    }
                    Self::Keys(min, max, page)
                },
                4 => {
                    let key = Cow::read(reader)?;
                    let min = u64::read(reader)?;
                    let max = u64::read(reader)?;
                    if min > max {
                        debug!("Invalid min topoheight in Step Request");
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap key balances request minimum topoheight {min} exceeds maximum {max}")))
                    }

                    let page = Option::read(reader)?;
                    if let Some(page_number) = &page {
                        if *page_number == 0 {
                            debug!("Invalid page number (0) in Step Request");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("bootstrap key balances request page number must be nonzero when present"))
                        }
                    }
                    Self::KeyBalances(key, min, max, page)
                },
                5 => {
                    let key = Cow::read(reader)?;
                    let asset = Cow::read(reader)?;
                    let min = u64::read(reader)?;
                    let max = u64::read(reader)?;
                    if min > max {
                        debug!("Invalid min topoheight in Step Request");
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap spendable balances request minimum topoheight {min} exceeds maximum {max}")))
                    }

                    Self::SpendableBalances(key, asset, min, max)
                },
                6 => {
                    let min = u64::read(reader)?;
                    let max = u64::read(reader)?;
                    let len = u16::read(reader)?;
                    if len > MAX_ITEMS_PER_PAGE as u16 {
                        debug!("Invalid accounts request length: {}", len);
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap accounts request contains {len} public keys; maximum is {MAX_ITEMS_PER_PAGE}")))
                    }

                    let mut keys = IndexSet::with_capacity(len as usize);
                    for _ in 0..len {
                        if !keys.insert(PublicKey::read(reader)?) {
                            debug!("Duplicated public key for accounts request");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("duplicate public key in bootstrap accounts request"))
                        }
                    }

                    Self::Accounts(min, max, Cow::Owned(keys))
                },
                7 => {
                    let min = u64::read(reader)?;
                    let max = u64::read(reader)?;
                    let page = Option::read(reader)?;
                    if let Some(page_number) = &page {
                        if *page_number == 0 {
                            debug!("Invalid page number (0) in Step Request");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("bootstrap contracts request page number must be nonzero when present"))
                        }
                    }
                    Self::Contracts(min, max, page)
                },
                8 => {
                    let min = u64::read(reader)?;
                    let max = u64::read(reader)?;
                    let hash = Cow::read(reader)?;
                    Self::ContractModule(min, max, hash)
                },
                9 => {
                    let hash = Cow::read(reader)?;
                    let topoheight = u64::read(reader)?;
                    let page = Option::read(reader)?;
                    Self::ContractBalances(hash, topoheight, page)
                },
                10 => {
                    let hash = Cow::read(reader)?;
                    let topoheight = u64::read(reader)?;
                    let skip = u64::read(reader)?;
                    Self::ContractStores(hash, topoheight, skip)
                },
                11 => {
                    let min = u64::read(reader)?;
                    let max = u64::read(reader)?;

                    if min > max {
                        debug!("Invalid min topoheight in Step Request");
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap contract executions request minimum topoheight {min} exceeds maximum {max}")))
                    }

                    let page = Option::read(reader)?;
                    if let Some(page_number) = &page {
                        if *page_number == 0 {
                            debug!("Invalid page number (0) in Step Request");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("bootstrap contract executions request page number must be nonzero when present"))
                        }
                    }
                    Self::ContractsExecutions(min, max, page)
                },
                12 => {
                    let hash = Cow::read(reader)?;
                    let min_topoheight = u64::read(reader)?;
                    let max_topoheight = u64::read(reader)?;

                    let page = Option::read(reader)?;
                    if let Some(page_number) = &page {
                        if *page_number == 0 {
                            debug!("Invalid page number (0) in Step Request");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("bootstrap contract events request page number must be nonzero when present"))
                        }
                    }

                    Self::ContractsEvents(hash, min_topoheight, max_topoheight, page)
                },
                13 => {
                    Self::BlocksMetadata(u64::read(reader)?)
                },
                id => {
                    debug!("Received invalid value for StepResponse: {}", id);
                    return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("unknown bootstrap request step ID {id}")))
                }
            })
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            match self {
                Self::ChainInfo(blocks) => {
                    0u8.write(writer)?;
                    (blocks.len() as u8).write(writer)?;
                    for block_id in blocks {
                        block_id.write(writer)?;
                    }
                    Ok(())
                },
                Self::Assets(min, max, page) => {
                    1u8.write(writer)?;
                    min.write(writer)?;
                    max.write(writer)?;
                    page.write(writer)
                },
                Self::AssetsSupply(topoheight, assets) => {
                    2u8.write(writer)?;
                    topoheight.write(writer)?;
                    assets.write(writer)
                },
                Self::Keys(min, max, page) => {
                    3u8.write(writer)?;
                    min.write(writer)?;
                    max.write(writer)?;
                    page.write(writer)
                },
                Self::KeyBalances(key, min, max, page) => {
                    4u8.write(writer)?;
                    key.write(writer)?;
                    min.write(writer)?;
                    max.write(writer)?;
                    page.write(writer)
                },
                Self::SpendableBalances(key, asset, min, max) => {
                    5u8.write(writer)?;
                    key.write(writer)?;
                    asset.write(writer)?;
                    min.write(writer)?;
                    max.write(writer)
                },
                Self::Accounts(min, max, keys) => {
                    6u8.write(writer)?;
                    min.write(writer)?;
                    max.write(writer)?;
                    keys.write(writer)
                },
                Self::Contracts(min, max, pagination) => {
                    7u8.write(writer)?;
                    min.write(writer)?;
                    max.write(writer)?;
                    pagination.write(writer)
                },
                Self::ContractModule(min, max, hash) => {
                    8u8.write(writer)?;
                    min.write(writer)?;
                    max.write(writer)?;
                    hash.write(writer)
                },
                Self::ContractBalances(hash, topoheight, page) => {
                    9u8.write(writer)?;
                    hash.write(writer)?;
                    topoheight.write(writer)?;
                    page.write(writer)
                },
                Self::ContractStores(hash, topoheight, skip) => {
                    10u8.write(writer)?;
                    hash.write(writer)?;
                    topoheight.write(writer)?;
                    skip.write(writer)
                },
                Self::ContractsExecutions(min, max, page) => {
                    11u8.write(writer)?;
                    min.write(writer)?;
                    max.write(writer)?;
                    page.write(writer)
                },
                Self::ContractsEvents(hash, min_topoheight, max_topoheight, page) => {
                    12u8.write(writer)?;
                    hash.write(writer)?;
                    min_topoheight.write(writer)?;
                    max_topoheight.write(writer)?;
                    page.write(writer)
                },
                Self::BlocksMetadata(topoheight) => {
                    13u8.write(writer)?;
                    topoheight.write(writer)
                },
            }
        })
    }

    fn size(&self) -> usize {
        let size = match self {
            Self::ChainInfo(blocks) => 1 + blocks.iter().map(|b| b.size()).sum::<usize>(),
            Self::Assets(min, max, page) => min.size() + max.size() + page.size(),
            Self::AssetsSupply(topoheight, assets) => topoheight.size() + assets.size(),
            Self::Keys(min, max, page) => min.size() + max.size() + page.size(),
            Self::KeyBalances(key, min, max, page) => key.size() + min.size() + max.size() + page.size(),
            Self::SpendableBalances(key, asset, min, max) => key.size() + asset.size() + min.size() + max.size(),
            Self::Accounts(min, max, nonces) => min.size() + max.size() + nonces.size(),
            Self::Contracts(min, max, pagination) => min.size() + max.size() + pagination.size(),
            Self::ContractModule(min, max, hash) => min.size() + max.size() + hash.size(),
            Self::ContractBalances(hash, topoheight, page) => hash.size() + topoheight.size() + page.size(),
            Self::ContractStores(hash, topoheight, skip) => hash.size() + topoheight.size() + skip.size(),
            Self::ContractsExecutions(min, max, page) => min.size() + max.size() + page.size(),
            Self::ContractsEvents(hash, min_topoheight, max_topoheight, page) => hash.size() + min_topoheight.size() + max_topoheight.size() + page.size(),
            Self::BlocksMetadata(topoheight) => topoheight.size()
        };
        // 1 for the id
        size + 1
    }
}

#[derive(Debug)]
pub enum StepResponse {
    // common point, topoheight of stable hash, stable height, stable hash
    ChainInfo(Option<CommonPoint>, u64, u64, Hash),
    // Set of assets, pagination
    Assets(IndexMap<Hash, AssetData>, Option<u64>),
    // List of circulating supply
    AssetsSupply(Vec<Option<u64>>),
    // Set of keys, pagination
    Keys(IndexSet<PublicKey>, Option<u64>),
    // All assets for requested key, pagination
    KeyBalances(IndexMap<Hash, Option<AccountSummary>>, Option<u64>),
    // This is for per key/account only
    // TopoHeight is for the next max exclusive topoheight (if none, no more data)
    SpendableBalances(Vec<Balance>, Option<TopoHeight>),
    // Nonces and multisig states for requested accounts
    // It is optional in case the peer send us some keys
    // that got deleted because he forked
    Accounts(Vec<(State<Nonce>, State<MultiSigPayload>)>),
    // Contracts hashes with pagination
    Contracts(IndexSet<Hash>, Option<u64>),
    // Contract module
    // This is one by one due to the potential max size
    ContractModule(State<ContractModule>),
    // Contract assets
    // all assets detected, pagination
    ContractBalances(IndexMap<Hash, u64>, Option<u64>),
    // Contract stores
    // entries, next skip count (0 if no more data)
    ContractStores(IndexMap<ValueCell, Option<ValueCell>>, u64),
    // Contract executions
    ContractsExecutions(IndexSet<ScheduledExecutionMetadata>, Option<u64>),
    // Contracts events registered for the requested
    // event id, listener contract and max topoheight (for pagination)
    ContractsEvents(IndexMap<(Hash, u64), Option<EventCallbackRegistration>>, Option<u64>),
    // top blocks metadata
    BlocksMetadata(IndexSet<BlockMetadata>),
}

impl StepResponse {
    pub fn kind(&self) -> StepKind {
        match self {
            Self::ChainInfo(_, _, _, _) => StepKind::ChainInfo,
            Self::Assets(_, _) => StepKind::Assets,
            Self::AssetsSupply(_) => StepKind::Assets,
            Self::Keys(_, _) => StepKind::Keys,
            Self::KeyBalances(_, _) => StepKind::KeyBalances,
            Self::SpendableBalances(_, _) => StepKind::KeyBalances,
            Self::Accounts(_) => StepKind::Accounts,
            Self::Contracts(_, _) => StepKind::Contracts,
            Self::ContractModule(_) => StepKind::Contracts,
            Self::ContractBalances(_, _) => StepKind::Contracts,
            Self::ContractStores(_, _) => StepKind::Contracts,
            Self::ContractsExecutions(_, _) => StepKind::Contracts,
            Self::ContractsEvents(_, _) => StepKind::Contracts,
            Self::BlocksMetadata(_) => StepKind::BlocksMetadata
        }
    }
}

impl Serializer for StepResponse {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(match u8::read(reader)? {
                0 => {
                    let common_point = Option::read(reader)?;
                    let topoheight = u64::read(reader)?;
                    let stable_height = u64::read(reader)?;
                    let hash = Hash::read(reader)?;

                    Self::ChainInfo(common_point, topoheight, stable_height, hash)
                },
                1 => {
                    let len = u16::read(reader)?;
                    if len > MAX_ITEMS_PER_PAGE as u16 {
                        debug!("Invalid assets response length: {}", len);
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap assets response contains {len} assets; maximum is {MAX_ITEMS_PER_PAGE}")))
                    }

                    let mut assets = IndexMap::with_capacity(len as usize);
                    for _ in 0..len {
                        let key = Hash::read(reader)?;
                        let value = AssetData::read(reader)?;
                        if assets.insert(key, value).is_some() {
                            debug!("Duplicated asset key in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("duplicate asset hash in bootstrap assets response"))
                        }
                    }

                    let page = Option::read(reader)?;
                    if let Some(page_number) = &page {
                        if *page_number == 0 {
                            debug!("Invalid page number (0) in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("bootstrap assets response page number must be nonzero when present"))
                        }
                    }
                    Self::Assets(assets, page)
                },
                2 => {
                    let len = u16::read(reader)?;
                    if len > MAX_ITEMS_PER_PAGE as u16 {
                        debug!("Invalid assets supply response length: {}", len);
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap asset supply response contains {len} values; maximum is {MAX_ITEMS_PER_PAGE}")))
                    }

                    let mut values = Vec::with_capacity(len as usize);
                    for _ in 0..len {
                        values.push(Option::read(reader)?);
                    }

                    Self::AssetsSupply(values)
                },
                3 => {
                    let len = u16::read(reader)?;
                    if len > MAX_ITEMS_PER_PAGE as u16 {
                        debug!("Invalid keys response length: {}", len);
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap keys response contains {len} public keys; maximum is {MAX_ITEMS_PER_PAGE}")))
                    }
                    let mut keys = IndexSet::with_capacity(len as usize);
                    for _ in 0..len {
                        if !keys.insert(PublicKey::read(reader)?) {
                            debug!("Duplicated public key in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("duplicate public key in bootstrap keys response"))
                        }
                    }

                    let page = Option::read(reader)?;
                    if let Some(page_number) = &page {
                        if *page_number == 0 {
                            debug!("Invalid page number (0) in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("bootstrap keys response page number must be nonzero when present"))
                        }
                    }
                    Self::Keys(keys, page)
                },
                4 => {
                    let len = u16::read(reader)?;
                    if len > MAX_ITEMS_PER_PAGE as u16 {
                        debug!("Invalid key balances response length: {}", len);
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap key balances response contains {len} assets; maximum is {MAX_ITEMS_PER_PAGE}")))
                    }
                    let mut keys = IndexMap::with_capacity(len as usize);
                    for _ in 0..len {
                        let key = Hash::read(reader)?;
                        let value = Option::read(reader)?;
                        if keys.insert(key, value).is_some() {
                            debug!("Duplicated key in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("duplicate asset hash in bootstrap key balances response"))
                        }
                    }

                    let page = Option::read(reader)?;
                    if let Some(page_number) = &page {
                        if *page_number == 0 {
                            debug!("Invalid page number (0) in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("bootstrap key balances response page number must be nonzero when present"))
                        }
                    }
                    Self::KeyBalances(keys, page)
                },
                5 => {
                    let len = u16::read(reader)?;
                    if len > MAX_ITEMS_PER_PAGE as u16 {
                        debug!("Invalid spendable balances response length: {}", len);
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap spendable balances response contains {len} balances; maximum is {MAX_ITEMS_PER_PAGE}")))
                    }

                    let mut balances = Vec::with_capacity(len as usize);
                    for _ in 0..len {
                        let balance = Balance::read(reader)?;
                        balances.push(balance);
                    }

                    Self::SpendableBalances(balances, Option::read(reader)?)
                },
                6 => {
                    let len = u16::read(reader)?;
                    if len > MAX_ITEMS_PER_PAGE as u16 {
                        debug!("Invalid accounts response length: {}", len);
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap accounts response contains {len} accounts; maximum is {MAX_ITEMS_PER_PAGE}")))
                    }
                    let mut accounts = Vec::with_capacity(len as usize);
                    for _ in 0..len {
                        let nonce = State::<Nonce>::read(reader)?;
                        let multisig = State::<MultiSigPayload>::read(reader)?;
                        accounts.push((nonce, multisig));
                    }

                    Self::Accounts(accounts)
                },
                7 => {
                    let len = u16::read(reader)?;
                    if len > MAX_ITEMS_PER_PAGE as u16 {
                        debug!("Invalid contracts response length: {}", len);
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap contracts response contains {len} contract hashes; maximum is {MAX_ITEMS_PER_PAGE}")))
                    }

                    let mut contracts = IndexSet::with_capacity(len as usize);
                    for _ in 0..len {
                        if !contracts.insert(Hash::read(reader)?) {
                            debug!("Duplicated contract hash in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("duplicate contract hash in bootstrap contracts response"))
                        }
                    }

                    let page = Option::read(reader)?;
                    if let Some(page_number) = &page {
                        if *page_number == 0 {
                            debug!("Invalid page number (0) in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("bootstrap contracts response page number must be nonzero when present"))
                        }
                    }
                    Self::Contracts(contracts, page)
                },
                8 => Self::ContractModule(State::read(reader)?),
                9 => {
                    let len = u16::read(reader)?;
                    if len > MAX_ITEMS_PER_PAGE as u16 {
                        debug!("Invalid contracts assets response length: {}", len);
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap contract balances response contains {len} assets; maximum is {MAX_ITEMS_PER_PAGE}")))
                    }

                    let mut assets = IndexMap::with_capacity(len as usize);
                    for _ in 0..len {
                        let asset = Hash::read(reader)?;
                        let value = u64::read(reader)?;
                        if assets.insert(asset, value).is_some() {
                            debug!("Duplicated contract asset in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("duplicate asset hash in bootstrap contract balances response"))
                        }
                    }

                    let page = Option::read(reader)?;
                    if let Some(page_number) = &page {
                        if *page_number == 0 {
                            debug!("Invalid page number (0) in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("bootstrap contract balances response page number must be nonzero when present"))
                        }
                    }

                    Self::ContractBalances(assets, page)
                },
                10 => {
                    let len = u16::read(reader)?;
                    // No maximum limit validation since we're using dynamic sizing
                    let mut entries = IndexMap::with_capacity(len as usize);
                    for _ in 0..len {
                        let key = ValueCell::read(reader)?;
                        let value = Option::read(reader)?;
                        if entries.insert(key, value).is_some() {
                            debug!("Duplicated contract store in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("duplicate storage key in bootstrap contract stores response"))
                        }
                    }

                    let next_skip = u64::read(reader)?;

                    Self::ContractStores(entries, next_skip)
                },
                11 => {
                    let len = u16::read(reader)?;
                    if len > MAX_ITEMS_PER_PAGE as u16 {
                        debug!("Invalid contracts executions response length: {}", len);
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap contract executions response contains {len} executions; maximum is {MAX_ITEMS_PER_PAGE}")))
                    }

                    let mut executions = IndexSet::with_capacity(len as usize);
                    for _ in 0..len {
                        let metadata = ScheduledExecutionMetadata::read(reader)?;
                        if !executions.insert(metadata) {
                            debug!("Duplicated scheduled execution metadata in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("duplicate scheduled execution metadata in bootstrap contract executions response"))
                        }
                    }

                    let page = Option::read(reader)?;
                    if let Some(page_number) = &page {
                        if *page_number == 0 {
                            debug!("Invalid page number (0) in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("bootstrap contract executions response page number must be nonzero when present"))
                        }
                    }

                    Self::ContractsExecutions(executions, page)
                }
                12 => {
                    let len = u16::read(reader)?;
                    if len > MAX_ITEMS_PER_PAGE as u16 {
                        debug!("Invalid contracts events response length: {}", len);
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap contract events response contains {len} events; maximum is {MAX_ITEMS_PER_PAGE}")))
                    }

                    let mut events = IndexMap::with_capacity(len as usize);
                    for _ in 0..len {
                        let listener_contract = Hash::read(reader)?;
                        let event_id = u64::read(reader)?;

                        let event = Option::read(reader)?;
                        if events.insert((listener_contract, event_id), event).is_some() {
                            debug!("Duplicated contract event in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("duplicate contract and event ID pair in bootstrap contract events response"))
                        }
                    }

                    let page = Option::read(reader)?;
                    if let Some(page_number) = &page {
                        if *page_number == 0 {
                            debug!("Invalid page number (0) in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("bootstrap contract events response page number must be nonzero when present"))
                        }
                    }

                    Self::ContractsEvents(events, page)
                },
                13 => {
                    let len = u16::read(reader)?;
                    if len > PRUNE_SAFETY_LIMIT as u16 + 1 {
                        debug!("Invalid blocks metadata response length: {}", len);
                        return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("bootstrap block metadata response contains {len} blocks; maximum is {}", PRUNE_SAFETY_LIMIT as u16 + 1)))
                    }

                    let mut blocks = IndexSet::with_capacity(len as usize);
                    for _ in 0..len {
                        let metadata = BlockMetadata::read(reader)?;
                        if !blocks.insert(metadata) {
                            debug!("Duplicated block metadata in Step Response");
                            return Err(SerializationError::new(DecodeError::InvalidValue).context("duplicate block metadata in bootstrap block metadata response"))
                        }
                    }

                    Self::BlocksMetadata(blocks)
                },
                id => {
                    debug!("Received invalid value for StepResponse: {}", id);
                    return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("unknown bootstrap response step ID {id}")))
                }
            })
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            match self {
                Self::ChainInfo(common_point, topoheight, stable_height, hash) => {
                    0u8.write(writer)?;
                    common_point.write(writer)?;
                    topoheight.write(writer)?;
                    stable_height.write(writer)?;
                    hash.write(writer)
                },
                Self::Assets(assets, page) => {
                    1u8.write(writer)?;
                    assets.write(writer)?;
                    page.write(writer)
                },
                Self::AssetsSupply(supply) => {
                    2u8.write(writer)?;
                    supply.write(writer)
                }
                Self::Keys(keys, page) => {
                    3u8.write(writer)?;
                    keys.write(writer)?;
                    page.write(writer)
                },
                Self::KeyBalances(keys, page) => {
                    4u8.write(writer)?;
                    keys.write(writer)?;
                    page.write(writer)
                },
                Self::SpendableBalances(balances, page) => {
                    5u8.write(writer)?;
                    balances.write(writer)?;
                    page.write(writer)
                },
                Self::Accounts(nonces) => {
                    6u8.write(writer)?;
                    nonces.write(writer)
                },
                Self::Contracts(contracts, page) => {
                    7u8.write(writer)?;
                    contracts.write(writer)?;
                    page.write(writer)
                },
                Self::ContractModule(metadata) => {
                    8u8.write(writer)?;
                    metadata.write(writer)
                },
                Self::ContractBalances(assets, page) => {
                    9u8.write(writer)?;
                    assets.write(writer)?;
                    page.write(writer)
                },
                Self::ContractStores(entries, next_skip) => {
                    10u8.write(writer)?;
                    entries.write(writer)?;
                    next_skip.write(writer)
                },
                Self::ContractsExecutions(executions, page) => {
                    11u8.write(writer)?;
                    executions.write(writer)?;
                    page.write(writer)
                },
                Self::ContractsEvents(events, page) => {
                    12u8.write(writer)?;
                    events.write(writer)?;
                    page.write(writer)
                },
                Self::BlocksMetadata(blocks) => {
                    13u8.write(writer)?;
                    blocks.write(writer)
                }
            }
        })
    }

    fn size(&self) -> usize {
        let size = match self {
            Self::ChainInfo(common_point, topoheight, stable_height, hash) => common_point.size() + topoheight.size() + stable_height.size() + hash.size(),
            Self::Assets(assets, page) => assets.size() + page.size(),
            Self::AssetsSupply(supply) => supply.len(),
            Self::Keys(keys, page) => keys.size() + page.size(),
            Self::KeyBalances(keys, page) => keys.size() + page.size(),
            Self::SpendableBalances(balances, page) => balances.size() + page.size(),
            Self::Accounts(nonces) => nonces.size(),
            Self::Contracts(contracts, page) => contracts.size() + page.size(),
            Self::ContractModule(metadata) => metadata.size(),
            Self::ContractBalances(assets, page) => assets.size() + page.size(),
            Self::ContractStores(entries, next_skip) => entries.size() + next_skip.size(),
            Self::ContractsExecutions(executions, page) => executions.size() + page.size(),
            Self::ContractsEvents(events, page) => events.size() + page.size(),
            Self::BlocksMetadata(blocks) => blocks.size()
        };
        // 1 for the id
        size + 1
    }
}
