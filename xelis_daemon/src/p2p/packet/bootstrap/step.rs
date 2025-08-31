use std::borrow::Cow;
use indexmap::{IndexMap, IndexSet};
use log::debug;
use xelis_common::{
    account::{AccountSummary, Balance, Nonce},
    asset::AssetData,
    block::TopoHeight,
    contract::{MAX_KEY_SIZE, MAX_VALUE_SIZE},
    crypto::{
        Hash,
        PublicKey
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    },
    static_assert,
    transaction::MultiSigPayload,
    versioned_type::State
};
use xelis_vm::{Module, ValueCell};
use crate::{
    config::{CHAIN_SYNC_REQUEST_MAX_BLOCKS, PEER_MAX_PACKET_SIZE, PRUNE_SAFETY_LIMIT},
    p2p::packet::{
        bootstrap::BlockMetadata,
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

// Contract Stores can be a big packet, we must ensure that we are below the max packet size
static_assert!(
    MAX_ITEMS_PER_PAGE * (MAX_KEY_SIZE + MAX_VALUE_SIZE) + 32 <= PEER_MAX_PACKET_SIZE as usize,
    "Contract Stores packet must be below max packet size"
);

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
    // Hash of the contract, topoheight, page
    ContractStores(Cow<'a, Hash>, TopoHeight, Option<u64>),
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
            Self::BlocksMetadata(_) => StepKind::BlocksMetadata
        }
    }

    pub fn get_requested_topoheight(&self) -> Option<u64> {
        Some(*match self {
            Self::Assets(_, topo, _) => topo,
            Self::AssetsSupply(topo, _) => topo,
            Self::Keys(_, topo, _) => topo,
            Self::KeyBalances(_, _, topo, _) => topo,
            Self::SpendableBalances(_, _, _, topo) => topo,
            Self::Accounts(_, topo, _) => topo,
            Self::Contracts(_, topo, _) => topo,
            Self::ContractModule(_, topo, _) => topo,
            Self::ContractBalances(_, topo, _) => topo,
            Self::BlocksMetadata(topo) => topo,
            _ => return None,
        })
    }
}

impl Serializer for StepRequest<'_> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => {
                let len = reader.read_u8()?;
                if len == 0 || len > CHAIN_SYNC_REQUEST_MAX_BLOCKS as u8 {
                    debug!("Invalid chain info request length: {}", len);
                    return Err(ReaderError::InvalidValue)
                }

                let mut blocks = IndexSet::with_capacity(len as usize);
                for _ in 0..len {
                    if !blocks.insert(BlockId::read(reader)?) {
                        debug!("Duplicated block id for chain info request");
                        return Err(ReaderError::InvalidValue)
                    }
                }
                Self::ChainInfo(blocks)
            }
            1 => {
                let min_topoheight = reader.read_u64()?;
                let topoheight = reader.read_u64()?;
                if min_topoheight > topoheight {
                    debug!("Invalid min topoheight in Step Request");
                    return Err(ReaderError::InvalidValue)
                }

                let page = Option::read(reader)?;
                if let Some(page_number) = &page {
                    if *page_number == 0 {
                        debug!("Invalid page number (0) in Step Request");
                        return Err(ReaderError::InvalidValue)
                    }
                }
                Self::Assets(min_topoheight, topoheight, page)
            },
            2 => {
                let topoheight = reader.read_u64()?;
                let len = reader.read_u16()?;
                if len == 0 || len > MAX_ITEMS_PER_PAGE as u16 {
                    debug!("Invalid assets request length: {}", len);
                    return Err(ReaderError::InvalidValue)
                }

                let mut assets = IndexSet::with_capacity(len as usize);
                for _ in 0..len {
                    if !assets.insert(Hash::read(reader)?) {
                        debug!("Duplicated asset id for assets supply request");
                        return Err(ReaderError::InvalidValue)
                    }
                }

                Self::AssetsSupply(topoheight, Cow::Owned(assets))
            },
            3 => {
                let min = reader.read_u64()?;
                let max = reader.read_u64()?;
                if min > max {
                    debug!("Invalid min topoheight in Step Request");
                    return Err(ReaderError::InvalidValue)
                }

                let page = Option::read(reader)?;
                if let Some(page_number) = &page {
                    if *page_number == 0 {
                        debug!("Invalid page number (0) in Step Request");
                        return Err(ReaderError::InvalidValue)
                    }
                }
                Self::Keys(min, max, page)
            },
            4 => {
                let key = Cow::read(reader)?;
                let min = reader.read_u64()?;
                let max = reader.read_u64()?;
                if min > max {
                    debug!("Invalid min topoheight in Step Request");
                    return Err(ReaderError::InvalidValue)
                }

                let page = Option::read(reader)?;
                if let Some(page_number) = &page {
                    if *page_number == 0 {
                        debug!("Invalid page number (0) in Step Request");
                        return Err(ReaderError::InvalidValue)
                    }
                }
                Self::KeyBalances(key, min, max, page)
            },
            5 => {
                let key = Cow::read(reader)?;
                let asset = Cow::read(reader)?;
                let min = reader.read_u64()?;
                let max = reader.read_u64()?;
                if min > max {
                    debug!("Invalid min topoheight in Step Request");
                    return Err(ReaderError::InvalidValue)
                }

                Self::SpendableBalances(key, asset, min, max)
            },
            6 => {
                let min = reader.read_u64()?;
                let max = reader.read_u64()?;
                let len = reader.read_u16()?;
                if len > MAX_ITEMS_PER_PAGE as u16 {
                    debug!("Invalid accounts request length: {}", len);
                    return Err(ReaderError::InvalidValue)
                }

                let mut keys = IndexSet::with_capacity(len as usize);
                for _ in 0..len {
                    if !keys.insert(PublicKey::read(reader)?) {
                        debug!("Duplicated public key for accounts request");
                        return Err(ReaderError::InvalidValue)
                    }
                }

                Self::Accounts(min, max, Cow::Owned(keys))
            },
            7 => {
                let min = reader.read_u64()?;
                let max = reader.read_u64()?;
                let page = Option::read(reader)?;
                if let Some(page_number) = &page {
                    if *page_number == 0 {
                        debug!("Invalid page number (0) in Step Request");
                        return Err(ReaderError::InvalidValue)
                    }
                }
                Self::Contracts(min, max, page)
            },
            8 => {
                let min = reader.read_u64()?;
                let max = reader.read_u64()?;
                let hash = Cow::read(reader)?;
                Self::ContractModule(min, max, hash)
            },
            9 => {
                let hash = Cow::read(reader)?;
                let topoheight = reader.read_u64()?;
                let page = Option::read(reader)?;
                Self::ContractBalances(hash, topoheight, page)
            },
            10 => {
                let hash = Cow::read(reader)?;
                let topoheight = reader.read_u64()?;
                let page = Option::read(reader)?;
                Self::ContractStores(hash, topoheight, page)
            },
            11 => {
                Self::BlocksMetadata(reader.read_u64()?)
            },
            id => {
                debug!("Received invalid value for StepResponse: {}", id);
                return Err(ReaderError::InvalidValue)
            }
        })
    }

    fn write(&self, writer: &mut Writer) {
        match self {
            Self::ChainInfo(blocks) => {
                writer.write_u8(0);
                writer.write_u8(blocks.len() as u8);
                for block_id in blocks {
                    block_id.write(writer);
                }
            },
            Self::Assets(min, max, page) => {
                writer.write_u8(1);
                writer.write_u64(min);
                writer.write_u64(max);
                page.write(writer);
            },
            Self::AssetsSupply(topoheight, assets) => {
                writer.write_u8(2);
                topoheight.write(writer);
                assets.write(writer);
            },
            Self::Keys(min, max, page) => {
                writer.write_u8(3);
                writer.write_u64(min);
                writer.write_u64(max);
                page.write(writer);
            },
            Self::KeyBalances(key, min, max, page) => {
                writer.write_u8(4);
                key.write(writer);
                writer.write_u64(min);
                writer.write_u64(max);
                page.write(writer);
            },
            Self::SpendableBalances(key, asset, min, max) => {
                writer.write_u8(5);
                key.write(writer);
                asset.write(writer);
                writer.write_u64(min);
                writer.write_u64(max);
            },
            Self::Accounts(min, max, keys) => {
                writer.write_u8(6);
                writer.write_u64(min);
                writer.write_u64(max);
                keys.write(writer);
            },
            Self::Contracts(min, max, pagination) => {
                writer.write_u8(7);
                writer.write_u64(min);
                writer.write_u64(max);
                pagination.write(writer);
            },
            Self::ContractModule(min, max, hash) => {
                writer.write_u8(8);
                writer.write_u64(min);
                writer.write_u64(max);
                hash.write(writer);
            },
            Self::ContractBalances(hash, topoheight, page) => {
                writer.write_u8(9);
                hash.write(writer);
                topoheight.write(writer);
                page.write(writer);
            },
            Self::ContractStores(hash, topoheight, page) => {
                writer.write_u8(10);
                hash.write(writer);
                topoheight.write(writer);
                page.write(writer);
            },
            Self::BlocksMetadata(topoheight) => {
                writer.write_u8(11);
                writer.write_u64(topoheight);
            },
        };
    }

    fn size(&self) -> usize {
        let size = match self {
            Self::ChainInfo(blocks) => 1 + blocks.size(),
            Self::Assets(min, max, page) => min.size() + max.size() + page.size(),
            Self::AssetsSupply(topoheight, assets) => topoheight.size() + assets.size(),
            Self::Keys(min, max, page) => min.size() + max.size() + page.size(),
            Self::KeyBalances(key, min, max, page) => key.size() + min.size() + max.size() + page.size(),
            Self::SpendableBalances(key, asset, min, max) => key.size() + asset.size() + min.size() + max.size(),
            Self::Accounts(min, max, nonces) => min.size() + max.size() + nonces.size(),
            Self::Contracts(min, max, pagination) => min.size() + max.size() + pagination.size(),
            Self::ContractModule(min, max, hash) => min.size() + max.size() + hash.size(),
            Self::ContractBalances(hash, topoheight, page) => hash.size() + topoheight.size() + page.size(),
            Self::ContractStores(hash, topoheight, page) => hash.size() + topoheight.size() + page.size(),
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
    ContractModule(State<Module>),
    // Contract assets
    // all assets detected, pagination
    ContractBalances(IndexMap<Hash, u64>, Option<u64>),
    // Contract assets
    // all assets detected, pagination
    ContractStores(IndexMap<ValueCell, ValueCell>, Option<u64>),
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
            Self::BlocksMetadata(_) => StepKind::BlocksMetadata
        }
    }
}

impl Serializer for StepResponse {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => {
                let common_point = Option::read(reader)?;
                let topoheight = reader.read_u64()?;
                let stable_height = reader.read_u64()?;
                let hash = reader.read_hash()?;

                Self::ChainInfo(common_point, topoheight, stable_height, hash)
            },
            1 => {
                let len = reader.read_u16()?;
                if len > MAX_ITEMS_PER_PAGE as u16 {
                    debug!("Invalid assets response length: {}", len);
                    return Err(ReaderError::InvalidValue)
                }

                let mut assets = IndexMap::with_capacity(len as usize);
                for _ in 0..len {
                    let key = Hash::read(reader)?;
                    let value = AssetData::read(reader)?;
                    if assets.insert(key, value).is_some() {
                        debug!("Duplicated asset key in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }

                let page = Option::read(reader)?;
                if let Some(page_number) = &page {
                    if *page_number == 0 {
                        debug!("Invalid page number (0) in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }
                Self::Assets(assets, page)
            },
            2 => {
                let len = reader.read_u16()?;
                if len > MAX_ITEMS_PER_PAGE as u16 {
                    debug!("Invalid assets supply response length: {}", len);
                    return Err(ReaderError::InvalidValue)
                }

                let mut values = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    values.push(Option::read(reader)?);
                }

                Self::AssetsSupply(values)
            },
            3 => {
                let len = reader.read_u16()?;
                if len > MAX_ITEMS_PER_PAGE as u16 {
                    debug!("Invalid keys response length: {}", len);
                    return Err(ReaderError::InvalidValue)
                }
                let mut keys = IndexSet::with_capacity(len as usize);
                for _ in 0..len {
                    if !keys.insert(PublicKey::read(reader)?) {
                        debug!("Duplicated public key in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }

                let page = Option::read(reader)?;
                if let Some(page_number) = &page {
                    if *page_number == 0 {
                        debug!("Invalid page number (0) in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }
                Self::Keys(keys, page)
            },
            4 => {
                let len = reader.read_u16()?;
                if len > MAX_ITEMS_PER_PAGE as u16 {
                    debug!("Invalid key balances response length: {}", len);
                    return Err(ReaderError::InvalidValue)
                }
                let mut keys = IndexMap::with_capacity(len as usize);
                for _ in 0..len {
                    let key = Hash::read(reader)?;
                    let value = Option::read(reader)?;
                    if keys.insert(key, value).is_some() {
                        debug!("Duplicated key in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }

                let page = Option::read(reader)?;
                if let Some(page_number) = &page {
                    if *page_number == 0 {
                        debug!("Invalid page number (0) in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }
                Self::KeyBalances(keys, page)
            },
            5 => {
                let len = reader.read_u16()?;
                if len > MAX_ITEMS_PER_PAGE as u16 {
                    debug!("Invalid spendable balances response length: {}", len);
                    return Err(ReaderError::InvalidValue)
                }

                let mut balances = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    let balance = Balance::read(reader)?;
                    balances.push(balance);
                }

                Self::SpendableBalances(balances, Option::read(reader)?)
            },
            6 => {
                let len = reader.read_u16()?;
                if len > MAX_ITEMS_PER_PAGE as u16 {
                    debug!("Invalid accounts response length: {}", len);
                    return Err(ReaderError::InvalidValue)
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
                let len = reader.read_u16()?;
                if len > MAX_ITEMS_PER_PAGE as u16 {
                    debug!("Invalid contracts response length: {}", len);
                    return Err(ReaderError::InvalidValue)
                }

                let mut contracts = IndexSet::with_capacity(len as usize);
                for _ in 0..len {
                    if !contracts.insert(Hash::read(reader)?) {
                        debug!("Duplicated contract hash in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }

                let page = Option::read(reader)?;
                if let Some(page_number) = &page {
                    if *page_number == 0 {
                        debug!("Invalid page number (0) in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }
                Self::Contracts(contracts, page)
            },
            8 => Self::ContractModule(State::read(reader)?),
            9 => {
                let len = reader.read_u16()?;
                if len > MAX_ITEMS_PER_PAGE as u16 {
                    debug!("Invalid contracts assets response length: {}", len);
                    return Err(ReaderError::InvalidValue)
                }

                let mut assets = IndexMap::with_capacity(len as usize);
                for _ in 0..len {
                    let asset = Hash::read(reader)?;
                    let value = reader.read_u64()?;
                    if assets.insert(asset, value).is_some() {
                        debug!("Duplicated contract asset in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }

                let page = Option::read(reader)?;
                if let Some(page_number) = &page {
                    if *page_number == 0 {
                        debug!("Invalid page number (0) in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }

                Self::ContractBalances(assets, page)
            },
            10 => {
                let len = reader.read_u16()?;
                if len > MAX_ITEMS_PER_PAGE as u16 {
                    debug!("Invalid contracts assets response length: {}", len);
                    return Err(ReaderError::InvalidValue)
                }

                let mut entries = IndexMap::with_capacity(len as usize);
                for _ in 0..len {
                    let key = ValueCell::read(reader)?;
                    let value = ValueCell::read(reader)?;
                    if entries.insert(key, value).is_some() {
                        debug!("Duplicated contract store in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }

                let page = Option::read(reader)?;
                if let Some(page_number) = &page {
                    if *page_number == 0 {
                        debug!("Invalid page number (0) in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }

                Self::ContractStores(entries, page)
            },
            11 => {
                let len = reader.read_u16()?;
                if len > PRUNE_SAFETY_LIMIT as u16 + 1 {
                    debug!("Invalid blocks metadata response length: {}", len);
                    return Err(ReaderError::InvalidValue)
                }

                let mut blocks = IndexSet::with_capacity(len as usize);
                for _ in 0..len {
                    let metadata = BlockMetadata::read(reader)?;
                    if !blocks.insert(metadata) {
                        debug!("Duplicated block metadata in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }

                Self::BlocksMetadata(blocks)
            },
            id => {
                debug!("Received invalid value for StepResponse: {}", id);
                return Err(ReaderError::InvalidValue)
            }
        })
    }

    fn write(&self, writer: &mut Writer) {
        match self {
            Self::ChainInfo(common_point, topoheight, stable_height, hash) => {
                writer.write_u8(0);
                common_point.write(writer);
                writer.write_u64(topoheight);
                writer.write_u64(stable_height);
                writer.write_hash(hash);
            },
            Self::Assets(assets, page) => {
                writer.write_u8(1);
                assets.write(writer);
                page.write(writer);
            },
            Self::AssetsSupply(supply) => {
                writer.write_u8(2);
                supply.write(writer);
            }
            Self::Keys(keys, page) => {
                writer.write_u8(3);
                keys.write(writer);
                page.write(writer);
            },
            Self::KeyBalances(keys, page) => {
                writer.write_u8(4);
                keys.write(writer);
                page.write(writer);
            },
            Self::SpendableBalances(balances, page) => {
                writer.write_u8(5);
                balances.write(writer);
                page.write(writer);
            },
            Self::Accounts(nonces) => {
                writer.write_u8(6);
                nonces.write(writer);
            },
            Self::Contracts(contracts, page) => {
                writer.write_u8(7);
                contracts.write(writer);
                page.write(writer);
            },
            Self::ContractModule(metadata) => {
                writer.write_u8(8);
                metadata.write(writer);
            },
            Self::ContractBalances(assets, page) => {
                writer.write_u8(9);
                assets.write(writer);
                page.write(writer);
            },
            Self::ContractStores(entries, page) => {
                writer.write_u8(10);
                entries.write(writer);
                page.write(writer);
            },
            Self::BlocksMetadata(blocks) => {
                writer.write_u8(11);
                blocks.write(writer);
            }
        };
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
            Self::ContractStores(entries, page) => entries.size() + page.size(),
            Self::BlocksMetadata(blocks) => blocks.size()
        };
        // 1 for the id
        size + 1
    }
}
