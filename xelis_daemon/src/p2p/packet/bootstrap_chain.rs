use std::{
    borrow::Cow,
    hash::{Hash as StdHash, Hasher}
};
use indexmap::{IndexMap, IndexSet};
use log::debug;
use xelis_common::{
    account::{AccountSummary, Balance, Nonce},
    asset::AssetData,
    block::TopoHeight,
    contract::ContractMetadata,
    crypto::{
        Hash,
        PublicKey
    },
    difficulty::{
        CumulativeDifficulty,
        Difficulty
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    },
    transaction::MultiSigPayload,
    varuint::VarUint,
    versioned_type::State
};
use super::chain::{BlockId, CommonPoint};
use crate::config::CHAIN_SYNC_REQUEST_MAX_BLOCKS;

// this file implements the protocol for the fast sync (bootstrapped chain)
// You will have to request through StepRequest::FetchAssets all the registered assets
// based on the size of the chain, you can have pagination or not.
// With the set of assets, you can retrieve all registered keys for it and then its balances
// Nonces need to be retrieve only one time because its common for all assets.
// The protocol is based on
// how many items we can answer per request

pub const MAX_ITEMS_PER_PAGE: usize = 1024;

#[derive(Debug)]
pub struct BlockMetadata {
    // Hash of the block
    pub hash: Hash,
    // Emitted supply
    pub supply: u64,
    // Burned supply
    pub burned_supply: u64,
    // Miner reward
    pub reward: u64,
    // Difficulty of the block
    pub difficulty: Difficulty,
    // Cumulative difficulty of the chain
    pub cumulative_difficulty: CumulativeDifficulty,
    // Difficulty P variable
    pub p: VarUint,
    // All transactions marked as executed in this block
    pub executed_transactions: IndexSet<Hash>
}

impl StdHash for BlockMetadata {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl PartialEq for BlockMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for BlockMetadata {}

impl Serializer for BlockMetadata {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let hash = reader.read_hash()?;
        let supply = reader.read_u64()?;
        let burned_supply = reader.read_u64()?;
        let reward = reader.read_u64()?;
        let difficulty = Difficulty::read(reader)?;
        let cumulative_difficulty = CumulativeDifficulty::read(reader)?;
        let p = VarUint::read(reader)?;

        // We don't write it through IndexSet impl directly
        // as we must support any u16 len same as a BlockHeader
        // TODO best would be a const type providing a configurable MAX_ITEMS

        let len = reader.read_u16()?;
        let mut executed_transactions = IndexSet::new();
        for _ in 0..len {
            if !executed_transactions.insert(Hash::read(reader)?) {
                return Err(ReaderError::InvalidValue)
            }
        }

        Ok(Self {
            hash,
            supply,
            burned_supply,
            reward,
            difficulty,
            cumulative_difficulty,
            p,
            executed_transactions
        })
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.hash);
        writer.write_u64(&self.supply);
        writer.write_u64(&self.burned_supply);
        writer.write_u64(&self.reward);
        self.difficulty.write(writer);
        self.cumulative_difficulty.write(writer);
        self.p.write(writer);
        self.executed_transactions.write(writer);
    }

    fn size(&self) -> usize {
        self.hash.size()
        + self.supply.size()
        + self.burned_supply.size()
        + self.reward.size()
        + self.difficulty.size()
        + self.cumulative_difficulty.size()
        + self.p.size()
        + self.executed_transactions.size()
    }
}

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
    ContractMetadata(TopoHeight, TopoHeight, Cow<'a, Hash>),
    // Request blocks metadata starting topoheight
    BlocksMetadata(TopoHeight)
}

impl<'a> StepRequest<'a> {
    pub fn kind(&self) -> StepKind {
        match self {
            Self::ChainInfo(_) => StepKind::ChainInfo,
            Self::Assets(_, _, _) => StepKind::Assets,
            Self::Keys(_, _, _) => StepKind::Keys,
            Self::KeyBalances(_, _, _, _) => StepKind::KeyBalances,
            Self::SpendableBalances(_, _, _, _) => StepKind::KeyBalances,
            Self::Accounts(_, _, _) => StepKind::Accounts,
            Self::Contracts(_, _, _) => StepKind::Contracts,
            Self::ContractMetadata(_, _, _) => StepKind::Contracts,
            Self::BlocksMetadata(_) => StepKind::BlocksMetadata
        }
    }

    pub fn get_requested_topoheight(&self) -> Option<u64> {
        Some(*match self {
            Self::Assets(_, topo, _) => topo,
            Self::Keys(_, topo, _) => topo,
            Self::KeyBalances(_, _, topo, _) => topo,
            Self::SpendableBalances(_, _, _, topo) => topo,
            Self::Accounts(_, topo, _) => topo,
            Self::Contracts(_, topo, _) => topo,
            Self::ContractMetadata(_, topo, _) => topo,
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
            3 => {
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
            4 => {
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
            5 => {
                let min = reader.read_u64()?;
                let max = reader.read_u64()?;
                let keys = Cow::read(reader)?;
                Self::Accounts(min, max, keys)
            },
            6 => {
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
            7 => {
                let min = reader.read_u64()?;
                let max = reader.read_u64()?;
                let hash = Cow::read(reader)?;
                Self::ContractMetadata(min, max, hash)
            }
            8 => {
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
            Self::Keys(min, max, page) => {
                writer.write_u8(2);
                writer.write_u64(min);
                writer.write_u64(max);
                page.write(writer);
            },
            Self::KeyBalances(key, min, max, page) => {
                writer.write_u8(3);
                key.write(writer);
                writer.write_u64(min);
                writer.write_u64(max);
                page.write(writer);
            },
            Self::SpendableBalances(key, asset, min, max) => {
                writer.write_u8(4);
                key.write(writer);
                asset.write(writer);
                writer.write_u64(min);
                writer.write_u64(max);
            },
            Self::Accounts(min, max, nonces) => {
                writer.write_u8(5);
                writer.write_u64(min);
                writer.write_u64(max);
                nonces.write(writer);
            },
            Self::Contracts(min, max, pagination) => {
                writer.write_u8(6);
                writer.write_u64(min);
                writer.write_u64(max);
                pagination.write(writer);
            },
            Self::ContractMetadata(min, max, hash) => {
                writer.write_u8(7);
                writer.write_u64(min);
                writer.write_u64(max);
                hash.write(writer);
            },
            Self::BlocksMetadata(topoheight) => {
                writer.write_u8(8);
                writer.write_u64(topoheight);
            },
        };
    }

    fn size(&self) -> usize {
        let size = match self {
            Self::ChainInfo(blocks) => 1 + blocks.size(),
            Self::Assets(min, max, page) => min.size() + max.size() + page.size(),
            Self::Keys(min, max, page) => min.size() + max.size() + page.size(),
            Self::KeyBalances(key, min, max, page) => key.size() + min.size() + max.size() + page.size(),
            Self::SpendableBalances(key, asset, min, max) => key.size() + asset.size() + min.size() + max.size(),
            Self::Accounts(min, max, nonces) => min.size() + max.size() + nonces.size(),
            Self::Contracts(min, max, pagination) => min.size() + max.size() + pagination.size(),
            Self::ContractMetadata(min, max, hash) => min.size() + max.size() + hash.size(),
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
    ContractMetadata(State<ContractMetadata>),
    // top blocks metadata
    BlocksMetadata(IndexSet<BlockMetadata>),
}

impl StepResponse {
    pub fn kind(&self) -> StepKind {
        match self {
            Self::ChainInfo(_, _, _, _) => StepKind::ChainInfo,
            Self::Assets(_, _) => StepKind::Assets,
            Self::Keys(_, _) => StepKind::Keys,
            Self::KeyBalances(_, _) => StepKind::KeyBalances,
            Self::SpendableBalances(_, _) => StepKind::KeyBalances,
            Self::Accounts(_) => StepKind::Accounts,
            Self::Contracts(_, _) => StepKind::Contracts,
            Self::ContractMetadata(_) => StepKind::Contracts,
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
                let assets = IndexMap::read(reader)?;
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
                let keys = IndexSet::read(reader)?;
                let page = Option::read(reader)?;
                if let Some(page_number) = &page {
                    if *page_number == 0 {
                        debug!("Invalid page number (0) in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }
                Self::Keys(keys, page)
            },
            3 => {
                let keys = IndexMap::read(reader)?;
                let page = Option::read(reader)?;
                if let Some(page_number) = &page {
                    if *page_number == 0 {
                        debug!("Invalid page number (0) in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }
                Self::KeyBalances(keys, page)
            },
            4 => Self::SpendableBalances(Vec::read(reader)?, Option::read(reader)?),
            5 => Self::Accounts(Vec::read(reader)?),
            6 => {
                let contracts = IndexSet::<Hash>::read(reader)?;
                let page = Option::read(reader)?;
                if let Some(page_number) = &page {
                    if *page_number == 0 {
                        debug!("Invalid page number (0) in Step Response");
                        return Err(ReaderError::InvalidValue)
                    }
                }
                Self::Contracts(contracts, page)
            },
            7 => {
                Self::ContractMetadata(State::read(reader)?)
            }
            8 => {
                Self::BlocksMetadata(IndexSet::read(reader)?)
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
            Self::Keys(keys, page) => {
                writer.write_u8(2);
                keys.write(writer);
                page.write(writer);
            },
            Self::KeyBalances(keys, page) => {
                writer.write_u8(3);
                keys.write(writer);
                page.write(writer);
            },
            Self::SpendableBalances(balances, page) => {
                writer.write_u8(4);
                balances.write(writer);
                page.write(writer);
            },
            Self::Accounts(nonces) => {
                writer.write_u8(5);
                nonces.write(writer);
            },
            Self::Contracts(contracts, page) => {
                writer.write_u8(6);
                contracts.write(writer);
                page.write(writer);
            },
            Self::ContractMetadata(metadata) => {
                writer.write_u8(7);
                metadata.write(writer);
            },
            Self::BlocksMetadata(blocks) => {
                writer.write_u8(8);
                blocks.write(writer);
            }
        };
    }

    fn size(&self) -> usize {
        let size = match self {
            Self::ChainInfo(common_point, topoheight, stable_height, hash) => common_point.size() + topoheight.size() + stable_height.size() + hash.size(),
            Self::Assets(assets, page) => assets.size() + page.size(),
            Self::Keys(keys, page) => keys.size() + page.size(),
            Self::KeyBalances(keys, page) => keys.size() + page.size(),
            Self::SpendableBalances(balances, page) => balances.size() + page.size(),
            Self::Accounts(nonces) => nonces.size(),
            Self::Contracts(contracts, page) => contracts.size() + page.size(),
            Self::ContractMetadata(metadata) => metadata.size(),
            Self::BlocksMetadata(blocks) => blocks.size()
        };
        // 1 for the id
        size + 1
    }
}

#[derive(Debug)]
pub struct BootstrapChainRequest<'a> {
    step: StepRequest<'a>
}

impl<'a> BootstrapChainRequest<'a> {
    pub fn new(step: StepRequest<'a>) -> Self {
        Self {
            step
        }
    }

    pub fn kind(&self) -> StepKind {
        self.step.kind()
    }

    pub fn step(self) -> StepRequest<'a> {
        self.step
    }
}

impl Serializer for BootstrapChainRequest<'_> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self::new(StepRequest::read(reader)?))
    }

    fn write(&self, writer: &mut Writer) {
        self.step.write(writer);
    }

    fn size(&self) -> usize {
        self.step.size()
    }
}

#[derive(Debug)]
pub struct BootstrapChainResponse {
    response: StepResponse
}

impl BootstrapChainResponse {
    pub fn new(response: StepResponse) -> Self {
        Self {
            response
        }
    }

    pub fn kind(&self) -> StepKind {
        self.response.kind()
    }

    pub fn response(self) -> StepResponse {
        self.response
    }
}

impl Serializer for BootstrapChainResponse {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self::new(StepResponse::read(reader)?))
    }

    fn write(&self, writer: &mut Writer) {
        self.response.write(writer);
    }

    fn size(&self) -> usize {
        self.response.size()
    }
}
