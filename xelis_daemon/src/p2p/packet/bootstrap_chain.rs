use std::{
    borrow::Cow,
    hash::{Hash as StdHash, Hasher}
};
use indexmap::IndexSet;
use log::debug;
use xelis_common::{
    account::{BalanceType, CiphertextCache},
    asset::AssetWithData,
    crypto::{
        Hash, PublicKey
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
    varuint::VarUint
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
    // Circulating supply
    pub supply: u64,
    // Miner reward
    pub reward: u64,
    // Difficulty of the block
    pub difficulty: Difficulty,
    // Cumulative difficulty of the chain
    pub cumulative_difficulty: CumulativeDifficulty,
    // Difficulty P variable
    pub p: VarUint,
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
        let reward = reader.read_u64()?;
        let difficulty = Difficulty::read(reader)?;
        let cumulative_difficulty = CumulativeDifficulty::read(reader)?;
        let p = VarUint::read(reader)?;

        Ok(Self {
            hash,
            supply,
            reward,
            difficulty,
            cumulative_difficulty,
            p
        })
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.hash);
        writer.write_u64(&self.supply);
        writer.write_u64(&self.reward);
        self.difficulty.write(writer);
        self.cumulative_difficulty.write(writer);
        self.p.write(writer);
    }

    fn size(&self) -> usize {
        self.hash.size()
        + self.supply.size()
        + self.reward.size()
        + self.difficulty.size()
        + self.cumulative_difficulty.size()
        + self.p.size()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum StepKind {
    ChainInfo,
    Assets,
    Keys,
    Balances,
    Nonces,
    BlocksMetadata
}

impl StepKind {
    pub fn next(&self) -> Option<Self> {
        Some(match self {
            Self::ChainInfo => Self::Assets,
            Self::Assets => Self::Keys,
            Self::Keys => Self::Balances,
            Self::Balances => Self::Nonces,
            Self::Nonces => Self::BlocksMetadata,
            Self::BlocksMetadata => return None
        })
    }
}

#[derive(Debug)]
pub enum StepRequest<'a> {
    // Request chain info (top topoheight, top height, top hash)
    ChainInfo(IndexSet<BlockId>),
    // Min topoheight, Max topoheight, Pagination
    Assets(u64, u64, Option<u64>),
    // Min topoheight, Max topoheight, Asset, pagination
    Keys(u64, u64, Option<u64>),
    // Max topoheight, Asset, Accounts
    Balances(u64, Cow<'a, Hash>, Cow<'a, IndexSet<PublicKey>>),
    // Max topoheight, Accounts
    Nonces(u64, Cow<'a, IndexSet<PublicKey>>),
    // Request blocks metadata starting topoheight
    BlocksMetadata(u64)
}

impl<'a> StepRequest<'a> {
    pub fn kind(&self) -> StepKind {
        match self {
            Self::ChainInfo(_) => StepKind::ChainInfo,
            Self::Assets(_, _, _) => StepKind::Assets,
            Self::Keys(_, _, _) => StepKind::Keys,
            Self::Balances(_, _, _) => StepKind::Balances,
            Self::Nonces(_, _) => StepKind::Nonces,
            Self::BlocksMetadata(_) => StepKind::BlocksMetadata
        }
    }

    pub fn get_requested_topoheight(&self) -> Option<u64> {
        Some(*match self {
            Self::ChainInfo(_) => return None,
            Self::Assets(_, topo, _) => topo,
            Self::Keys(_, topo, _) => topo,
            Self::Balances(topo, _, _) => topo,
            Self::Nonces(topo, _) => topo,
            Self::BlocksMetadata(topo) => topo
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
                let topoheight = reader.read_u64()?;
                let hash = Cow::<'_, Hash>::read(reader)?;
                let keys = Cow::<'_, IndexSet<PublicKey>>::read(reader)?;
                Self::Balances(topoheight, hash, keys)
            },
            4 => {
                let topoheight = reader.read_u64()?;
                let keys = Cow::<'_, IndexSet<PublicKey>>::read(reader)?;
                Self::Nonces(topoheight, keys)
            },
            5 => {
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
            Self::Balances(topoheight, asset, accounts) => {
                writer.write_u8(3);
                writer.write_u64(topoheight);
                writer.write_hash(asset);
                accounts.write(writer);
            },
            Self::Nonces(topoheight, nonces) => {
                writer.write_u8(4);
                writer.write_u64(topoheight);
                nonces.write(writer);
            },
            Self::BlocksMetadata(topoheight) => {
                writer.write_u8(5);
                writer.write_u64(topoheight);
            },
        };
    }

    fn size(&self) -> usize {
        let size = match self {
            Self::ChainInfo(blocks) => 1 + blocks.size(),
            Self::Assets(min, max, page) => min.size() + max.size() + page.size(),
            Self::Keys(min, max, page) => min.size() + max.size() + page.size(),
            Self::Balances(topoheight, asset, accounts) => topoheight.size() + asset.size() + accounts.size(),
            Self::Nonces(topoheight, nonces) => topoheight.size() + nonces.size(),
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
    Assets(IndexSet<AssetWithData>, Option<u64>),
    // Set of keys, pagination
    Keys(IndexSet<PublicKey>, Option<u64>),
    // Balances requested (optional because not all accounts may have balances for requested asset)
    // (CiphertextCache, Option<CiphertextCache>) (balance, output balance)
    Balances(Vec<Option<(CiphertextCache, Option<CiphertextCache>, BalanceType)>>),
    // Nonces for requested accounts
    Nonces(Vec<u64>),
    // top blocks metadata
    BlocksMetadata(IndexSet<BlockMetadata>),
}

impl StepResponse {
    pub fn kind(&self) -> StepKind {
        match self {
            Self::ChainInfo(_, _, _, _) => StepKind::ChainInfo,
            Self::Assets(_, _) => StepKind::Assets,
            Self::Keys(_, _) => StepKind::Keys,
            Self::Balances(_) => StepKind::Balances,
            Self::Nonces(_) => StepKind::Nonces,
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
                let assets = IndexSet::<AssetWithData>::read(reader)?;
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
                let keys = IndexSet::<PublicKey>::read(reader)?;
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
                Self::Balances(Vec::read(reader)?)
            },
            4 => {
                Self::Nonces(Vec::<u64>::read(reader)?)
            },
            5 => {
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
            Self::Balances(balances) => {
                writer.write_u8(3);
                balances.write(writer);
            },
            Self::Nonces(nonces) => {
                writer.write_u8(4);
                nonces.write(writer);
            },
            Self::BlocksMetadata(blocks) => {
                writer.write_u8(5);
                blocks.write(writer);
            }
        };
    }

    fn size(&self) -> usize {
        let size = match self {
            Self::ChainInfo(common_point, topoheight, stable_height, hash) => {
                common_point.size() + topoheight.size() + stable_height.size() + hash.size()
            },
            Self::Assets(assets, page) => {
                assets.size() + page.size()
            },
            Self::Keys(keys, page) => {
                keys.size() + page.size()
            },
            Self::Balances(balances) => {
                balances.size()
            },
            Self::Nonces(nonces) => {
                nonces.size()
            },
            Self::BlocksMetadata(blocks) => {
                blocks.size()
            }
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
