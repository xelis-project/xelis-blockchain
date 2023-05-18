use std::{collections::{BTreeSet, HashSet}, borrow::Cow};

use log::debug;
use xelis_common::{crypto::{hash::Hash, key::PublicKey}, serializer::{Serializer, ReaderError, Reader, Writer}, block::Difficulty};

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
    pub hash: Hash,
    pub supply: u64,
    pub reward: u64,
    pub difficulty: Difficulty,
    pub cumulative_difficulty: Difficulty
}

impl Serializer for BlockMetadata {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let hash = reader.read_hash()?;
        let supply = reader.read_u64()?;
        let reward = reader.read_u64()?;
        let difficulty = reader.read_u64()?;
        let cumulative_difficulty = reader.read_u64()?;

        Ok(Self {
            hash,
            supply,
            reward,
            difficulty,
            cumulative_difficulty
        })
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.hash);
        writer.write_u64(&self.supply);
        writer.write_u64(&self.reward);
        writer.write_u64(&self.difficulty);
        writer.write_u64(&self.cumulative_difficulty);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum StepKind {
    Assets,
    Keys,
    Balances,
    Nonces,
    BlocksMetadata,
    Tips
}

#[derive(Debug)]
pub enum StepRequest<'a> {
    // Pagination
    Assets(Option<u64>),
    // Asset, pagination
    Keys(Option<u64>),
    // Asset, Accounts
    Balances(Cow<'a, Hash>, Cow<'a, BTreeSet<Cow<'a, PublicKey>>>),
    // Accounts
    Nonces(Cow<'a, BTreeSet<Cow<'a, PublicKey>>>),
    // Request blocks metadata starting topoheight
    BlocksMetadata(u64),
    Tips
}

impl<'a> StepRequest<'a> {
    pub fn kind(&self) -> StepKind {
        match self {
            Self::Assets(_) => StepKind::Assets,
            Self::Keys(_) => StepKind::Keys,
            Self::Balances(_, _) => StepKind::Balances,
            Self::Nonces(_) => StepKind::Nonces,
            Self::BlocksMetadata(_) => StepKind::BlocksMetadata,
            Self::Tips => StepKind::Tips
        }
    }
}

impl Serializer for StepRequest<'_> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => {
                let page = reader.read_optional_non_zero_u64()?;
                Self::Assets(page)
            },
            1 => {
                let page = reader.read_optional_non_zero_u64()?;
                Self::Keys(page)
            },
            2 => {
                let hash = Cow::<'_, Hash>::read(reader)?;
                let keys = Cow::<'_, BTreeSet<Cow<'_, PublicKey>>>::read(reader)?;
                Self::Balances(hash, keys)
            },
            3 => {
                Self::Nonces(Cow::<'_, BTreeSet<Cow<'_, PublicKey>>>::read(reader)?)
            },
            4 => {
                Self::BlocksMetadata(reader.read_u64()?)
            },
            5 => {
                Self::Tips
            },
            id => {
                debug!("Received invalid value for StepResponse: {}", id);
                return Err(ReaderError::InvalidValue)
            }
        })
    }

    fn write(&self, writer: &mut Writer) {
        match self {
            Self::Assets(page) => {
                writer.write_u8(0);
                writer.write_optional_non_zero_u64(page);
            },
            Self::Keys(page) => {
                writer.write_u8(1);
                writer.write_optional_non_zero_u64(page);
            },
            Self::Balances(asset, accounts) => {
                writer.write_u8(2);
                writer.write_hash(asset);
                accounts.write(writer);
            },
            Self::Nonces(nonces) => {
                writer.write_u8(3);
                nonces.write(writer);
            },
            Self::BlocksMetadata(blocks) => {
                writer.write_u8(4);
                blocks.write(writer);
            },
            Self::Tips => {
                writer.write_u8(5);
            }
        };
    }
}

#[derive(Debug)]
pub enum StepResponse {
    Assets(BTreeSet<Hash>, Option<u64>), // Set of assets, pagination
    Keys(BTreeSet<PublicKey>, Option<u64>), // Set of keys, pagination
    Balances(Vec<Option<u64>>), // Balances requested
    Nonces(Vec<u64>), // Nonces for requested accounts
    BlocksMetadata(Vec<BlockMetadata>), // top blocks metadata
    Tips(HashSet<Hash>) // chain tips
}

impl StepResponse {
    pub fn kind(&self) -> StepKind {
        match self {
            Self::Assets(_, _) => StepKind::Assets,
            Self::Keys(_, _) => StepKind::Keys,
            Self::Balances(_) => StepKind::Balances,
            Self::Nonces(_) => StepKind::Nonces,
            Self::BlocksMetadata(_) => StepKind::BlocksMetadata,
            Self::Tips(_) => StepKind::Tips
        }
    }
}

impl Serializer for StepResponse {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => {
                let assets = BTreeSet::<Hash>::read(reader)?;
                let page = reader.read_optional_non_zero_u64()?;
                Self::Assets(assets, page)
            },
            1 => {
                let keys = BTreeSet::<PublicKey>::read(reader)?;
                let page = reader.read_optional_non_zero_u64()?;
                Self::Keys(keys, page)
            },
            2 => {
                Self::Balances(Vec::<Option<u64>>::read(reader)?)
            },
            3 => {
                Self::Nonces(Vec::<u64>::read(reader)?)
            },
            4 => {
                Self::BlocksMetadata(Vec::<BlockMetadata>::read(reader)?)
            },
            5 => {
                let count = reader.read_u8()? as usize;
                let mut set = HashSet::with_capacity(count);
                for _ in 0..count {
                    let hash = reader.read_hash()?;
                    set.insert(hash);
                }
                Self::Tips(set)
            }
            id => {
                debug!("Received invalid value for StepResponse: {}", id);
                return Err(ReaderError::InvalidValue)
            }
        })
    }

    fn write(&self, writer: &mut Writer) {
        match self {
            Self::Assets(assets, page) => {
                writer.write_u8(0);
                assets.write(writer);
                writer.write_optional_non_zero_u64(page);
            },
            Self::Keys(keys, page) => {
                writer.write_u8(1);
                keys.write(writer);
                writer.write_optional_non_zero_u64(page);
            },
            Self::Balances(balances) => {
                writer.write_u8(2);
                balances.write(writer);
            },
            Self::Nonces(nonces) => {
                writer.write_u8(3);
                nonces.write(writer);
            },
            Self::BlocksMetadata(blocks) => {
                writer.write_u8(4);
                blocks.write(writer);
            },
            Self::Tips(tips) => {
                writer.write_u8(5);

                writer.write_u8(tips.len() as u8);
                for hash in tips {
                    writer.write_hash(hash);
                }
            }
        };
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
}
