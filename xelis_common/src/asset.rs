use std::borrow::Cow;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    block::TopoHeight,
    crypto::Hash,
    serializer::{Reader, ReaderError, Serializer, Writer},
    versioned_type::Versioned
};

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AssetOwner {
    // No creator of this asset
    // its either native asset
    // or the creator link has been deleted
    None,
    // Original owner of the asset
    Creator {
        // Contract hash that created this asset
        contract: Hash,
        // Id used to create this asset
        // This is the original inner ID
        // used by the smart contract
        // This may be invalid if the asset
        // is transfered
        id: u64,
    },
    // New owner of the asset
    Owner {
        // Original contract that created this asset
        origin: Hash,
        // Original id used to create this asset
        origin_id: u64,
        // Current owner of the asset
        owner: Hash
    }
}

impl AssetOwner {
    // Get the contract that currently owns this asset
    pub fn get_contract(&self) -> Option<&Hash> {
        match self {
            Self::Creator { contract, .. } | Self::Owner { origin: contract, .. } => Some(contract),
            Self::None => None
        }
    }

    // Get the original contract that created this asset
    pub fn get_origin_contract(&self) -> Option<&Hash> {
        match self {
            Self::Creator { contract, .. } => Some(contract),
            Self::Owner { origin: contract, .. } => Some(contract),
            Self::None => None
        }
    }

    // Get the id used to create this asset
    pub fn get_id(&self) -> Option<u64> {
        match self {
            Self::Creator { id, .. } | Self::Owner { origin_id: id, .. } => Some(*id),
            Self::None => None
        }
    }

    // Check if the given address is the owner of this asset
    pub fn is_owner(&self, address: &Hash) -> bool {
        match self {
            Self::Owner { owner: contract, .. } | Self::Creator { contract, .. } if *contract == *address => true,
            _ => false
        }
    }

    // Transfer the ownership of this asset
    pub fn transfer(&mut self, current: &Hash, new_owner: Hash) -> bool {
        match self {
            Self::Creator { contract, id } if *contract == *current => {
                *self = Self::Owner {
                    origin: contract.clone(),
                    origin_id: *id,
                    owner: new_owner
                };

                true
            },
            Self::Owner { owner, .. } if *owner == *current => {
                *owner = new_owner;
                true
            },
            _ => false
        }
    }
}

impl Serializer for AssetOwner {
    fn write(&self, writer: &mut Writer) {
        match self {
            Self::None => {
                writer.write_u8(0);
            },
            Self::Creator { contract, id } => {
                writer.write_u8(1);
                contract.write(writer);
                id.write(writer);
            },
            Self::Owner { origin, origin_id, owner } => {
                writer.write_u8(2);
                origin.write(writer);
                origin_id.write(writer);
                owner.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        match reader.read_u8()? {
            0 => Ok(Self::None),
            1 => {
                let contract = reader.read()?;
                let id = reader.read()?;
                Ok(Self::Creator { contract, id })
            },
            2 => {
                let origin = reader.read()?;
                let origin_id = reader.read()?;
                let owner = reader.read()?;
                Ok(Self::Owner { origin, origin_id, owner })
            },
            _ => Err(ReaderError::InvalidValue)
        }
    }

    fn size(&self) -> usize {
        match self {
            Self::None => 1,
            Self::Creator { .. } => 1 + 32 + 8,
            Self::Owner { .. } => 1 + 32 + 8 + 32
        }
    }
}

pub type VersionedAssetData = Versioned<AssetData>;


#[derive(Serialize, Deserialize, Debug, Clone, Copy, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MaxSupplyMode {
    // No max supply set
    None,
    // Fixed, emitted one time
    // and managed by the contract
    Fixed(u64),
    // As long as the circulating supply
    // is below the max supply, mint is possible
    Mintable(u64),
}

impl MaxSupplyMode {
    pub fn get_max(&self) -> Option<u64> {
        match self {
            Self::None => None,
            Self::Fixed(max) | Self::Mintable(max) => Some(*max)
        }
    }

    pub fn allow_minting(&self, current_supply: u64, amount: u64) -> bool {
        match self {
            Self::None => true,
            Self::Fixed(_) => false,
            Self::Mintable(max) => current_supply.checked_add(amount) <= Some(*max)
        }
    }

    pub fn is_mintable(&self) -> bool {
        matches!(self, Self::Mintable(_) | Self::None)
    }
}

impl Serializer for MaxSupplyMode {
    fn write(&self, writer: &mut Writer) {
        match self {
            Self::None => {
                writer.write_u8(0);
            },
            Self::Fixed(max) => {
                writer.write_u8(1);
                max.write(writer);
            },
            Self::Mintable(max) => {
                writer.write_u8(2);
                max.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        match reader.read_u8()? {
            0 => Ok(Self::None),
            1 => Ok(Self::Fixed(reader.read_u64()?)),
            2 => Ok(Self::Mintable(reader.read_u64()?)),
            _ => Err(ReaderError::InvalidValue)
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct AssetData {
    // How many atomic units is needed for a full coin
    decimals: u8,
    // The name of the asset
    name: String,
    // The ticker of the asset
    // Maximum 6 chars
    ticker: String,
    // The total supply of the asset
    max_supply: MaxSupplyMode,
    // Contract owning this asset
    owner: AssetOwner
}

impl AssetData {
    pub fn new(decimals: u8, name: String, ticker: String, max_supply: MaxSupplyMode, owner: AssetOwner) -> Self {
        Self {
            decimals,
            name,
            ticker,
            max_supply,
            owner
        }
    }

    pub fn get_decimals(&self) -> u8 {
        self.decimals
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_ticker(&self) -> &str {
        &self.ticker
    }

    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    pub fn set_ticker(&mut self, ticker: String) {
        self.ticker = ticker;
    }

    pub fn get_max_supply(&self) -> MaxSupplyMode {
        self.max_supply
    }

    pub fn get_owner(&self) -> &AssetOwner {
        &self.owner
    }

    pub fn get_owner_mut(&mut self) -> &mut AssetOwner {
        &mut self.owner
    }
}

impl Serializer for AssetData {
    fn write(&self, writer: &mut Writer) {
        self.decimals.write(writer);
        self.name.write(writer);
        self.ticker.write(writer);
        self.max_supply.write(writer);
        self.owner.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let decimals = reader.read()?;
        let name = reader.read()?;
        let ticker = reader.read()?;
        let max_supply = reader.read()?;
        let owner = reader.read()?;

        Ok(Self::new(decimals, name, ticker, max_supply, owner))
    }

    fn size(&self) -> usize {
        self.decimals.size() + self.name.size() + self.max_supply.size()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, JsonSchema)]
pub struct RPCAssetData<'a> {
    // The asset hash
    pub asset: Cow<'a, Hash>,
    // At which topoheight was this asset created
    pub topoheight: TopoHeight,
    // Inner data
    #[serde(flatten)]
    pub inner: AssetData
}