use std::borrow::Cow;
use serde::{Deserialize, Serialize};

use crate::{
    block::TopoHeight,
    crypto::Hash,
    serializer::{Reader, ReaderError, Serializer, Writer},
    versioned_type::Versioned
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AssetOwner {
    // Contract hash
    contract: Hash,
    // Id used to create this asset
    // This is the original inner ID
    // used by the smart contract
    // This may be invalid if the asset
    // is transfered
    id: u64
}

impl AssetOwner {
    pub fn new(contract: Hash, id: u64) -> Self {
        Self {
            contract,
            id
        }
    }

    pub fn get_contract(&self) -> &Hash {
        &self.contract
    }

    pub fn set_contract(&mut self, contract: Hash) {
        self.contract = contract;
    }

    pub fn get_id(&self) -> u64 {
        self.id
    }
}

impl Serializer for AssetOwner {
    fn write(&self, writer: &mut Writer) {
        self.contract.write(writer);
        self.id.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let contract = reader.read()?;
        let id = reader.read()?;

        Ok(Self::new(contract, id))
    }

    fn size(&self) -> usize {
        self.contract.size() + self.id.size()
    }
}

pub type VersionedAssetData = Versioned<AssetData>;


#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
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
            Self::Fixed(max) => current_supply.checked_add(amount) <= Some(*max),
            Self::Mintable(max) => current_supply.checked_add(amount) <= Some(*max)
        }
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

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    owner: Option<AssetOwner>
}

impl AssetData {
    pub fn new(decimals: u8, name: String, ticker: String, max_supply: MaxSupplyMode, owner: Option<AssetOwner>) -> Self {
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

    pub fn get_owner(&self) -> &Option<AssetOwner> {
        &self.owner
    }

    pub fn get_owner_mut(&mut self) -> Option<&mut AssetOwner> {
        self.owner.as_mut()
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

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct RPCAssetData<'a> {
    // The asset hash
    pub asset: Cow<'a, Hash>,
    // At which topoheight was this asset created
    pub topoheight: TopoHeight,
    // Inner data
    #[serde(flatten)]
    pub inner: AssetData
}