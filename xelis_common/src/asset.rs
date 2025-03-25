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
    max_supply: Option<u64>,
    // Contract owning this asset
    owner: Option<AssetOwner>
}

impl AssetData {
    pub fn new(decimals: u8, name: String, ticker: String, max_supply: Option<u64>, owner: Option<AssetOwner>) -> Self {
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

    pub fn get_max_supply(&self) -> Option<u64> {
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