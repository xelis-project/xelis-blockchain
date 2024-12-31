use std::borrow::Cow;
use serde::{Deserialize, Serialize};

use crate::{
    block::TopoHeight,
    crypto::Hash,
    serializer::{Reader, ReaderError, Serializer, Writer}
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AssetData {
    // How many atomic units is needed for a full coin
    decimals: u8,
    // The name of the asset
    name: String,
    // The total supply of the asset
    max_supply: Option<u64>,
}

impl AssetData {
    pub fn new(decimals: u8, name: String, max_supply: Option<u64>) -> Self {
        Self {
            decimals,
            name,
            max_supply
        }
    }

    pub fn get_decimals(&self) -> u8 {
        self.decimals
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    pub fn get_max_supply(&self) -> Option<u64> {
        self.max_supply
    }
}

impl Serializer for AssetData {
    fn write(&self, writer: &mut Writer) {
        self.decimals.write(writer);
        self.name.write(writer);
        self.max_supply.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let decimals = reader.read()?;
        let name = reader.read()?;
        let max_supply = reader.read()?;

        Ok(Self::new(decimals, name, max_supply))
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
    // How many atomic units is needed for a full coin
    pub decimals: u8,
    // The name of the asset
    pub name: Cow<'a, str>,
    // The total supply of the asset
    pub max_supply: Option<u64>,
    // The contract that created this asset
    pub contract: Option<Cow<'a, Hash>>,
}