use std::{borrow::Cow, hash::{Hash as StdHash, Hasher}};
use serde::{Deserialize, Serialize};

use crate::{
    block::TopoHeight,
    crypto::Hash,
    serializer::{Reader, ReaderError, Serializer, Writer}
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AssetData<'a> {
    // How many atomic units is needed for a full coin
    decimals: u8,
    // The name of the asset
    name: Cow<'a, str>,
    // The contract that created this asset
    contract: Option<Cow<'a, Hash>>,
}

impl<'a> AssetData<'a> {
    pub fn new(decimals: u8, name: Cow<'a, str>, contract: Option<Cow<'a, Hash>>) -> Self {
        Self {
            decimals,
            name,
            contract
        }
    }

    pub fn get_decimals(&self) -> u8 {
        self.decimals
    }
}

impl<'a> Serializer for AssetData<'a> {
    fn write(&self, writer: &mut Writer) {
        self.decimals.write(writer);
        self.name.write(writer);
        self.contract.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let decimals = reader.read()?;
        let name = reader.read()?;
        let contract = reader.read()?;

        Ok(Self::new(decimals, name, contract))
    }

    fn size(&self) -> usize {
        self.decimals.size() + self.name.size() + self.contract.size()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AssetWithData<'a> {
    // The asset hash
    asset: Cow<'a, Hash>,
    // At which topoheight was this asset created
    topoheight: TopoHeight,
    // The data of the asset
    #[serde(flatten)]
    data: AssetData<'a>
}

impl<'a> AssetWithData<'a> {
    pub fn new(asset: Cow<'a, Hash>, topoheight: TopoHeight, data: AssetData<'a>) -> Self {
        Self {
            asset,
            topoheight,
            data
        }
    }

    pub fn get_asset(&self) -> &Hash {
        &self.asset
    }

    pub fn get_data(&self) -> &AssetData {
        &self.data
    }

    pub fn consume(self) -> (Cow<'a, Hash>, TopoHeight, AssetData<'a>) {
        (self.asset, self.topoheight, self.data)
    }
}

impl<'a> Serializer for AssetWithData<'a> {
    fn write(&self, writer: &mut Writer) {
        self.asset.write(writer);
        self.topoheight.write(writer);
        self.data.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let asset = reader.read()?;
        let topoheight = reader.read()?;
        let data = reader.read()?;

        Ok(Self::new(asset, topoheight, data))
    }

    fn size(&self) -> usize {
        self.asset.size() + self.topoheight.size() + self.data.size()
    }
}

impl<'a> StdHash for AssetWithData<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.asset.hash(state);
    }
}

impl<'a> PartialEq for AssetWithData<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.asset == other.asset
    }
}

impl<'a> Eq for AssetWithData<'a> {}