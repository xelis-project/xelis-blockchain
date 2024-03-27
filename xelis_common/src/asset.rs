use std::hash::{Hash as StdHash, Hasher};
use crate::{
    serializer::{Serializer, Writer, Reader, ReaderError},
    crypto::Hash
};

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AssetData {
    // At which topoheight this asset is registered
    topoheight: u64,
    // How many atomic units is needed for a full coin
    decimals: u8,
}

impl AssetData {
    pub fn new(topoheight: u64, decimals: u8) -> Self {
        Self {
            topoheight,
            decimals
        }
    }

    pub fn get_topoheight(&self) -> u64 {
        self.topoheight
    }

    pub fn get_decimals(&self) -> u8 {
        self.decimals
    }
}

impl Serializer for AssetData {
    fn write(&self, writer: &mut Writer) {
        writer.write_u64(&self.topoheight);
        writer.write_u8(self.decimals);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(
            Self::new(reader.read_u64()?, reader.read_u8()?)
        )
    }

    fn size(&self) -> usize {
        self.topoheight.size() + self.decimals.size()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AssetWithData {
    asset: Hash,
    #[serde(flatten)]
    data: AssetData
}

impl AssetWithData {
    pub fn new(asset: Hash, data: AssetData) -> Self {
        Self {
            asset,
            data
        }
    }

    pub fn get_asset(&self) -> &Hash {
        &self.asset
    }

    pub fn get_data(&self) -> &AssetData {
        &self.data
    }

    pub fn to_asset(self) -> Hash {
        self.asset
    }

    pub fn consume(self) -> (Hash, AssetData) {
        (self.asset, self.data)
    }
}

impl Serializer for AssetWithData {
    fn write(&self, writer: &mut Writer) {
        self.asset.write(writer);
        self.data.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(
            Self::new(reader.read_hash()?, AssetData::read(reader)?)
        )
    }

    fn size(&self) -> usize {
        self.asset.size() + self.data.size()
    }
}

impl StdHash for AssetWithData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.asset.hash(state);
    }
}

impl PartialEq for AssetWithData {
    fn eq(&self, other: &Self) -> bool {
        self.asset == other.asset
    }
}

impl Eq for AssetWithData {}