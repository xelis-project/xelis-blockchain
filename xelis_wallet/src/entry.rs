use serde::Serialize;
use xelis_common::{
    api::DataElement, config::XELIS_ASSET, crypto::{
        Hash,
        PublicKey
    }, serializer::{
        Reader, ReaderError, Serializer, Writer
    }, utils::{format_coin, format_xelis}
};
use anyhow::Result;
use crate::storage::EncryptedStorage;

#[derive(Debug, Serialize, Clone)]
pub struct Transfer {
    key: PublicKey,
    asset: Hash,
    amount: u64,
    // raw (plain text) extra data if build by this wallet
    extra_data: Option<DataElement>
}

impl Transfer {
    pub fn new(key: PublicKey, asset: Hash, amount: u64, extra_data: Option<DataElement>) -> Self {
        Self {
            key,
            asset,
            amount,
            extra_data
        }
    }

    pub fn get_key(&self) -> &PublicKey {
        &self.key
    }

    pub fn get_asset(&self) -> &Hash {
        &self.asset
    }

    pub fn get_amount(&self) -> u64 {
        self.amount
    }

    pub fn get_extra_data(&self) -> &Option<DataElement> {
        &self.extra_data
    }
}

impl Serializer for Transfer {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let key = PublicKey::read(reader)?;
        let asset = reader.read_hash()?;
        let amount = reader.read_u64()?;

        let extra_data = Option::read(reader)?;

        Ok(Self {
            key,
            asset,
            amount,
            extra_data
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.key.write(writer);
        writer.write_hash(&self.asset);
        writer.write_u64(&self.amount);

        self.extra_data.write(writer);
    }

    fn size(&self) -> usize {
        self.key.size() + self.asset.size() + self.amount.size() + self.extra_data.size()
    }
}

// TODO support SC call / SC Deploy
#[derive(Debug, Serialize, Clone)]
pub enum EntryData {
    #[serde(rename = "coinbase")]
    Coinbase { reward: u64 }, // Coinbase is only XELIS_ASSET
    #[serde(rename = "burn")]
    Burn {
        asset: Hash,
        amount: u64
    },
    #[serde(rename = "incoming")]
    Incoming { from: PublicKey, transfers: Vec<Transfer> },
    #[serde(rename = "outgoing")]
    Outgoing { transfers: Vec<Transfer> }
}

impl Serializer for EntryData {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = reader.read_u8()?;
        Ok(match id  {
            0 => Self::Coinbase { reward: reader.read_u64()? },
            1 => Self::Burn {
                asset: reader.read_hash()?,
                amount: reader.read_u64()?
            },
            2 => {
                let key = PublicKey::read(reader)?;
                let size = reader.read_u16()? as usize;
                let mut transfers = Vec::new();
                for _ in 0..size {
                    let transfer = Transfer::read(reader)?;
                    transfers.push(transfer);
                }
                Self::Incoming { from: key, transfers }
            }
            3 => {
                let size = reader.read_u16()? as usize;
                let mut transfers = Vec::new();
                for _ in 0..size {
                    let transfer = Transfer::read(reader)?;
                    transfers.push(transfer);
                }
                Self::Outgoing { transfers }
            }
            _ => return Err(ReaderError::InvalidValue)
        }) 
    }

    fn write(&self, writer: &mut Writer) {
        match &self {
            Self::Coinbase{ reward } => {
                writer.write_u8(0);
                writer.write_u64(reward);
            },
            Self::Burn { asset, amount } => {
                writer.write_u8(1);
                writer.write_hash(asset);
                writer.write_u64(amount);
            },
            Self::Incoming { from, transfers } => {
                writer.write_u8(2);
                from.write(writer);
                writer.write_u16(transfers.len() as u16);
                for transfer in transfers {
                    transfer.write(writer);
                }
            },
            Self::Outgoing { transfers } => {
                writer.write_u8(3);
                writer.write_u16(transfers.len() as u16);
                for transfer in transfers {
                    transfer.write(writer);
                }
            }
        }
    }

    fn size(&self) -> usize {
        1 + match &self {
            Self::Coinbase { reward } => reward.size(),
            Self::Burn { asset, amount } => asset.size() + amount.size(),
            Self::Incoming { from, transfers } => {
                from.size() + 2 + transfers.iter().map(|t| t.size()).sum::<usize>()
            },
            Self::Outgoing { transfers } => {
                2 + transfers.iter().map(|t| t.size()).sum::<usize>()
            }
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct TransactionEntry {
    hash: Hash,
    topoheight: u64,
    #[serde(skip_serializing_if="Option::is_none")]
    fee: Option<u64>,
    #[serde(skip_serializing_if="Option::is_none")]
    nonce: Option<u64>,
    #[serde(flatten)]
    entry: EntryData,
}

impl TransactionEntry {
    pub fn new(hash: Hash, topoheight: u64, fee: Option<u64>, nonce: Option<u64>, entry: EntryData) -> Self {
        Self {
            hash,
            topoheight,
            fee,
            nonce,
            entry,
        }
    }

    pub fn get_hash(&self) -> &Hash {
        &self.hash
    }

    pub fn get_topoheight(&self) -> u64 {
        self.topoheight
    }

    pub fn get_fee(&self) -> Option<u64> {
        self.fee
    }

    pub fn get_nonce(&self) -> Option<u64> {
        self.nonce
    }

    pub fn get_entry(&self) -> &EntryData {
        &self.entry
    }

    pub fn get_mut_entry(&mut self) -> &mut EntryData {
        &mut self.entry
    }

    pub fn summary(&self, mainnet: bool, storage: &EncryptedStorage) -> Result<String> {
        let entry_str = match self.get_entry() {
            EntryData::Coinbase { reward } => format!("Coinbase {} XELIS", format_xelis(*reward)),
            EntryData::Burn { asset, amount } => {
                let decimals = storage.get_asset_decimals(asset)?;
                format!("Burn {} of {}", format_coin(*amount, decimals), asset)
            },
            EntryData::Incoming { from, transfers } => {
                let mut str = String::new();
                for transfer in transfers {
                    if *transfer.get_asset() == XELIS_ASSET {
                        str.push_str(&format!("Received {} XELIS from {}", format_xelis(transfer.get_amount()), from.clone().to_address(mainnet)));
                    } else {
                        let decimals = storage.get_asset_decimals(transfer.get_asset())?;
                        str.push_str(&format!("Received {} {} from {}", format_coin(transfer.get_amount(), decimals), transfer.get_asset(), from.clone().to_address(mainnet)));
                    }
                }
                str
            },
            EntryData::Outgoing { transfers } => {
                let mut str = String::new();
                for transfer in transfers {
                    if *transfer.get_asset() == XELIS_ASSET {
                        str.push_str(&format!("Sent {} XELIS to {}", format_xelis(transfer.get_amount()), transfer.get_key().clone().to_address(mainnet)));
                    } else {
                        let decimals = storage.get_asset_decimals(transfer.get_asset())?;
                        str.push_str(&format!("Sent {} {} to {}", format_coin(transfer.get_amount(), decimals), transfer.get_asset(), transfer.get_key().clone().to_address(mainnet)));
                    }
                }
                str
            }
        };

        Ok(if let (Some(fee), Some(nonce)) = (self.fee, self.nonce) {
            format!("Hash {} at TopoHeight {}, Nonce {}, Fee: {}, Data: {}", self.hash, self.topoheight, nonce, format_xelis(fee), entry_str)
        } else { // mostly coinbase
            format!("Hash {} at TopoHeight {}: {}", self.hash, self.topoheight, entry_str)
        })
    }
}

impl Serializer for TransactionEntry {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let hash = reader.read_hash()?;
        let topoheight = reader.read_u64()?;
        let fee = Option::read(reader)?;
        let nonce = Option::read(reader)?;
        let entry = EntryData::read(reader)?;

        Ok(Self {
            hash,
            topoheight,
            fee,
            nonce,
            entry
        })
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.hash);
        writer.write_u64(&self.topoheight);

        self.fee.write(writer);
        self.nonce.write(writer);
        self.entry.write(writer);
    }

    fn size(&self) -> usize {
        self.hash.size() + self.topoheight.size() + self.fee.size() + self.nonce.size() + self.entry.size()
    }
}
