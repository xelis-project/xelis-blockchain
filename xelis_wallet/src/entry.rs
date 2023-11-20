use std::fmt::{self, Display, Formatter};

use serde::Serialize;
use xelis_common::{crypto::{hash::Hash, key::PublicKey}, serializer::{Serializer, ReaderError, Reader, Writer}, utils::format_xelis, api::DataElement};

#[derive(Serialize, Clone)]
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
}

// TODO support SC call / SC Deploy
#[derive(Serialize, Clone)]
pub enum EntryData {
    #[serde(rename = "coinbase")]
    Coinbase(u64), // Coinbase is only XELIS_ASSET
    #[serde(rename = "burn")]
    Burn {
        asset: Hash,
        amount: u64
    },
    #[serde(rename = "incoming")]
    Incoming(PublicKey, Vec<Transfer>),
    #[serde(rename = "outgoing")]
    Outgoing(Vec<Transfer>)
}

impl Serializer for EntryData {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = reader.read_u8()?;
        Ok(match id  {
            0 => Self::Coinbase(reader.read_u64()?),
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
                Self::Incoming(key, transfers)
            }
            3 => {
                let size = reader.read_u16()? as usize;
                let mut transfers = Vec::new();
                for _ in 0..size {
                    let transfer = Transfer::read(reader)?;
                    transfers.push(transfer);
                }
                Self::Outgoing(transfers)
            }
            _ => return Err(ReaderError::InvalidValue)
        }) 
    }

    fn write(&self, writer: &mut Writer) {
        match &self {
            Self::Coinbase(amount) => {
                writer.write_u8(0);
                writer.write_u64(amount);
            },
            Self::Burn { asset, amount } => {
                writer.write_u8(1);
                writer.write_hash(asset);
                writer.write_u64(amount);
            },
            Self::Incoming(key, transfers) => {
                writer.write_u8(2);
                key.write(writer);
                writer.write_u16(transfers.len() as u16);
                for transfer in transfers {
                    transfer.write(writer);
                }
            },
            Self::Outgoing(transfers) => {
                writer.write_u8(3);
                writer.write_u16(transfers.len() as u16);
                for transfer in transfers {
                    transfer.write(writer);
                }
            }
        }
    }
}

#[derive(Serialize, Clone)]
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
}

// TODO display values with correct decimals from asset
impl Display for TransactionEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let entry_str = match self.get_entry() {
            EntryData::Coinbase(reward) => format!("Coinbase {} XELIS", format_xelis(*reward)),
            EntryData::Burn { asset, amount } => format!("Burn {} of {}", amount, asset),
            EntryData::Incoming(sender, txs) => {
                if txs.len() == 1 {
                    format!("Received from {} {} {}", sender, format_xelis(txs[0].amount), txs[0].asset)
                } else {
                    format!("Incoming from {} {} transfers", sender, txs.len())
                }
            },
            EntryData::Outgoing(txs) => {
                if txs.len() == 1 {
                    format!("Sent to {} {} {}", txs[0].key, format_xelis(txs[0].amount), txs[0].asset)
                } else {
                    format!("{} differents transfers", txs.len())
                }
            }
        };

        if let (Some(fee), Some(nonce)) = (self.fee, self.nonce) {
            write!(f, "Hash {} at TopoHeight {}, Nonce {}, Fee: {}, Data: {}", self.hash, self.topoheight, nonce, format_xelis(fee), entry_str)
        } else { // mostly coinbase
            write!(f, "Hash {} at TopoHeight {}: {}", self.hash, self.topoheight, entry_str)
        }
    }
}