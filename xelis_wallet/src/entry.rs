use xelis_common::{
    api::{
        DataElement,
        wallet::{
            TransactionEntry as RPCTransactionEntry,
            EntryType as RPCEntryType,
            TransferIn as RPCTransferIn,
            TransferOut as RPCTransferOut
        }
    },
    config::XELIS_ASSET,
    crypto::{
        Hash,
        PublicKey
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    },
    utils::{
        format_coin,
        format_xelis
    }
};
use anyhow::Result;
use crate::storage::EncryptedStorage;

#[derive(Debug, Clone)]
pub struct TransferOut {
    // Destination key
    destination: PublicKey,
    // Asset used
    asset: Hash,
    // Amount spent
    amount: u64,
    // Extra data with good format
    extra_data: Option<DataElement>
}

#[derive(Debug, Clone)]
pub struct TransferIn {
    // Asset used
    asset: Hash,
    // Amount spent
    amount: u64,
    // Extra data with good format
    extra_data: Option<DataElement>
}

impl TransferOut {
    pub fn new(destination: PublicKey, asset: Hash, amount: u64, extra_data: Option<DataElement>) -> Self {
        Self {
            destination,
            asset,
            amount,
            extra_data
        }
    }

    pub fn get_destination(&self) -> &PublicKey {
        &self.destination
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


impl TransferIn {
    pub fn new(asset: Hash, amount: u64, extra_data: Option<DataElement>) -> Self {
        Self {
            asset,
            amount,
            extra_data
        }
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

impl Serializer for TransferOut {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let destination = PublicKey::read(reader)?;
        let asset = reader.read_hash()?;
        let amount = reader.read_u64()?;

        let extra_data = Option::read(reader)?;

        Ok(Self {
            destination,
            asset,
            amount,
            extra_data
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.destination.write(writer);
        writer.write_hash(&self.asset);
        writer.write_u64(&self.amount);

        self.extra_data.write(writer);
    }

    fn size(&self) -> usize {
        self.destination.size() + self.asset.size() + self.amount.size() + self.extra_data.size()
    }
}

impl Serializer for TransferIn {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let asset = reader.read_hash()?;
        let amount = reader.read_u64()?;

        let extra_data = Option::read(reader)?;

        Ok(Self {
            asset,
            amount,
            extra_data
        })
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.asset);
        writer.write_u64(&self.amount);

        self.extra_data.write(writer);
    }

    fn size(&self) -> usize {
        self.asset.size() + self.amount.size() + self.extra_data.size()
    }
}

#[derive(Debug, Clone)]
pub enum EntryData {
    // Coinbase is only XELIS_ASSET
    Coinbase {
        reward: u64
    },
    Burn {
        asset: Hash,
        amount: u64
    },
    Incoming {
        from: PublicKey,
        transfers: Vec<TransferIn>
    },
    Outgoing {
        transfers: Vec<TransferOut>,
        // Fee paid
        fee: u64,
        // Nonce used
        nonce: u64
    }
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
                    let transfer = TransferIn::read(reader)?;
                    transfers.push(transfer);
                }
                Self::Incoming { from: key, transfers }
            }
            3 => {
                let size = reader.read_u16()? as usize;
                let mut transfers = Vec::new();
                for _ in 0..size {
                    let transfer = TransferOut::read(reader)?;
                    transfers.push(transfer);
                }
                let fee = reader.read_u64()?;
                let nonce = reader.read_u64()?;

                Self::Outgoing { transfers, fee, nonce }
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
            Self::Outgoing { transfers, fee, nonce } => {
                writer.write_u8(3);
                writer.write_u16(transfers.len() as u16);
                for transfer in transfers {
                    transfer.write(writer);
                }
                writer.write_u64(fee);
                writer.write_u64(nonce);
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
            Self::Outgoing { transfers, fee, nonce } => {
                2 + transfers.iter().map(|t| t.size()).sum::<usize>() + fee.size() + nonce.size()
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransactionEntry {
    hash: Hash,
    topoheight: u64,
    entry: EntryData,
}

impl TransactionEntry {
    pub fn new(hash: Hash, topoheight: u64, entry: EntryData) -> Self {
        Self {
            hash,
            topoheight,
            entry,
        }
    }

    pub fn get_hash(&self) -> &Hash {
        &self.hash
    }

    pub fn get_topoheight(&self) -> u64 {
        self.topoheight
    }

    pub fn get_entry(&self) -> &EntryData {
        &self.entry
    }

    pub fn get_mut_entry(&mut self) -> &mut EntryData {
        &mut self.entry
    }

    // Convert to RPC Transaction Entry
    // This is a necessary step to serialize correctly the public key into an address
    pub fn serializable(self, mainnet: bool) -> RPCTransactionEntry {
        RPCTransactionEntry {
            hash: self.hash,
            topoheight: self.topoheight,
            entry: match self.entry {
                EntryData::Coinbase { reward } => RPCEntryType::Coinbase { reward },
                EntryData::Burn { asset, amount } => RPCEntryType::Burn { asset, amount },
                EntryData::Incoming { from, transfers } => {
                    let transfers = transfers.into_iter().map(|t| RPCTransferIn {
                        asset: t.asset,
                        amount: t.amount,
                        extra_data: t.extra_data
                    }).collect();
                    RPCEntryType::Incoming { from: from.to_address(mainnet), transfers }
                },
                EntryData::Outgoing { transfers, fee, nonce } => {
                    let transfers = transfers.into_iter().map(|t| RPCTransferOut {
                        destination: t.destination.to_address(mainnet),
                        asset: t.asset,
                        amount: t.amount,
                        extra_data: t.extra_data
                    }).collect();
                    RPCEntryType::Outgoing { transfers, fee, nonce }
                }
            }
        }
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
                        str.push_str(&format!("Received {} XELIS from {}", format_xelis(transfer.get_amount()), from.as_address(mainnet)));
                    } else {
                        let decimals = storage.get_asset_decimals(transfer.get_asset())?;
                        str.push_str(&format!("Received {} {} from {}", format_coin(transfer.get_amount(), decimals), transfer.get_asset(), from.as_address(mainnet)));
                    }
                }
                str
            },
            EntryData::Outgoing { transfers, fee, nonce } => {
                let mut str = format!("Fee: {}, Nonce: {} ", format_xelis(*fee), nonce);
                for transfer in transfers {
                    if *transfer.get_asset() == XELIS_ASSET {
                        str.push_str(&format!("Sent {} XELIS to {}", format_xelis(transfer.get_amount()), transfer.get_destination().as_address(mainnet)));
                    } else {
                        let decimals = storage.get_asset_decimals(transfer.get_asset())?;
                        str.push_str(&format!("Sent {} {} to {}", format_coin(transfer.get_amount(), decimals), transfer.get_asset(), transfer.get_destination().as_address(mainnet)));
                    }
                }
                str
            }
        };

        Ok(format!("Hash {} at TopoHeight {}: {}", self.hash, self.topoheight, entry_str))
    }
}

impl Serializer for TransactionEntry {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let hash = reader.read_hash()?;
        let topoheight = reader.read_u64()?;
        let entry = EntryData::read(reader)?;

        Ok(Self {
            hash,
            topoheight,
            entry
        })
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.hash);
        writer.write_u64(&self.topoheight);
        self.entry.write(writer);
    }

    fn size(&self) -> usize {
        self.hash.size() + self.topoheight.size() + self.entry.size()
    }
}


pub enum Transfer<'a> {
    In(&'a mut TransferIn),
    Out(&'a mut TransferOut)
}

impl<'a> Transfer<'a> {
    pub fn get_asset(&self) -> &Hash {
        match self {
            Transfer::In(t) => &t.asset,
            Transfer::Out(t) => &t.asset
        }
    }

    pub fn get_amount(&self) -> u64 {
        match self {
            Transfer::In(t) => t.amount,
            Transfer::Out(t) => t.amount
        }
    }

    pub fn get_extra_data(&self) -> &Option<DataElement> {
        match self {
            Transfer::In(t) => &t.extra_data,
            Transfer::Out(t) => &t.extra_data
        }
    }
}
