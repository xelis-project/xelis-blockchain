use indexmap::{IndexMap, IndexSet};
use xelis_common::{
    time::TimestampMillis,
    api::wallet::{
        TransactionEntry as RPCTransactionEntry,
        EntryType as RPCEntryType,
        TransferIn as RPCTransferIn,
        TransferOut as RPCTransferOut
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
    transaction::extra_data::PlaintextExtraData,
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
    extra_data: Option<PlaintextExtraData>
}

#[derive(Debug, Clone)]
pub struct TransferIn {
    // Asset used
    asset: Hash,
    // Amount spent
    amount: u64,
    // Extra data with good format
    extra_data: Option<PlaintextExtraData>
}

impl TransferOut {
    pub fn new(destination: PublicKey, asset: Hash, amount: u64, extra_data: Option<PlaintextExtraData>) -> Self {
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

    pub fn get_extra_data(&self) -> &Option<PlaintextExtraData> {
        &self.extra_data
    }
}


impl TransferIn {
    pub fn new(asset: Hash, amount: u64, extra_data: Option<PlaintextExtraData>) -> Self {
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

    pub fn get_extra_data(&self) -> &Option<PlaintextExtraData> {
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
        // Burned asset
        asset: Hash,
        // Burned amount
        amount: u64,
        // Fee paid
        fee: u64,
        // Nonce used by the TX
        nonce: u64
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
    },
    MultiSig {
        // Public keys
        participants: IndexSet<PublicKey>,
        // Required signatures
        threshold: u8,
        // Fee paid for the TX
        fee: u64,
        // Nonce used
        nonce: u64,
    },
    InvokeContract {
        // Contract address
        contract: Hash,
        // Deposits made
        deposits: IndexMap<Hash, u64>,
        // Chunk id invoked
        chunk_id: u16,
        // Fee paid
        fee: u64,
        // Nonce used
        nonce: u64
    },
    DeployContract {
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
                amount: reader.read_u64()?,
                fee: reader.read_u64()?,
                nonce: reader.read_u64()?
            },
            2 => {
                let key = PublicKey::read(reader)?;
                let size = reader.read_u8()? as usize;
                let mut transfers = Vec::new();
                for _ in 0..size {
                    let transfer = TransferIn::read(reader)?;
                    transfers.push(transfer);
                }
                Self::Incoming { from: key, transfers }
            }
            3 => {
                let size = reader.read_u8()? as usize;
                let mut transfers = Vec::new();
                for _ in 0..size {
                    let transfer = TransferOut::read(reader)?;
                    transfers.push(transfer);
                }
                let fee = reader.read_u64()?;
                let nonce = reader.read_u64()?;

                Self::Outgoing { transfers, fee, nonce }
            }
            4 => {
                let size = reader.read_u8()? as usize;
                let mut participants = IndexSet::new();
                for _ in 0..size {
                    let key = PublicKey::read(reader)?;
                    participants.insert(key);
                }
                let threshold = reader.read_u8()?;
                let fee = reader.read_u64()?;
                let nonce = reader.read_u64()?;
                Self::MultiSig { participants, threshold, fee, nonce }
            },
            5 => {
                let contract = reader.read_hash()?;
                let chunk_id = reader.read_u16()?;
                let deposits_size = reader.read_u8()? as usize;
                let mut deposits = IndexMap::new();
                for _ in 0..deposits_size {
                    let asset = reader.read_hash()?;
                    let amount = reader.read_u64()?;
                    deposits.insert(asset, amount);
                }

                let fee = reader.read_u64()?;
                let nonce = reader.read_u64()?;
                Self::InvokeContract { contract, deposits, chunk_id, fee, nonce }
            },
            6 => {
                let fee = reader.read_u64()?;
                let nonce = reader.read_u64()?;
                Self::DeployContract { fee, nonce }
            }
            _ => return Err(ReaderError::InvalidValue)
        }) 
    }

    fn write(&self, writer: &mut Writer) {
        match &self {
            Self::Coinbase { reward } => {
                writer.write_u8(0);
                writer.write_u64(reward);
            },
            Self::Burn { asset, amount, fee, nonce } => {
                writer.write_u8(1);
                writer.write_hash(asset);
                writer.write_u64(amount);
                writer.write_u64(fee);
                writer.write_u64(nonce);
            },
            Self::Incoming { from, transfers } => {
                writer.write_u8(2);
                from.write(writer);
                // Transfers are maximum 255, so we can use u8
                writer.write_u8(transfers.len() as u8);
                for transfer in transfers {
                    transfer.write(writer);
                }
            },
            Self::Outgoing { transfers, fee, nonce } => {
                writer.write_u8(3);
                // Max 255 transfers per TX, so we can use u8
                writer.write_u8(transfers.len() as u8);
                for transfer in transfers {
                    transfer.write(writer);
                }
                writer.write_u64(fee);
                writer.write_u64(nonce);
            },
            Self::MultiSig { participants: keys, threshold, fee, nonce } => {
                writer.write_u8(4);
                writer.write_u8(keys.len() as u8);
                for key in keys {
                    key.write(writer);
                }
                writer.write_u8(*threshold);
                writer.write_u64(fee);
                writer.write_u64(nonce);
            },
            Self::InvokeContract { contract, deposits, chunk_id, fee, nonce } => {
                writer.write_u8(5);
                writer.write_hash(contract);
                writer.write_u16(*chunk_id);
                writer.write_u8(deposits.len() as u8);
                for (asset, amount) in deposits {
                    asset.write(writer);
                    amount.write(writer);
                }

                writer.write_u64(fee);
                writer.write_u64(nonce);
            },
            Self::DeployContract { fee, nonce } => {
                writer.write_u8(6);
                writer.write_u64(fee);
                writer.write_u64(nonce);
            }
        }
    }

    fn size(&self) -> usize {
        1 + match &self {
            Self::Coinbase { reward } => reward.size(),
            Self::Burn { asset, amount, fee, nonce } => asset.size() + amount.size() + fee.size() + nonce.size(),
            Self::Incoming { from, transfers } => {
                from.size() + 1 + transfers.iter().map(|t| t.size()).sum::<usize>()
            },
            Self::Outgoing { transfers, fee, nonce } => {
                1 + transfers.iter().map(|t| t.size()).sum::<usize>() + fee.size() + nonce.size()
            },
            Self::MultiSig { participants, threshold, fee, nonce } => {
                1 + participants.iter().map(|k| k.size()).sum::<usize>() + threshold.size() + fee.size() + nonce.size()
            },
            Self::InvokeContract { contract, deposits, chunk_id, fee, nonce } => {
                contract.size() + 2 + deposits.iter().map(|(a, b)| a.size() + b.size()).sum::<usize>() + chunk_id.size() + fee.size() + nonce.size()
            },
            Self::DeployContract { fee, nonce } => {
                fee.size() + nonce.size()
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransactionEntry {
    // Transaction hash
    hash: Hash,
    // Block topoheight
    topoheight: u64,
    // Block timestamp
    timestamp: TimestampMillis,
    // Entry data of the transaction
    entry: EntryData,
}

impl TransactionEntry {
    // Create a new transaction entry
    pub const fn new(hash: Hash, topoheight: u64, timestamp: TimestampMillis, entry: EntryData) -> Self {
        Self {
            hash,
            topoheight,
            timestamp,
            entry,
        }
    }

    // Get the hash of the transaction
    pub fn get_hash(&self) -> &Hash {
        &self.hash
    }

    // Get the topoheight at which the transaction was executed
    pub fn get_topoheight(&self) -> u64 {
        self.topoheight
    }

    // Get the timestamp of the block
    pub fn get_timestamp(&self) -> u64 {
        self.timestamp
    }

    // Get the entry data of the transaction
    pub fn get_entry(&self) -> &EntryData {
        &self.entry
    }

    // Get the mutable entry data of the transaction
    pub fn get_mut_entry(&mut self) -> &mut EntryData {
        &mut self.entry
    }

    // Is the transaction created by us
    pub fn is_outgoing(&self) -> bool {
        match &self.entry {
            EntryData::Burn { .. } => true,
            EntryData::Outgoing { .. } => true,
            EntryData::MultiSig { .. } => true,
            _ => false,
        }
    }

    // Convert to RPC Transaction Entry
    // This is a necessary step to serialize correctly the public key into an address
    pub fn serializable(self, mainnet: bool) -> RPCTransactionEntry {
        RPCTransactionEntry {
            hash: self.hash,
            topoheight: self.topoheight,
            timestamp: self.timestamp,
            entry: match self.entry {
                EntryData::Coinbase { reward } => RPCEntryType::Coinbase { reward },
                EntryData::Burn { asset, amount, fee, nonce } => RPCEntryType::Burn { asset, amount, fee, nonce },
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
                },
                EntryData::MultiSig { participants, threshold, fee, nonce } => {
                    let participants = participants.into_iter().map(|p| p.to_address(mainnet)).collect();
                    RPCEntryType::MultiSig { participants, threshold, fee, nonce }
                },
                EntryData::InvokeContract { contract, deposits, chunk_id, fee, nonce } => {
                    RPCEntryType::InvokeContract { contract, deposits, chunk_id, fee, nonce }
                },
                EntryData::DeployContract { fee, nonce } => {
                    RPCEntryType::DeployContract { fee, nonce }
                }
            }
        }
    }

    pub async fn summary(&self, mainnet: bool, storage: &EncryptedStorage) -> Result<String> {
        let entry_str = match self.get_entry() {
            EntryData::Coinbase { reward } => format!("Coinbase {} XELIS", format_xelis(*reward)),
            EntryData::Burn { asset, amount, fee, nonce } => {
                let data = storage.get_asset(asset).await?;
                format!("Fee: {}, Nonce: {} Burn {} of {}", format_xelis(*fee), nonce, format_coin(*amount, data.get_decimals()), asset)
            },
            EntryData::Incoming { from, transfers } => {
                let mut str = String::new();
                for transfer in transfers {
                    if *transfer.get_asset() == XELIS_ASSET {
                        str.push_str(&format!("Received {} XELIS from {}", format_xelis(transfer.get_amount()), from.as_address(mainnet)));
                    } else {
                        let data = storage.get_asset(transfer.get_asset()).await?;
                        str.push_str(&format!("Received {} {} from {}", format_coin(transfer.get_amount(), data.get_decimals()), transfer.get_asset(), from.as_address(mainnet)));
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
                        let data = storage.get_asset(transfer.get_asset()).await?;
                        str.push_str(&format!("Sent {} {} to {}", format_coin(transfer.get_amount(), data.get_decimals()), transfer.get_asset(), transfer.get_destination().as_address(mainnet)));
                    }
                }
                str
            },
            EntryData::MultiSig { participants, threshold, fee, nonce } => {
                let mut str = format!("Fee: {}, Nonce: {} ", format_xelis(*fee), nonce);
                str.push_str(&format!("MultiSig setup with threshold {} and {} participants", threshold, participants.len()));
                for participant in participants {
                    str.push_str(&format!("{}", participant.as_address(mainnet)));
                }
                str
            },
            EntryData::InvokeContract { contract, deposits, chunk_id, fee, nonce } => {
                let mut str = format!("Fee: {}, Nonce: {} ", format_xelis(*fee), nonce);
                str.push_str(&format!("Invoke contract {} with chunk id {}", contract, chunk_id));
                for (asset, amount) in deposits {
                    let data = storage.get_asset(&asset).await?;
                    str.push_str(&format!("Deposit {} {} to contract", format_coin(*amount, data.get_decimals()), asset));
                }
                str
            },
            EntryData::DeployContract { fee, nonce } => {
                format!("Fee: {}, Nonce: {} Deploy contract", format_xelis(*fee), nonce)
            }
        };

        Ok(format!("Hash {} at TopoHeight {}: {}", self.hash, self.topoheight, entry_str))
    }
}

impl Serializer for TransactionEntry {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let hash = reader.read_hash()?;
        let topoheight = reader.read_u64()?;
        let timestamp = reader.read_u64()?;
        let entry = EntryData::read(reader)?;

        Ok(Self::new(
            hash,
            topoheight,
            timestamp,
            entry
        ))
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.hash);
        writer.write_u64(&self.topoheight);
        writer.write_u64(&self.timestamp);
        self.entry.write(writer);
    }

    fn size(&self) -> usize {
        self.hash.size() + self.topoheight.size() + self.entry.size()
    }
}

#[derive(Debug)]
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

    pub fn get_extra_data(&self) -> &Option<PlaintextExtraData> {
        match self {
            Transfer::In(t) => &t.extra_data,
            Transfer::Out(t) => &t.extra_data
        }
    }
}
