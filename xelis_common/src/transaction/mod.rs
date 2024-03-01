use crate::{
    crypto::{
        elgamal::{CompressedCiphertext, CompressedCommitment, CompressedHandle, CompressedPublicKey},
        proofs::{CiphertextValidityProof, CommitmentEqProof},
        Hash,
        Hashable,
    },
    serializer::{Reader, ReaderError, Serializer, Writer}
};
use bulletproofs::RangeProof;
use log::debug;
use serde::{Deserialize, Serialize};

mod builder;
mod verify;

// Maximum size of payload per transfer
pub const EXTRA_DATA_LIMIT_SIZE: usize = 1024;
pub const MAX_TRANSFER_COUNT: usize = 255;

pub enum Role {
    Sender,
    Receiver,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SourceCommitment {
    commitment: CompressedCommitment,
    proof: CommitmentEqProof,
    asset: Hash,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransferPayload {
    asset: Hash,
    destination: CompressedPublicKey,
    // we can put whatever we want up to EXTRA_DATA_LIMIT_SIZE bytes
    extra_data: Option<Vec<u8>>,
    /// Represents the ciphertext along with `sender_handle` and `receiver_handle`.
    /// The opening is reused for both of the sender and receiver commitments.
    commitment: CompressedCommitment,
    sender_handle: CompressedHandle,
    receiver_handle: CompressedHandle,
    ct_validity_proof: CiphertextValidityProof,
}

// Burn is a public payload allowing to use it as a proof of burn
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BurnPayload {
    asset: Hash,
    amount: u64
}

// this enum represent all types of transaction available on XELIS Network
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransactionType {
    Transfers(Vec<TransferPayload>),
    Burn(BurnPayload),
}

// Compressed transaction to be sent over the network
// TODO add signature
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction {
    /// Version of the transaction
    version: u8,
    // Source of the transaction
    source: CompressedPublicKey,
    /// Type of the transaction
    data: TransactionType,
    /// Fees in XELIS
    fee: u64,
    /// nonce must be equal to the one on chain account
    /// used to prevent replay attacks and have ordered transactions
    nonce: u64,
    /// We have one source commitment and equality proof per asset used in the tx.
    source_commitments: Vec<SourceCommitment>,
    /// The range proof is aggregated across all transfers and across all assets.
    range_proof: RangeProof,
}

impl TransferPayload {
    pub fn get_ciphertext(&self, role: Role) -> CompressedCiphertext {
        let handle = match role {
            Role::Receiver => self.receiver_handle.clone(),
            Role::Sender => self.sender_handle.clone(),
        };

        CompressedCiphertext::new(self.commitment.clone(), handle)
    }
}

impl Transaction {
    pub fn new(source: CompressedPublicKey, data: TransactionType, fee: u64, nonce: u64, source_commitments: Vec<SourceCommitment>, range_proof: RangeProof) -> Self {
        Transaction {
            version: 0,
            source,
            data,
            fee,
            nonce,
            source_commitments,
            range_proof,
        }
    }

    pub fn get_version(&self) -> u8 {
        self.version
    }

    pub fn get_source(&self) -> &CompressedPublicKey {
        &self.source
    }

    pub fn get_data(&self) -> &TransactionType {
        &self.data
    }

    pub fn get_fee(&self) -> u64 {
        self.fee
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn consume(self) -> (CompressedPublicKey, TransactionType) {
        (self.source, self.data)
    }
}

impl Serializer for SourceCommitment {
    fn write(&self, writer: &mut Writer) {
        self.commitment.write(writer);
        self.proof.write(writer);
        self.asset.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<SourceCommitment, ReaderError> {
        let commitment = CompressedCommitment::read(reader)?;
        let proof = CommitmentEqProof::read(reader)?;
        let asset = Hash::read(reader)?;

        Ok(SourceCommitment {
            commitment,
            proof,
            asset
        })
    }

    fn size(&self) -> usize {
        self.commitment.size() + self.proof.size() + self.asset.size()
    }
}

impl Serializer for TransferPayload {
    fn write(&self, writer: &mut Writer) {
        self.asset.write(writer);
        self.destination.write(writer);
        writer.write_bool(self.extra_data.is_some());
        if let Some(extra_data) = &self.extra_data {
            writer.write_u16(extra_data.len() as u16);
            writer.write_bytes(extra_data);
        }
        self.commitment.write(writer);
        self.sender_handle.write(writer);
        self.receiver_handle.write(writer);
        self.ct_validity_proof.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<TransferPayload, ReaderError> {
        let asset = Hash::read(reader)?;
        let destination = CompressedPublicKey::read(reader)?;
        let has_extra_data = reader.read_bool()?;
        let extra_data = if has_extra_data {
            let extra_data_size = reader.read_u16()? as usize;
            if extra_data_size > EXTRA_DATA_LIMIT_SIZE {
                return Err(ReaderError::InvalidSize)
            }

            Some(reader.read_bytes(extra_data_size)?)
        } else {
            None
        };

        let commitment = CompressedCommitment::read(reader)?;
        let sender_handle = CompressedHandle::read(reader)?;
        let receiver_handle = CompressedHandle::read(reader)?;
        let ct_validity_proof = CiphertextValidityProof::read(reader)?;

        Ok(TransferPayload {
            asset,
            destination,
            extra_data,
            commitment,
            sender_handle,
            receiver_handle,
            ct_validity_proof
        })
    }

    fn size(&self) -> usize {
        // + 1 for the bool
        let mut size = self.asset.size() + self.destination.size() + 1 + self.commitment.size() + self.sender_handle.size() + self.receiver_handle.size();
        if let Some(extra_data) = &self.extra_data {
            // + 2 for the size of the extra data
            size += 2 + extra_data.len();
        }
        size
    }
}

impl Serializer for BurnPayload {
    fn write(&self, writer: &mut Writer) {
        self.asset.write(writer);
        self.amount.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<BurnPayload, ReaderError> {
        let asset = Hash::read(reader)?;
        let amount = reader.read_u64()?;
        Ok(BurnPayload {
            asset,
            amount
        })
    }

    fn size(&self) -> usize {
        self.asset.size() + self.amount.size()
    }
}

impl Serializer for TransactionType {
    fn write(&self, writer: &mut Writer) {
        match self {
            TransactionType::Burn(payload) => {
                writer.write_u8(0);
                payload.write(writer);
            }
            TransactionType::Transfers(txs) => {
                writer.write_u8(1);
                // max 255 txs per transaction
                let len: u8 = txs.len() as u8;
                writer.write_u8(len);
                for tx in txs {
                    tx.write(writer);
                }
            }
        };
    }

    fn read(reader: &mut Reader) -> Result<TransactionType, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => {
                let payload = BurnPayload::read(reader)?;
                TransactionType::Burn(payload)
            },
            1 => {
                let txs_count = reader.read_u8()?;
                if txs_count == 0 || txs_count > MAX_TRANSFER_COUNT as u8 {
                    return Err(ReaderError::InvalidSize)
                }

                let mut txs = Vec::with_capacity(txs_count as usize);
                for _ in 0..txs_count {
                    txs.push(TransferPayload::read(reader)?);
                }
                TransactionType::Transfers(txs)
            },
            _ => {
                return Err(ReaderError::InvalidValue)
            }
        })
    }

    fn size(&self) -> usize {
        match self {
            TransactionType::Burn(payload) => {
                1 + payload.size()
            },
            TransactionType::Transfers(txs) => {
                let mut size = 1;
                for tx in txs {
                    size += tx.size();
                }
                size
            }
        }
    }
}

impl Serializer for Transaction {
    fn write(&self, writer: &mut Writer) {
        writer.write_u8(self.version);
        self.source.write(writer);
        self.data.write(writer);
        writer.write_u64(&self.fee);
        writer.write_u64(&self.nonce);
        self.range_proof.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Transaction, ReaderError> {
        let version = reader.read_u8()?;
        // At this moment we only support version 0, so we check it here directly
        if version != 0 {
            debug!("Expected version 0 got version {version}");
            return Err(ReaderError::InvalidValue)
        }

        let source = CompressedPublicKey::read(reader)?;
        let data = TransactionType::read(reader)?;
        let fee = reader.read_u64()?;
        let nonce = reader.read_u64()?;
        let range_proof = RangeProof::read(reader)?;
        // let signature = Signature::read(reader)?;

        Ok(Transaction {
            version,
            source,
            data,
            fee,
            nonce,
            source_commitments: Vec::new(),
            range_proof,
            // signature
        })
    }

    fn size(&self) -> usize {
        1 + self.source.size() + self.data.size() + self.fee.size() + self.nonce.size() // + self.signature.size()
    }
}

impl Hashable for Transaction {}

impl AsRef<Transaction> for Transaction {
    fn as_ref(&self) -> &Transaction {
        self
    }
}