use serde::{Deserialize, Serialize};
use xelis_vm::Module;
use crate::{
    account::Nonce,
    crypto::{
        elgamal::{
            CompressedCommitment,
            CompressedPublicKey
        },
        proofs::CommitmentEqProof,
        Hash,
        Hashable,
        Signature,
    },
    serializer::*
};

use bulletproofs::RangeProof;
use multisig::MultiSig;

pub mod builder;
pub mod verify;
pub mod extra_data;
pub mod multisig;
mod payload;

mod reference;
mod version;

pub use payload::*;
pub use reference::Reference;
pub use version::TxVersion;

#[cfg(test)]
mod tests;

// Maximum size of extra data per transfer
pub const EXTRA_DATA_LIMIT_SIZE: usize = 1024;
// Maximum total size of payload across all transfers per transaction
pub const EXTRA_DATA_LIMIT_SUM_SIZE: usize = EXTRA_DATA_LIMIT_SIZE * 32;
// Maximum number of transfers per transaction
pub const MAX_TRANSFER_COUNT: usize = 255;
// Maximum number of deposits per Invoke Call
pub const MAX_DEPOSIT_PER_INVOKE_CALL: usize = 255;
// Maximum number of participants in a multi signature account
pub const MAX_MULTISIG_PARTICIPANTS: usize = 255;

/// Simple enum to determine which DecryptHandle to use to craft a Ciphertext
/// This allows us to store one time the commitment and only a decrypt handle for each.
/// The DecryptHandle is used to decrypt the ciphertext and is selected based on the role in the transaction.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Sender,
    Receiver,
}

// SourceCommitment is a structure that holds the commitment and the equality proof
// of the commitment to the asset
// In a transaction, every spendings are summed up in a single commitment per asset
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SourceCommitment {
    commitment: CompressedCommitment,
    proof: CommitmentEqProof,
    asset: Hash,
}

impl SourceCommitment {
    /// Create a new SourceCommitment
    pub fn new(commitment: CompressedCommitment, proof: CommitmentEqProof, asset: Hash) -> Self {
        SourceCommitment {
            commitment,
            proof,
            asset
        }
    }

    // Get the commitment
    pub fn get_commitment(&self) -> &CompressedCommitment {
        &self.commitment
    }

    // Get the equality proof
    pub fn get_proof(&self) -> &CommitmentEqProof {
        &self.proof
    }

    // Get the asset hash
    pub fn get_asset(&self) -> &Hash {
        &self.asset
    }
}

// this enum represent all types of transaction available on XELIS Network
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransactionType {
    Transfers(Vec<TransferPayload>),
    Burn(BurnPayload),
    MultiSig(MultiSigPayload),
    InvokeContract(InvokeContractPayload),
    DeployContract(Module),
}

// Transaction to be sent over the network
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction {
    /// Version of the transaction
    version: TxVersion,
    // Source of the transaction
    source: CompressedPublicKey,
    /// Type of the transaction
    data: TransactionType,
    /// Fees in XELIS
    fee: u64,
    /// nonce must be equal to the one on chain account
    /// used to prevent replay attacks and have ordered transactions
    nonce: Nonce,
    /// We have one source commitment and equality proof per asset used in the tx.
    source_commitments: Vec<SourceCommitment>,
    /// The range proof is aggregated across all transfers and across all assets.
    range_proof: RangeProof,
    /// At which block the TX is built
    reference: Reference,
    /// MultiSig contains the signatures of the transaction
    /// Only available since V1
    multisig: Option<MultiSig>,
    /// The signature of the source key
    signature: Signature,
}

impl Transaction {
    // Create a new transaction
    #[inline(always)]
    pub fn new(
        version: TxVersion,
        source: CompressedPublicKey,
        data: TransactionType,
        fee: u64,
        nonce: Nonce,
        source_commitments: Vec<SourceCommitment>,
        range_proof: RangeProof,
        reference: Reference,
        multisig: Option<MultiSig>,
        signature: Signature
    ) -> Self {
        Self {
            version,
            source,
            data,
            fee,
            nonce,
            source_commitments,
            range_proof,
            reference,
            multisig,
            signature,
        }
    }

    // Get the transaction version
    pub fn get_version(&self) -> TxVersion {
        self.version
    }

    // Get the source key
    pub fn get_source(&self) -> &CompressedPublicKey {
        &self.source
    }

    // Get the transaction type
    pub fn get_data(&self) -> &TransactionType {
        &self.data
    }

    // Get fees paid to miners
    pub fn get_fee(&self) -> u64 {
        self.fee
    }

    // Get the nonce used
    pub fn get_nonce(&self) -> Nonce {
        self.nonce
    }

    // Get the source commitments
    pub fn get_source_commitments(&self) -> &Vec<SourceCommitment> {
        &self.source_commitments
    }

    // Get the used assets
    pub fn get_assets(&self) -> impl Iterator<Item = &Hash> {
        self.source_commitments.iter().map(|c| &c.asset)
    }

    // Get the range proof
    pub fn get_range_proof(&self) -> &RangeProof {
        &self.range_proof
    }

    // Get the multisig
    pub fn get_multisig(&self) -> &Option<MultiSig> {
        &self.multisig
    }

    // Get the count of signatures in a multisig transaction
    pub fn get_multisig_count(&self) -> usize {
        self.multisig.as_ref().map(|m| m.len()).unwrap_or(0)
    }

    // Get the signature of source key
    pub fn get_signature(&self) -> &Signature {
        &self.signature
    }

    // Get the block reference to determine which block the transaction is built
    pub fn get_reference(&self) -> &Reference {
        &self.reference
    }

    // Get the burned amount
    // This will returns the burned amount by a Burn payload
    // Or the % of execution fees to burn due to a Smart Contracts call
    // only if the asset is XELIS
    pub fn get_burned_amount(&self, asset: &Hash) -> Option<u64> {
        match &self.data {
            TransactionType::Burn(payload) if payload.asset == *asset => Some(payload.amount),
            _ => None
        }
    }

    // Get the total outputs count per TX
    // default is 1
    // Transfers / Deposits are their own len
    pub fn get_outputs_count(&self) -> usize {
        match &self.data {
            TransactionType::Transfers(transfers) => transfers.len(),
            TransactionType::InvokeContract(payload) => payload.deposits.len().max(1),
            _ => 1
        }
    }

    // Consume the transaction by returning the source public key and the transaction type
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
            },
            TransactionType::MultiSig(payload) => {
                writer.write_u8(2);
                payload.write(writer);
            },
            TransactionType::InvokeContract(payload) => {
                writer.write_u8(3);
                payload.write(writer);
            },
            TransactionType::DeployContract(module) => {
                writer.write_u8(4);
                module.write(writer);
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
            2 => {
                let payload = MultiSigPayload::read(reader)?;
                TransactionType::MultiSig(payload)
            },
            3 => {
                let payload = InvokeContractPayload::read(reader)?;
                TransactionType::InvokeContract(payload)
            },
            4 => {
                let module = Module::read(reader)?;
                TransactionType::DeployContract(module)
            },
            _ => {
                return Err(ReaderError::InvalidValue)
            }
        })
    }

    fn size(&self) -> usize {
        1 + match self {
            TransactionType::Burn(payload) => payload.size(),
            TransactionType::Transfers(txs) => {
                // 1 byte for variant, 1 byte for count of transfers
                let mut size = 1;
                for tx in txs {
                    size += tx.size();
                }
                size
            },
            TransactionType::MultiSig(payload) => {
                // 1 byte for variant, 1 byte for threshold, 1 byte for count of participants
                1 + 1 + payload.participants.iter().map(|p| p.size()).sum::<usize>()
            },
            TransactionType::InvokeContract(payload) => payload.size(),
            TransactionType::DeployContract(module) => module.size(),
        }
    }
}

impl Serializer for Transaction {
    fn write(&self, writer: &mut Writer) {
        self.version.write(writer);
        self.source.write(writer);
        self.data.write(writer);
        self.fee.write(writer);
        self.nonce.write(writer);

        writer.write_u8(self.source_commitments.len() as u8);
        for commitment in &self.source_commitments {
            commitment.write(writer);
        }

        self.range_proof.write(writer);
        self.reference.write(writer);

        if self.version != TxVersion::V0 {
            self.multisig.write(writer);
        }

        self.signature.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Transaction, ReaderError> {
        let version = TxVersion::read(reader)?;

        reader.context_mut()
            .store(version);

        let source = CompressedPublicKey::read(reader)?;
        let data = TransactionType::read(reader)?;
        let fee = reader.read_u64()?;
        let nonce = Nonce::read(reader)?;

        let commitments_len = reader.read_u8()?;
        if commitments_len == 0 || commitments_len > MAX_TRANSFER_COUNT as u8 {
            return Err(ReaderError::InvalidSize)
        }

        let mut source_commitments = Vec::with_capacity(commitments_len as usize);
        for _ in 0..commitments_len {
            source_commitments.push(SourceCommitment::read(reader)?);
        }

        let range_proof = RangeProof::read(reader)?;
        let reference = Reference::read(reader)?;
        let multisig = if version == TxVersion::V0 {
            None
        } else {
            Option::read(reader)?
        };

        let signature = Signature::read(reader)?;

        Ok(Transaction::new(
            version,
            source,
            data,
            fee,
            nonce,
            source_commitments,
            range_proof,
            reference,
            multisig,
            signature,
        ))
    }

    fn size(&self) -> usize {
        // Version byte
        let mut size = 1
        + self.source.size()
        + self.data.size()
        + self.fee.size()
        + self.nonce.size()
        // Commitments length byte
        + 1
        + self.source_commitments.iter().map(|c| c.size()).sum::<usize>()
        + self.range_proof.size()
        + self.reference.size()
        + self.signature.size();

        if self.version != TxVersion::V0 {
            size += self.multisig.size();
        }

        size
    }
}

impl Hashable for Transaction {}

impl AsRef<Transaction> for Transaction {
    fn as_ref(&self) -> &Transaction {
        self
    }
}