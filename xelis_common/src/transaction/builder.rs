//! This file represents the transactions without the proofs
//! Not really a 'builder' per say
//! Intended to be used when creating a transaction before making the associated proofs and signature

use bulletproofs::RangeProof;
use curve25519_dalek::Scalar;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    iter,
};
use crate::{
    account::CiphertextVariant,
    api::DataElement,
    config::XELIS_ASSET,
    crypto::{
        elgamal::{
            Ciphertext,
            CompressedPublicKey,
            DecryptHandle,
            KeyPair,
            PedersenCommitment,
            PedersenOpening,
            PublicKey,
            RISTRETTO_COMPRESSED_SIZE,
            SCALAR_SIZE
        },
        proofs::{
            CiphertextValidityProof,
            CommitmentEqProof,
            ProofGenerationError,
            BP_GENS,
            PC_GENS
        },
        Address,
        Hash,
        ProtocolTranscript,
        HASH_SIZE
    },
    serializer::{Reader, ReaderError, Serializer, Writer},
    utils::calculate_tx_fee
};
use thiserror::Error;

use super::{BurnPayload, Role, SourceCommitment, Transaction, TransactionType, TransferPayload, EXTRA_DATA_LIMIT_SIZE, MAX_TRANSFER_COUNT};

#[derive(Error, Debug, Clone)]
pub enum GenerationError<T> {
    #[error("Error in the state: {0}")]
    State(T),
    #[error("Empty transfers")]
    EmptyTransfers,
    #[error("Max transfer count reached")]
    MaxTransferCountReached,
    #[error("Sender is receiver")]
    SenderIsReceiver,
    #[error("Extra data too large")]
    ExtraDataTooLarge,
    #[error("Address is not on the same network as us")]
    InvalidNetwork,
    #[error("Extra data was provied with an integrated address")]
    ExtraDataAndIntegratedAddress,
    #[error("Proof generation error: {0}")]
    Proof(#[from] ProofGenerationError),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum FeeBuilder {
    // calculate tx fees based on its size and multiply by this value
    Multiplier(f64),
    Value(u64) // set a direct value of how much fees you want to pay
}

impl Default for FeeBuilder {
    fn default() -> Self {
        FeeBuilder::Multiplier(1f64)
    }
}

/// If the returned balance and ct do not match, the build function will panic and/or
/// the proof will be invalid.
pub trait AccountState {
    type Error;

    /// Used to verify if the address is on the same chain
    fn is_mainnet(&self) -> bool;

    /// Get the balance from the source
    fn get_account_balance(&self, asset: &Hash) -> Result<u64, Self::Error>;

    /// Get the balance ciphertext from the source
    fn get_account_ciphertext(&self, asset: &Hash) -> Result<CiphertextVariant, Self::Error>;

    /// Update the balance and the ciphertext
    fn update_account_balance(&mut self, asset: &Hash, new_balance: u64, ciphertext: Ciphertext) -> Result<(), Self::Error>;

    /// Verify if the account exists or if we should pay more fees for account creation
    fn account_exists(&self, account: &CompressedPublicKey) -> Result<bool, Self::Error>;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransactionTypeBuilder {
    Transfers(Vec<TransferBuilder>),
    // We can use the same as final transaction
    Burn(BurnPayload)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransferBuilder {
    pub asset: Hash,
    pub amount: u64,
    pub destination: Address,
    // we can put whatever we want up to EXTRA_DATA_LIMIT_SIZE bytes
    pub extra_data: Option<DataElement>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransactionBuilder {
    version: u8,
    source: CompressedPublicKey,
    data: TransactionTypeBuilder,
    fee_builder: FeeBuilder,
    nonce: u64,
    fee: u64,
}

// Internal struct for build
struct TransferWithCommitment {
    inner: TransferBuilder,
    commitment: PedersenCommitment,
    sender_handle: DecryptHandle,
    receiver_handle: DecryptHandle,
    destination: PublicKey,
    amount_opening: PedersenOpening,
}

impl TransferWithCommitment {
    fn get_ciphertext(&self, role: Role) -> Ciphertext {
        let handle = match role {
            Role::Receiver => self.receiver_handle.clone(),
            Role::Sender => self.sender_handle.clone(),
        };

        Ciphertext::new(self.commitment.clone(), handle)
    }
}

impl TransactionTypeBuilder {
    pub fn used_assets(&self) -> HashSet<Hash> {
        let mut consumed = HashSet::new();

        // Native asset is always used. (fees)
        consumed.insert(XELIS_ASSET);

        match &self {
            TransactionTypeBuilder::Transfers(transfers) => {
                for transfer in transfers {
                    consumed.insert(transfer.asset.clone());
                }
            }
            TransactionTypeBuilder::Burn(payload) => {
                consumed.insert(payload.asset.clone());
            }
        }

        consumed
    }
}

// Used to build the final transaction
// by signing it
struct TransactionSigner {
    version: u8,
    source: CompressedPublicKey,
    data: TransactionType,
    fee: u64,
    nonce: u64,
    source_commitments: Vec<SourceCommitment>,
    range_proof: RangeProof,
}

impl TransactionSigner {
    pub fn sign(self, keypair: &KeyPair) -> Transaction {
        let bytes = self.to_bytes();
        let signature = keypair.sign(&bytes);

        Transaction {
            version: self.version,
            source: self.source,
            data: self.data,
            fee: self.fee,
            nonce: self.nonce,
            source_commitments: self.source_commitments,
            range_proof: self.range_proof,
            signature,
        }
    }
}

impl TransactionBuilder {
    pub fn new(version: u8, source: CompressedPublicKey, data: TransactionTypeBuilder, fee_builder: FeeBuilder, nonce: u64) -> Self {
        Self {
            version,
            source,
            data,
            fee_builder,
            nonce,
            fee: 0,
        }
    }

    /// Estimate by hand the bytes size of a final TX
    // Returns bytes size and transfers count
    fn estimate_size(&self) -> (usize, usize) {
        let assets_used = self.data.used_assets().len();
        // Version byte
        let mut size = 1
        + self.source.size()
        // Transaction type byte
        + 1 
        + self.fee.size()
        + self.nonce.size()
        // Commitments byte length
        + 1
        // We have one source commitment per asset spent
        // (commitment, asset, proof)
        +  assets_used * (RISTRETTO_COMPRESSED_SIZE + HASH_SIZE + (RISTRETTO_COMPRESSED_SIZE * 3 + SCALAR_SIZE * 3))
        // Range Proof
        + RISTRETTO_COMPRESSED_SIZE * 4 + SCALAR_SIZE * 3
        ;

        let transfers_count = match &self.data {
            TransactionTypeBuilder::Transfers(transfers) => {
                for transfer in transfers {
                    size += transfer.asset.size()
                    + transfer.destination.get_public_key().size()
                    // Commitment, sender handle, receiver handle
                    + RISTRETTO_COMPRESSED_SIZE * 3
                    // Ct Validity Proof
                    + (RISTRETTO_COMPRESSED_SIZE * 2 + SCALAR_SIZE * 2)
                    // Extra data byte
                    + 1;

                    if let Some(extra_data) = &transfer.extra_data {
                        size += extra_data.size();
                    }
                }
                transfers.len()
            }
            TransactionTypeBuilder::Burn(payload) => {
                size += payload.amount.size() + payload.asset.size();
                0
            }
        };

        // Inner Product Proof
        size += SCALAR_SIZE * 2 + RISTRETTO_COMPRESSED_SIZE * 2 * (transfers_count + assets_used).next_power_of_two();

        (size, transfers_count)
    }

    // Estimate the fees for this TX
    pub fn estimate_fees(&self) -> u64 {
        let calculated_fee = match self.fee_builder {
            FeeBuilder::Multiplier(multiplier) => {
                let (size, transfers) = self.estimate_size();
                let expected_fee = calculate_tx_fee(size, transfers, 0);
                (expected_fee as f64 * multiplier) as u64
            },
            // If the value is set, use it
            FeeBuilder::Value(value) => value
        };

        calculated_fee
    }

    fn get_new_source_ct(&self, mut ct: Ciphertext, asset: &Hash, transfers: &[TransferWithCommitment]) -> Ciphertext {
        if asset == &XELIS_ASSET {
            // Fees are applied to the native blockchain asset only.
            ct -= Scalar::from(self.fee);
        }

        match &self.data {
            TransactionTypeBuilder::Transfers(_) => {
                for transfer in transfers {
                    if &transfer.inner.asset == asset {
                        ct -= transfer.get_ciphertext(Role::Sender);
                    }
                }
            }
            TransactionTypeBuilder::Burn(payload) => {
                if *asset == payload.asset {
                    ct -= Scalar::from(payload.amount)
                }
            }
        }

        ct
    }

    /// Compute the full cost of the transaction
    pub fn get_transaction_cost(&self, asset: &Hash) -> u64 {
        let mut cost = 0;

        if *asset == XELIS_ASSET {
            // Fees are applied to the native blockchain asset only.
            cost += self.fee;
        }

        match &self.data {
            TransactionTypeBuilder::Transfers(transfers) => {
                for transfer in transfers {
                    if &transfer.asset == asset {
                        cost += transfer.amount;
                    }
                }
            }
            TransactionTypeBuilder::Burn(payload) => {
                if *asset == payload.asset {
                    cost += payload.amount
                }
            }
        }

        cost
    }

    pub fn build<B: AccountState>(
        mut self,
        state: &mut B,
        source_keypair: &KeyPair,
    ) -> Result<Transaction, GenerationError<B::Error>> {
        // Compute the fees
        self.fee = self.estimate_fees();

        // 0.a Create the commitments

        let used_assets = self.data.used_assets();

        let transfers = if let TransactionTypeBuilder::Transfers(transfers) = &mut self.data {
            if transfers.len() == 0 {
                return Err(GenerationError::EmptyTransfers);
            }

            if transfers.len() > MAX_TRANSFER_COUNT {
                return Err(GenerationError::MaxTransferCountReached);
            }

            let pk = source_keypair.get_public_key().compress();
            let mut extra_data_size = 0;
            for transfer in transfers.iter_mut() {
                if *transfer.destination.get_public_key() == pk {
                    return Err(GenerationError::SenderIsReceiver);
                }

                if state.is_mainnet() != transfer.destination.is_mainnet() {
                    return Err(GenerationError::InvalidNetwork);
                }

                // Either extra data provided or an integrated address, not both
                if transfer.extra_data.is_some() && !transfer.destination.is_normal() {
                    return Err(GenerationError::ExtraDataAndIntegratedAddress);
                }

                // Set the integrated data as extra data
                if let Some(extra_data) = transfer.destination.extract_data_only() {
                    transfer.extra_data = Some(extra_data);
                }

                if let Some(extra_data) = &transfer.extra_data {
                    extra_data_size += extra_data.size();
                }
            }

            if extra_data_size > EXTRA_DATA_LIMIT_SIZE {
                return Err(GenerationError::ExtraDataTooLarge);
            }

            transfers
                .iter()
                .map(|transfer| {
                    let destination = transfer
                        .destination
                        .get_public_key()
                        .decompress()
                        .map_err(|err| GenerationError::Proof(err.into()))?;

                    let amount_opening = PedersenOpening::generate_new();
                    let commitment =
                        PedersenCommitment::new_with_opening(transfer.amount, &amount_opening);
                    let sender_handle =
                        source_keypair.get_public_key().decrypt_handle(&amount_opening);
                    let receiver_handle = destination.decrypt_handle(&amount_opening);

                    Ok(TransferWithCommitment {
                        inner: transfer.clone(),
                        commitment,
                        sender_handle,
                        receiver_handle,
                        destination,
                        amount_opening,
                    })
                })
                .collect::<Result<Vec<_>, GenerationError<B::Error>>>()?
        } else {
            vec![]
        };
        let mut transcript = Transaction::prepare_transcript(self.version, &self.source, self.fee, self.nonce);

        let mut range_proof_openings: Vec<_> =
            iter::repeat_with(|| PedersenOpening::generate_new().as_scalar())
                .take(used_assets.len())
                .collect();

        let mut range_proof_values: Vec<_> = used_assets
            .iter()
            .map(|asset| {
                let cost = self.get_transaction_cost(&asset);
                let source_new_balance = state
                    .get_account_balance(asset)
                    .map_err(GenerationError::State)?
                    .checked_sub(cost)
                    .ok_or(ProofGenerationError::InsufficientFunds)?;

                Ok(source_new_balance)
            })
            .collect::<Result<Vec<_>, GenerationError<B::Error>>>()?;

        let source_commitments = used_assets
            .into_iter()
            .zip(&range_proof_openings)
            .zip(&range_proof_values)
            .map(|((asset, new_source_opening), &source_new_balance)| {
                let new_source_opening = PedersenOpening::from_scalar(*new_source_opening);

                let source_current_ciphertext = state
                    .get_account_ciphertext(&asset)
                    .map_err(GenerationError::State)?
                    .take()
                    .map_err(|err| GenerationError::Proof(err.into()))?;

                let commitment =
                    PedersenCommitment::new_with_opening(source_new_balance, &new_source_opening)
                    .compress();

                let new_source_ciphertext =
                    self.get_new_source_ct(source_current_ciphertext, &asset, &transfers);

                // 1. Make the CommitmentEqProof

                transcript.new_commitment_eq_proof_domain_separator();
                transcript.append_hash(b"new_source_commitment_asset", &asset);
                transcript.append_commitment(b"new_source_commitment", &commitment);

                let proof = CommitmentEqProof::new(
                    &source_keypair,
                    &new_source_ciphertext,
                    &new_source_opening,
                    source_new_balance,
                    &mut transcript,
                );

                // Store the new balance in preparation of next transaction
                state
                    .update_account_balance(&asset, source_new_balance, new_source_ciphertext)
                    .map_err(GenerationError::State)?;

                Ok(SourceCommitment {
                    asset,
                    commitment,
                    proof,
                })
            })
            .collect::<Result<Vec<_>, GenerationError<B::Error>>>()?;

        let transfers = if let TransactionTypeBuilder::Transfers(_) = &mut self.data {
            range_proof_values.reserve(transfers.len());
            range_proof_openings.reserve(transfers.len());

            let transfers = transfers
                .into_iter()
                .map(|transfer| {
                    let commitment = transfer.commitment.compress();
                    let sender_handle = transfer.sender_handle.compress();
                    let receiver_handle = transfer.receiver_handle.compress();

                    transcript.transfer_proof_domain_separator();
                    transcript.append_public_key(b"dest_pubkey", transfer.inner.destination.get_public_key());
                    transcript.append_commitment(b"amount_commitment", &commitment);
                    transcript.append_handle(b"amount_sender_handle", &sender_handle);
                    transcript.append_handle(b"amount_receiver_handle", &receiver_handle);

                    let ct_validity_proof = CiphertextValidityProof::new(
                        &transfer.destination,
                        transfer.inner.amount,
                        &transfer.amount_opening,
                        &mut transcript,
                    );

                    range_proof_values.push(transfer.inner.amount);
                    range_proof_openings.push(transfer.amount_opening.as_scalar());

                    TransferPayload {
                        commitment,
                        receiver_handle,
                        sender_handle,
                        destination: transfer.inner.destination.to_public_key(),
                        asset: transfer.inner.asset,
                        ct_validity_proof,
                        extra_data: transfer.inner.extra_data.map(|v| v.to_bytes()),
                    }
                })
                .collect::<Vec<_>>();

            transfers
        } else {
            vec![]
        };

        let n_commitments = range_proof_values.len();

        // Create fake commitments to make `m` (party size) of the bulletproof a power of two.
        let n_dud_commitments = n_commitments
            .checked_next_power_of_two()
            .ok_or(ProofGenerationError::Format)?
            - n_commitments;

        range_proof_values.extend(iter::repeat(0u64).take(n_dud_commitments));
        range_proof_openings.extend(iter::repeat(Scalar::ZERO).take(n_dud_commitments));

        let data = match self.data {
            TransactionTypeBuilder::Transfers(_) => TransactionType::Transfers(transfers),
            TransactionTypeBuilder::Burn(payload) => TransactionType::Burn(payload)
        };

        // 3. Create the RangeProof

        let (range_proof, _commitments) = RangeProof::prove_multiple(
            &BP_GENS,
            &PC_GENS,
            &mut transcript,
            &range_proof_values,
            &range_proof_openings,
            64,
        )
        .map_err(ProofGenerationError::from)?;

        let transaction = TransactionSigner {
            version: self.version,
            source: self.source,
            data,
            fee: self.fee,
            nonce: self.nonce,
            source_commitments,
            range_proof,
        }.sign(source_keypair);

        Ok(transaction)
    }
}

impl Serializer for TransactionSigner {
    fn write(&self, writer: &mut Writer) {
        self.version.write(writer);
        self.source.write(writer);
        self.data.write(writer);
        self.fee.write(writer);
        self.nonce.write(writer);
        self.source_commitments.write(writer);
        self.range_proof.write(writer);
    }

    // Should never be called
    fn read(_: &mut Reader) -> Result<Self, ReaderError> {
        Err(ReaderError::InvalidValue)
    }
}