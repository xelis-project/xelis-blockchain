//! This file represents the transactions without the proofs
//! Not really a 'builder' per say
//! Intended to be used when creating a transaction before making the associated proofs and signature

use bulletproofs::RangeProof;
use curve25519_dalek::Scalar;
use std::{
    collections::{HashMap, HashSet},
    iter,
};
use crate::{
    config::XELIS_ASSET,
    crypto::{
        elgamal::{Ciphertext, CompressedCiphertext, CompressedPublicKey, DecryptHandle, KeyPair, PedersenCommitment, PedersenOpening, PublicKey},
        proofs::{CiphertextValidityProof, CommitmentEqProof, ProofGenerationError, BP_GENS, PC_GENS},
        Hash, ProtocolTranscript,
    }
};
use thiserror::Error;

use super::{BurnPayload, Role, SourceCommitment, Transaction, TransactionType, TransferPayload, MAX_TRANSFER_COUNT};

#[derive(Error, Debug, Clone)]
pub enum GenerationError<T> {
    State(T),
    EmptyTransfers,
    MaxTransferCountReached,
    Proof(#[from] ProofGenerationError),
}

/// If the returned balance and ct do not match, the build function will panic and/or
/// the proof will be invalid.
pub trait GetBlockchainAccountBalance {
    type Error;

    /// Get the balance from the source
    fn get_account_balance(&self, asset: &Hash) -> Result<u64, Self::Error>;

    /// Get the balance ciphertext from the source
    fn get_account_ct(&self, asset: &Hash) -> Result<CompressedCiphertext, Self::Error>;
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransactionTypeBuilder {
    Transfers(Vec<TransferBuilder>),
    // We can use the same as final transaction
    Burn(BurnPayload)
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SmartContractCallBuilder {
    pub contract: Hash,
    pub assets: HashMap<Hash, u64>,
    pub params: HashMap<String, String>, // TODO
}
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TransferBuilder {
    pub asset: Hash,
    pub amount: u64,
    pub dest_pubkey: CompressedPublicKey,
    pub extra_data: Option<Vec<u8>>, // we can put whatever we want up to EXTRA_DATA_LIMIT_SIZE bytes
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TransactionBuilder {
    pub version: u8,
    pub source: CompressedPublicKey,
    pub data: TransactionTypeBuilder,
    pub fee: u64,
    pub nonce: u64,
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

impl TransactionBuilder {
    fn get_new_source_ct(
        &self,
        mut ct: Ciphertext,
        asset: &Hash,
        transfers: &[TransferWithCommitment],
    ) -> Ciphertext {
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

    pub fn used_assets(&self) -> HashSet<Hash> {
        let mut consumed = HashSet::new();

        // Native asset is always used. (fees)
        consumed.insert(XELIS_ASSET);

        match &self.data {
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

    pub fn build<B: GetBlockchainAccountBalance>(
        mut self,
        state: &mut B,
        source_keypair: &KeyPair,
    ) -> Result<Transaction, GenerationError<B::Error>> {
        // 0.a Create the commitments

        let used_assets = self.used_assets();

        let transfers = if let TransactionTypeBuilder::Transfers(transfers) = &mut self.data {
            if transfers.len() == 0 {
                return Err(GenerationError::EmptyTransfers);
            }

            if transfers.len() > MAX_TRANSFER_COUNT {
                return Err(GenerationError::MaxTransferCountReached);
            }

            transfers
                .iter()
                .map(|transfer| {
                    let dest_pubkey = transfer
                        .dest_pubkey
                        .decompress()
                        .map_err(|err| GenerationError::Proof(err.into()))?;

                    let amount_opening = PedersenOpening::generate_new();
                    let amount_commitment =
                        PedersenCommitment::new_with_opening(transfer.amount, &amount_opening);
                    let amount_sender_handle =
                        source_keypair.get_public_key().decrypt_handle(&amount_opening);
                    let amount_receiver_handle = dest_pubkey.decrypt_handle(&amount_opening);

                    Ok(TransferWithCommitment {
                        inner: transfer.clone(),
                        commitment: amount_commitment,
                        sender_handle: amount_sender_handle,
                        receiver_handle: amount_receiver_handle,
                        destination: dest_pubkey,
                        amount_opening,
                    })
                })
                .collect::<Result<Vec<_>, GenerationError<B::Error>>>()?
        } else {
            vec![]
        };
        let mut transcript =
            Transaction::prepare_transcript(self.version, &self.source, self.fee, self.nonce);

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
                    .get_account_ct(&asset)
                    .map_err(GenerationError::State)?
                    .decompress()
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
                    transcript.append_public_key(b"dest_pubkey", &transfer.inner.dest_pubkey);
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
                        destination: transfer.inner.dest_pubkey,
                        asset: transfer.inner.asset,
                        ct_validity_proof,
                        extra_data: transfer.inner.extra_data,
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

        Ok(Transaction {
            version: self.version,
            source: self.source,
            data,
            fee: self.fee,
            nonce: self.nonce,
            source_commitments,
            range_proof,
        })
    }
}