use bulletproofs::RangeProof;
use curve25519_dalek::{ristretto::CompressedRistretto, traits::Identity, RistrettoPoint, Scalar};
use merlin::Transcript;
use crate::{config::XELIS_ASSET, crypto::{elgamal::{Ciphertext, CompressedPublicKey, DecompressionError, DecryptHandle, PedersenCommitment}, proofs::{BatchCollector, ProofVerificationError, BP_GENS, PC_GENS}, Hash, ProtocolTranscript, SIGNATURE_SIZE}, serializer::Serializer};
use super::{Role, Transaction, TransactionType, TransferPayload};
use thiserror::Error;
use std::iter;

/// This trait is used by the batch verification function.
/// It is intended to represent a virtual snapshot of the current blockchain
/// state, where the transactions can get applied in order.
pub trait BlockchainVerificationState {
    type Error;

    /// Get the balance ciphertext for a receiver account
    async fn get_receiver_balance(
        &self,
        account: &CompressedPublicKey,
        asset: &Hash,
    ) -> Result<Ciphertext, Self::Error>;

    /// Get the balance ciphertext for a sender account
    async fn get_sender_balance(
        &self,
        account: &CompressedPublicKey,
        asset: &Hash,
    ) -> Result<Ciphertext, Self::Error>;

    /// Apply a new balance ciphertext to a receiver account
    async fn update_receiver_balance(
        &mut self,
        account: &CompressedPublicKey,
        asset: &Hash,
        new_balance: Ciphertext,
    ) -> Result<(), Self::Error>;

    /// Apply new balance ciphertext to a sender account
    async fn update_sender_balance(
        &mut self,
        account: &CompressedPublicKey,
        asset: &Hash,
        new_balance: Ciphertext,
        echange: Ciphertext,
    ) -> Result<(), Self::Error>;

    /// Get the nonce of an account
    async fn get_account_nonce(
        &self,
        account: &CompressedPublicKey
    ) -> Result<u64, Self::Error>;

    /// Apply a new nonce to an account
    async fn update_account_nonce(
        &mut self,
        account: &CompressedPublicKey,
        new_nonce: u64
    ) -> Result<(), Self::Error>;
}

#[derive(Error, Debug, Clone)]
pub enum VerificationError<T> {
    State(T),
    InvalidNonce,
    SenderIsReceiver,
    InvalidSignature,
    Proof(#[from] ProofVerificationError),
}

struct DecompressedTransferCt {
    commitment: PedersenCommitment,
    sender_handle: DecryptHandle,
    receiver_handle: DecryptHandle,
}

impl DecompressedTransferCt {
    fn decompress(transfer: &TransferPayload) -> Result<Self, DecompressionError> {
        Ok(Self {
            commitment: transfer.commitment.decompress()?,
            sender_handle: transfer.sender_handle.decompress()?,
            receiver_handle: transfer.receiver_handle.decompress()?,
        })
    }

    fn get_ciphertext(&self, role: Role) -> Ciphertext {
        let handle = match role {
            Role::Receiver => self.receiver_handle.clone(),
            Role::Sender => self.sender_handle.clone(),
        };

        Ciphertext::new(self.commitment.clone(), handle)
    }
}

impl Transaction {
    /// Get the new output ciphertext
    // This is used to substract the amount from the sender's balance
    fn get_sender_output_ct(
        &self,
        asset: &Hash,
        decompressed_transfers: &[DecompressedTransferCt],
    ) -> Result<Ciphertext, DecompressionError> {
        let mut output = Ciphertext::zero();

        if *asset == XELIS_ASSET {
            // Fees are applied to the native blockchain asset only.
            output += Scalar::from(self.fee);
        }

        match &self.data {
            TransactionType::Transfers(transfers) => {
                for (transfer, d) in transfers.iter().zip(decompressed_transfers.iter()) {
                    if asset == &transfer.asset {
                        output += d.get_ciphertext(Role::Sender);
                    }
                }
            }
            TransactionType::Burn(payload) => {
                if *asset == payload.asset {
                    output += Scalar::from(payload.amount)
                }
            }
        }

        Ok(output)
    }

    pub(crate) fn prepare_transcript(
        version: u8,
        source_pubkey: &CompressedPublicKey,
        fee: u64,
        nonce: u64,
    ) -> Transcript {
        let mut transcript = Transcript::new(b"transaction-proof");
        transcript.append_u64(b"version", version.into());
        transcript.append_public_key(b"source_pubkey", source_pubkey);
        transcript.append_u64(b"fee", fee);
        transcript.append_u64(b"nonce", nonce);
        transcript
    }

    // Verify that the commitment assets match the assets used in the tx
    fn verify_commitment_assets(&self) -> bool {
        let has_commitment_for_asset = |asset| {
            self.source_commitments
                .iter()
                .any(|c| &c.asset == asset)
        };

        // XELIS_ASSET is always required for fees
        if !has_commitment_for_asset(&XELIS_ASSET) {
            return false;
        }

        // Check for duplicates
        // Don't bother with hashsets or anything, number of transfers should be constrained
        if self
            .source_commitments
            .iter()
            .enumerate()
            .any(|(i, c)| {
                self.source_commitments
                    .iter()
                    .enumerate()
                    .any(|(i2, c2)| i != i2 && &c.asset == &c2.asset)
            })
        {
            return false;
        }

        match &self.data {
            TransactionType::Transfers(transfers) => transfers
                .iter()
                .all(|transfer| has_commitment_for_asset(&transfer.asset)),
            TransactionType::Burn(payload) => has_commitment_for_asset(&payload.asset),
        }
    }

    // internal, does not verify the range proof
    // returns (transcript, commitments for range proof)
    async fn pre_verify<B: BlockchainVerificationState>(
        &self,
        state: &mut B,
        sigma_batch_collector: &mut BatchCollector,
    ) -> Result<(Transcript, Vec<(RistrettoPoint, CompressedRistretto)>), VerificationError<B::Error>>
    {
        // First, check the nonce
        let account_nonce = state
            .get_account_nonce(&self.source).await
            .map_err(VerificationError::State)?;

        if account_nonce != self.nonce {
            return Err(VerificationError::InvalidNonce);
        }

        // Nonce is valid, update it for next transactions if any
        state
            .update_account_nonce(&self.source, self.nonce).await
            .map_err(VerificationError::State)?;

        if !self.verify_commitment_assets() {
            return Err(VerificationError::Proof(ProofVerificationError::Format));
        }

        let transfers_decompressed = if let TransactionType::Transfers(transfers) = &self.data {
            // Prevent sending to ourself
            for transfer in transfers.iter() {
                if transfer.destination == self.source {
                    return Err(VerificationError::SenderIsReceiver);
                }
            }

            transfers
                .iter()
                .map(DecompressedTransferCt::decompress)
                .collect::<Result<_, DecompressionError>>()
                .map_err(ProofVerificationError::from)?
        } else {
            vec![]
        };

        let new_source_commitments_decompressed = self
            .source_commitments
            .iter()
            .map(|commitment| commitment.commitment.decompress())
            .collect::<Result<Vec<_>, DecompressionError>>()
            .map_err(ProofVerificationError::from)?;

        let owner = self
            .source
            .decompress()
            .map_err(|err| VerificationError::Proof(err.into()))?;

        let mut transcript =
            Self::prepare_transcript(self.version, &self.source, self.fee, self.nonce);

        // 0. Verify Signature
        let bytes = self.to_bytes();
        if !self.signature.verify(&bytes[..bytes.len() - SIGNATURE_SIZE], &owner) {
            return Err(VerificationError::InvalidSignature);
        }

        // 1. Verify CommitmentEqProofs

        for (commitment, new_source_commitment) in self
            .source_commitments
            .iter()
            .zip(&new_source_commitments_decompressed)
        {
            let source_current_ciphertext = state
                .get_sender_balance(&self.source, &commitment.asset).await
                .map_err(VerificationError::State)?;

            // Ciphertext containing all the funds spent for this commitment
            let output = self.get_sender_output_ct(&commitment.asset, &transfers_decompressed)
            .map_err(|err| VerificationError::Proof(err.into()))?;

            // Compute the new final balance for account
            let new_ct = source_current_ciphertext - &output;
            transcript.new_commitment_eq_proof_domain_separator();
            transcript.append_hash(b"new_source_commitment_asset", &commitment.asset);
            transcript
                .append_commitment(b"new_source_commitment", &commitment.commitment);

            commitment.proof.pre_verify(
                &owner,
                &new_ct,
                &new_source_commitment,
                &mut transcript,
                sigma_batch_collector,
            )?;

            // Update source balance
            state
                .update_sender_balance(
                    &self.source,
                    &commitment.asset,
                    new_ct,
                    output,
                ).await
                .map_err(VerificationError::State)?;
        }

        // 2. Verify every CtValidityProof
        if let TransactionType::Transfers(transfers) = &self.data {
            for (transfer, decompressed) in transfers.iter().zip(&transfers_decompressed) {
                let receiver = transfer
                    .destination
                    .decompress()
                    .map_err(ProofVerificationError::from)?;

                // Update receiver balance

                let current_balance = state
                    .get_receiver_balance(
                        &transfer.destination,
                        &transfer.asset
                    ).await
                    .map_err(VerificationError::State)?;

                let receiver_ct = decompressed.get_ciphertext(Role::Receiver);
                let receiver_new_balance = current_balance + receiver_ct;

                state
                    .update_receiver_balance(
                        &transfer.destination,
                        &transfer.asset,
                        receiver_new_balance,
                    ).await
                    .map_err(VerificationError::State)?;

                // Validity proof

                transcript.transfer_proof_domain_separator();
                transcript.append_public_key(b"dest_pubkey", &transfer.destination);
                transcript.append_commitment(b"amount_commitment", &transfer.commitment);
                transcript.append_handle(b"amount_sender_handle", &transfer.sender_handle);
                transcript
                    .append_handle(b"amount_receiver_handle", &transfer.receiver_handle);

                transfer.ct_validity_proof.pre_verify(
                    &decompressed.commitment,
                    &receiver,
                    &decompressed.receiver_handle,
                    &mut transcript,
                    sigma_batch_collector,
                )?;
            }
        }

        // Prepare the new source commitments

        let new_source_commitments = self
            .source_commitments
            .iter()
            .zip(&new_source_commitments_decompressed)
            .map(|(commitment, new_source_commitment)| {
                (
                    new_source_commitment.as_point().clone(),
                    commitment.commitment.as_point().clone(),
                )
            });

        let mut n_commitments = self.source_commitments.len();
        if let TransactionType::Transfers(transfers) = &self.data {
            n_commitments += transfers.len()
        }

        // Create fake commitments to make `m` (party size) of the bulletproof a power of two.
        let n_dud_commitments = n_commitments
            .checked_next_power_of_two()
            .ok_or(ProofVerificationError::Format)?
            - n_commitments;

        let value_commitments: Vec<(RistrettoPoint, CompressedRistretto)> = if let TransactionType::Transfers(transfers) = &self.data {
            new_source_commitments
                .chain(transfers.iter().zip(&transfers_decompressed).map(
                    |(transfer, decompressed)| {
                        (
                            decompressed.commitment.as_point().clone(),
                            transfer.commitment.as_point().clone(),
                        )
                    },
                ))
                .chain(
                    iter::repeat((RistrettoPoint::identity(), CompressedRistretto::identity()))
                        .take(n_dud_commitments),
                )
                .collect()
        } else {
            new_source_commitments
                .chain(
                    iter::repeat((RistrettoPoint::identity(), CompressedRistretto::identity()))
                        .take(n_dud_commitments),
                )
                .collect()
        };

        // 3. Verify the aggregated RangeProof

        // range proof will be verified in batch by caller

        Ok((transcript, value_commitments))
    }

    pub async fn verify_batch<B: BlockchainVerificationState>(
        txs: &[Transaction],
        state: &mut B,
    ) -> Result<(), VerificationError<B::Error>> {
        let mut sigma_batch_collector = BatchCollector::default();
        let mut prepared = Vec::with_capacity(txs.len());
        for tx in txs {
            let (transcript, commitments) = tx.pre_verify(state, &mut sigma_batch_collector).await?;
            prepared.push((transcript, commitments));
        }

        sigma_batch_collector
            .verify()
            .map_err(|_| ProofVerificationError::GenericProof)?;

        RangeProof::verify_batch(
            txs.iter()
                .zip(&mut prepared)
                .map(|(tx, (transcript, commitments))| {
                    tx.range_proof
                        .verification_view(transcript, commitments, 64)
                }),
            &BP_GENS,
            &PC_GENS,
        )
        .map_err(ProofVerificationError::from)?;

        Ok(())
    }

    /// Verify one transaction. Use `verify_batch` to verify a batch of transactions.
    pub async fn verify<B: BlockchainVerificationState>(
        &self,
        state: &mut B,
    ) -> Result<(), VerificationError<B::Error>> {
        let mut sigma_batch_collector = BatchCollector::default();
        let (mut transcript, commitments) = self.pre_verify(state, &mut sigma_batch_collector).await?;

        sigma_batch_collector
            .verify()
            .map_err(|_| ProofVerificationError::GenericProof)?;

        RangeProof::verify_multiple(
            &self.range_proof,
            &BP_GENS,
            &PC_GENS,
            &mut transcript,
            &commitments,
            64,
        )
        .map_err(ProofVerificationError::from)?;

        Ok(())
    }

    /// Assume the tx is valid, apply it to `state`. May panic if a ciphertext is ill-formed.
    pub async fn apply_without_verify<B: BlockchainVerificationState>(
        &self,
        state: &mut B,
    ) -> Result<(), B::Error> {
        let transfers_decompressed = if let TransactionType::Transfers(transfers) = &self.data {
            transfers
                .iter()
                .map(DecompressedTransferCt::decompress)
                .map(Result::unwrap)
                .collect()
        } else {
            vec![]
        };

        for commitment in &self.source_commitments {
            let asset = &commitment.asset;
            let current_bal_sender = state
                .get_sender_balance(
                    &self.source,
                    asset
                ).await?;

            let output = self.get_sender_output_ct(asset, &transfers_decompressed)
                .expect("ill-formed ciphertext");

            // Compute the new final balance for account
            let new_ct = current_bal_sender - &output;

            state.update_sender_balance(
                &self.source, asset,
                new_ct,
                output,
            ).await?;
        }

        if let TransactionType::Transfers(transfers) = &self.data {
            for transfer in transfers {
                // Update receiver balance
                let current_bal = state
                    .get_receiver_balance(
                        &transfer.destination,
                        &transfer.asset,
                    ).await?;

                let receiver_ct = transfer
                    .get_ciphertext(Role::Receiver)
                    .decompress()
                    .expect("ill-formed ciphertext");

                let receiver_new_balance = current_bal + receiver_ct;

                state.update_receiver_balance(
                    &transfer.destination,
                    &transfer.asset,
                    receiver_new_balance,
                ).await?;
            }
        }
    
        Ok(())
    }
}