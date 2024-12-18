mod state;

use anyhow::{Context as AnyContext, Error as AnyError};
use bulletproofs::RangeProof;
use curve25519_dalek::{
    ristretto::CompressedRistretto,
    traits::Identity,
    RistrettoPoint,
    Scalar
};
use log::{debug, trace};
use merlin::Transcript;
use xelis_vm::{ConstantWrapper, ModuleValidator, VM};
use crate::{
    account::Nonce,
    config::{BURN_PER_CONTRACT, TRANSACTION_FEE_BURN_PERCENT, XELIS_ASSET},
    contract::{ChainState, ContractOutput, DeterministicRandom},
    crypto::{
        elgamal::{
            Ciphertext,
            CompressedPublicKey,
            DecompressionError,
            DecryptHandle,
            PedersenCommitment
        },
        hash,
        proofs::{
            BatchCollector,
            ProofVerificationError,
            BP_GENS,
            BULLET_PROOF_SIZE,
            PC_GENS
        },
        Hash,
        Hashable,
        ProtocolTranscript,
        SIGNATURE_SIZE
    }, serializer::Serializer, transaction::{
        TxVersion,
        EXTRA_DATA_LIMIT_SIZE,
        EXTRA_DATA_LIMIT_SUM_SIZE,
        MAX_DEPOSIT_PER_INVOKE_CALL,
        MAX_MULTISIG_PARTICIPANTS,
        MAX_TRANSFER_COUNT
    }
};
use super::{
    ContractDeposit,
    Role,
    Transaction,
    TransactionType,
    TransferPayload
};
pub use state::*;
use thiserror::Error;
use std::{borrow::Cow, iter};

#[derive(Error, Debug)]
pub enum VerificationError<T> {
    #[error("State error: {0}")]
    State(T),
    #[error("Invalid nonce, got {} expected {}", _0, _1)]
    InvalidNonce(Nonce, Nonce),
    #[error("Sender is receiver")]
    SenderIsReceiver,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Proof verification error: {0}")]
    Proof(#[from] ProofVerificationError),
    #[error("Extra Data is too big in transfer")]
    TransferExtraDataSize,
    #[error("Extra Data is too big in transaction")]
    TransactionExtraDataSize,
    #[error("Transfer count is invalid")]
    TransferCount,
    #[error("Invalid commitments assets")]
    Commitments,
    #[error("Invalid multisig participants count")]
    MultiSigParticipants,
    #[error("Invalid multisig threshold")]
    MultiSigThreshold,
    #[error("MultiSig not configured")]
    MultiSigNotConfigured,
    #[error("MultiSig not found")]
    MultiSigNotFound,
    #[error("Invalid format")]
    InvalidFormat,
    #[error("Module error: {0}")]
    ModuleError(String),
    #[error(transparent)]
    AnyError(#[from] AnyError),
    #[error("Invalid invoke contract")]
    InvalidInvokeContract,
    #[error("overflow during gas calculation")]
    GasOverflow,
}

struct DecompressedTransferCt {
    commitment: PedersenCommitment,
    sender_handle: DecryptHandle,
    receiver_handle: DecryptHandle,
}

impl DecompressedTransferCt {
    fn decompress(transfer: &TransferPayload) -> Result<Self, DecompressionError> {
        Ok(Self {
            commitment: transfer.get_commitment().decompress()?,
            sender_handle: transfer.get_sender_handle().decompress()?,
            receiver_handle: transfer.get_receiver_handle().decompress()?,
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
    // This function will be used to verify the transaction format
    pub fn has_valid_version_format(&self) -> bool {
        match self.version {
            // V0 don't support MultiSig format
            TxVersion::V0 => {
                if self.get_multisig().is_some() {
                    return false;
                }

                match &self.data {
                    TransactionType::MultiSig(_)
                    | TransactionType::InvokeContract(_)
                    | TransactionType::DeployContract(_) => false,
                    _ => true,
                }
            }
            TxVersion::V1 => true,
        }
    }

    /// Get the new output ciphertext
    /// This is used to substract the amount from the sender's balance
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
                    if asset == transfer.get_asset() {
                        output += d.get_ciphertext(Role::Sender);
                    }
                }
            }
            TransactionType::Burn(payload) => {
                if *asset == payload.asset {
                    output += Scalar::from(payload.amount)
                }
            },
            TransactionType::MultiSig(_) => {},
            TransactionType::InvokeContract(payload) => {
                if *asset == XELIS_ASSET {
                    output += Scalar::from(payload.max_gas);
                }

                if let Some(deposit) = payload.deposits.get(asset) {
                    match deposit {
                        ContractDeposit::Public(amount) => {
                            output += Scalar::from(*amount);
                        },
                        // ContractDeposit::Private { .. } => {
                            
                        // }
                    }
                }
            },
            TransactionType::DeployContract(_) => {
                // Burn a full coin for each contract deployed
                if *asset == XELIS_ASSET {
                    output += Scalar::from(BURN_PER_CONTRACT);
                }
            }
        }

        Ok(output)
    }

    /// Get the new output ciphertext for the sender
    pub fn get_expected_sender_outputs<'a>(&'a self) -> Result<Vec<(&'a Hash, Ciphertext)>, DecompressionError> {
        let mut balances = Vec::new();
        let decompressed_transfers = if let TransactionType::Transfers(transfers) = &self.data {
            transfers
                .iter()
                .map(DecompressedTransferCt::decompress)
                .collect::<Result<_, DecompressionError>>()?
        } else {
            Vec::new()
        };

        for commitment in self.source_commitments.iter() {
            let ciphertext = self.get_sender_output_ct(&commitment.asset, &decompressed_transfers)?;

            balances.push((&commitment.asset, ciphertext));
        }

        Ok(balances)
    }

    pub(crate) fn prepare_transcript(
        version: TxVersion,
        source_pubkey: &CompressedPublicKey,
        fee: u64,
        nonce: Nonce,
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
                .all(|transfer| has_commitment_for_asset(transfer.get_asset())),
            TransactionType::Burn(payload) => has_commitment_for_asset(&payload.asset),
            TransactionType::MultiSig(_) => true,
            TransactionType::InvokeContract(payload) => payload
                .deposits
                .keys()
                .all(|asset| has_commitment_for_asset(asset)),
            TransactionType::DeployContract(_) => true,
        }
    }

    // internal, does not verify the range proof
    // returns (transcript, commitments for range proof)
    async fn pre_verify<'a, E, B: BlockchainVerificationState<'a, E>>(
        &'a self,
        state: &mut B,
        sigma_batch_collector: &mut BatchCollector,
    ) -> Result<(Transcript, Vec<(RistrettoPoint, CompressedRistretto)>), VerificationError<E>>
    {
        trace!("Pre-verifying transaction");
        if !self.has_valid_version_format() {
            return Err(VerificationError::InvalidFormat);
        }

        trace!("Pre-verifying transaction on state");
        state.pre_verify_tx(&self).await
            .map_err(VerificationError::State)?;

        // First, check the nonce
        let account_nonce = state.get_account_nonce(&self.source).await
            .map_err(VerificationError::State)?;

        if account_nonce != self.nonce {
            return Err(VerificationError::InvalidNonce(account_nonce, self.nonce));
        }

        // Nonce is valid, update it for next transactions if any
        state
            .update_account_nonce(&self.source, self.nonce + 1).await
            .map_err(VerificationError::State)?;

        if !self.verify_commitment_assets() {
            debug!("Invalid commitment assets");
            return Err(VerificationError::Commitments);
        }

        let mut transfers_decompressed: Vec<_> = Vec::new();
        match &self.data {
            TransactionType::Transfers(transfers) => {
                if transfers.len() > MAX_TRANSFER_COUNT || transfers.is_empty() {
                    debug!("incorrect transfers size: {}", transfers.len());
                    return Err(VerificationError::TransferCount);
                }

                let mut extra_data_size = 0;
                // Prevent sending to ourself
                for transfer in transfers.iter() {
                    if *transfer.get_destination() == self.source {
                        debug!("sender cannot be the receiver in the same TX");
                        return Err(VerificationError::SenderIsReceiver);
                    }

                    if let Some(extra_data) = transfer.get_extra_data() {
                        let size = extra_data.size();
                        if size > EXTRA_DATA_LIMIT_SIZE {
                            return Err(VerificationError::TransferExtraDataSize);
                        }
                        extra_data_size += size;
                    }

                    let decompressed = DecompressedTransferCt::decompress(transfer)
                        .map_err(ProofVerificationError::from)?;

                    transfers_decompressed.push(decompressed);
                }
    
                // Check the sum of extra data size
                if extra_data_size > EXTRA_DATA_LIMIT_SUM_SIZE {
                    return Err(VerificationError::TransactionExtraDataSize);
                }
            },
            TransactionType::Burn(payload) => {
                let fee = self.fee;
                let amount = payload.amount;

                if amount == 0 {
                    return Err(VerificationError::InvalidFormat);
                }

                let total = fee.checked_add(amount)
                    .ok_or(VerificationError::InvalidFormat)?;

                if total < fee || total < amount {
                    return Err(VerificationError::InvalidFormat);
                }
            },
            TransactionType::MultiSig(payload) => {
                if payload.participants.len() > MAX_MULTISIG_PARTICIPANTS {
                    return Err(VerificationError::MultiSigParticipants);
                }

                // Threshold should be less than or equal to the number of participants
                if payload.threshold as usize > payload.participants.len() {
                    return Err(VerificationError::MultiSigThreshold);
                }

                // If the threshold is set to 0, while we have participants, its invalid
                // Threshold should be always > 0
                if payload.threshold == 0 && !payload.participants.is_empty() {
                    return Err(VerificationError::MultiSigThreshold);
                }

                // You can't contains yourself in the participants
                if payload.participants.contains(self.get_source()) {
                    return Err(VerificationError::MultiSigParticipants);
                }

                let is_reset = payload.threshold == 0 && payload.participants.is_empty();
                // If the multisig is reset, we need to check if it was already configured
                if is_reset && state.get_multisig_state(&self.source).await.map_err(VerificationError::State)?.is_none() {
                    return Err(VerificationError::MultiSigNotConfigured);
                }
            },
            TransactionType::InvokeContract(payload) => {
                if payload.deposits.len() > MAX_DEPOSIT_PER_INVOKE_CALL {
                    return Err(VerificationError::TransferCount);
                }

                let (module, environment) = state.get_contract_module_with_environment(&payload.contract).await
                    .map_err(VerificationError::State)?;

                if !module.is_entry_chunk(payload.chunk_id as usize) {
                    return Err(VerificationError::InvalidInvokeContract);
                }

                let validator = ModuleValidator::new(module, environment);
                for constant in payload.parameters.iter() {
                    let decompressed = constant.decompress(module.structs(), module.enums())
                        .context("decompress param")?;

                    // For safety, we wrap it in our custom type in case of a potential stackoverflow attack
                    let wrapped = ConstantWrapper(decompressed);

                    validator.verify_constant(&wrapped.0)
                        .map_err(|err| VerificationError::ModuleError(format!("{:#}", err)))?;
                }
            },
            TransactionType::DeployContract(module) => {
                let environment = state.get_contract_environment().await
                    .map_err(VerificationError::State)?;

                let validator = ModuleValidator::new(module, environment);
                validator.verify()
                    .map_err(|err| VerificationError::ModuleError(format!("{:#}", err)))?;
            }
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

        let mut transcript = Self::prepare_transcript(self.version, &self.source, self.fee, self.nonce);

        // 0.a Verify Signature
        let bytes = self.to_bytes();
        if !self.signature.verify(&bytes[..bytes.len() - SIGNATURE_SIZE], &owner) {
            debug!("transaction signature is invalid");
            return Err(VerificationError::InvalidSignature);
        }
    
        // 0.b Verify multisig
        if let Some(config) = state.get_multisig_state(&self.source).await.map_err(VerificationError::State)? {
            let Some(multisig) = self.get_multisig() else {
                return Err(VerificationError::MultiSigNotFound);
            };

            if (config.threshold as usize) != multisig.len() || multisig.len() > MAX_MULTISIG_PARTICIPANTS {
                return Err(VerificationError::MultiSigParticipants);
            }

            // Multisig are based on the Tx data, without the final signature
            // We need to remove the final signature and the multisig from the bytes
            // Each SigId is composed of a u8 and a signature (64 bytes + 1 byte)
            // We have overhead of 1 byte for the optional bool, and 1 byte for the count in u8
            // We also need to get rid of the final signature (64 bytes)
            let size = 1 + 1 + SIGNATURE_SIZE + multisig.len() * (SIGNATURE_SIZE + 1);
            if  size >= bytes.len() {
                return Err(VerificationError::InvalidFormat);
            }

            let hash = hash(&bytes[..bytes.len() - size]);
            for sig in multisig.get_signatures() {
                // A participant can't sign more than once because of the IndexSet (SignatureId impl Hash on id)
                let index = sig.id as usize;
                let Some(key) = config.participants.get_index(index) else {
                    return Err(VerificationError::MultiSigParticipants);
                };

                let decompressed = key.decompress().map_err(ProofVerificationError::from)?;
                if !sig.signature.verify(hash.as_bytes(), &decompressed) {
                    return Err(VerificationError::InvalidSignature);
                }
            }
        } else if self.get_multisig().is_some() {
            return Err(VerificationError::MultiSigNotConfigured);
        }

        // 1. Verify CommitmentEqProofs
        trace!("verifying commitments eq proofs");

        for (commitment, new_source_commitment) in self
            .source_commitments
            .iter()
            .zip(&new_source_commitments_decompressed)
        {
            // Ciphertext containing all the funds spent for this commitment
            let output = self.get_sender_output_ct(&commitment.asset, &transfers_decompressed)
                .map_err(ProofVerificationError::from)?;

            // Retrieve the balance of the sender
            let source_verification_ciphertext = state
                .get_sender_balance(&self.source, &commitment.asset, &self.reference).await
                .map_err(VerificationError::State)?;

            // Compute the new final balance for account
            *source_verification_ciphertext -= &output;
            transcript.new_commitment_eq_proof_domain_separator();
            transcript.append_hash(b"new_source_commitment_asset", &commitment.asset);
            transcript
                .append_commitment(b"new_source_commitment", &commitment.commitment);

            commitment.proof.pre_verify(
                &owner,
                &source_verification_ciphertext,
                &new_source_commitment,
                &mut transcript,
                sigma_batch_collector,
            )?;

            // Update source balance
            state
                .add_sender_output(
                    &self.source,
                    &commitment.asset,
                    output,
                ).await
                .map_err(VerificationError::State)?;
        }

        // 2. Verify every CtValidityProof
        trace!("verifying transfers ciphertext validity proofs");

        // Prepare the new source commitments at same time
        // Count the number of commitments
        let mut n_commitments = self.source_commitments.len();
        let mut value_commitments: Vec<(RistrettoPoint, CompressedRistretto)> = Vec::new();

        match &self.data {
            TransactionType::Transfers(transfers) => {
                // Count the number of transfers
                n_commitments += transfers.len();

                // Prepare the new commitments
                for (transfer, decompressed) in transfers.iter().zip(&transfers_decompressed) {
                    let receiver = transfer
                        .get_destination()
                        .decompress()
                        .map_err(ProofVerificationError::from)?;
    
                    // Update receiver balance
    
                    let current_balance = state
                        .get_receiver_balance(
                            Cow::Borrowed(transfer.get_destination()),
                            Cow::Borrowed(transfer.get_asset())
                        ).await
                        .map_err(VerificationError::State)?;

                    let receiver_ct = decompressed.get_ciphertext(Role::Receiver);
                    *current_balance += receiver_ct;

                    // Validity proof

                    transcript.transfer_proof_domain_separator();
                    transcript.append_public_key(b"dest_pubkey", transfer.get_destination());
                    transcript.append_commitment(b"amount_commitment", transfer.get_commitment());
                    transcript.append_handle(b"amount_sender_handle", transfer.get_sender_handle());
                    transcript
                        .append_handle(b"amount_receiver_handle", transfer.get_receiver_handle());

                    transfer.get_proof().pre_verify(
                        &decompressed.commitment,
                        &receiver,
                        &decompressed.receiver_handle,
                        &mut transcript,
                        sigma_batch_collector,
                    )?;

                    // Add the commitment to the list
                    value_commitments.push((decompressed.commitment.as_point().clone(), transfer.get_commitment().as_point().clone()));
                }
            },
            TransactionType::Burn(payload) => {
                if self.get_version() >= TxVersion::V1 {
                    transcript.burn_proof_domain_separator();
                    transcript.append_hash(b"burn_asset", &payload.asset);
                    transcript.append_u64(b"burn_amount", payload.amount);
                }
            },
            TransactionType::MultiSig(payload) => {
                transcript.multisig_proof_domain_separator();
                transcript.append_u64(b"multisig_threshold", payload.threshold as u64);
                for key in &payload.participants {
                    transcript.append_public_key(b"multisig_participant", key);
                }

                // Setup the multisig
                state.set_multisig_state(&self.source, payload).await
                    .map_err(VerificationError::State)?;
            },
            TransactionType::InvokeContract(payload) => {
                transcript.invoke_contract_proof_domain_separator();
                transcript.append_hash(b"contract_hash", &payload.contract);
                for (asset, deposit) in &payload.deposits {
                    transcript.append_hash(b"deposit_asset", asset);
                    match deposit {
                        ContractDeposit::Public(amount) => {
                            transcript.append_u64(b"deposit_plain", *amount);
                        },
                        // ContractDeposit::Private { .. } => {
                        //     todo!("private deposit");
                        // }
                    }
                }

                for param in payload.parameters.iter() {
                    transcript.append_message(b"contract_param", param.as_bytes());
                }
            },
            TransactionType::DeployContract(module) => {
                transcript.deploy_contract_proof_domain_separator();

                state.set_contract_module(self.hash(), module).await
                    .map_err(VerificationError::State)?;
            }
        }

        // Finalize the new source commitments

        // Create fake commitments to make `m` (party size) of the bulletproof a power of two.
        let n_dud_commitments = n_commitments
            .checked_next_power_of_two()
            .ok_or(ProofVerificationError::Format)?
            - n_commitments;

        let final_commitments = self
            .source_commitments
            .iter()
            .zip(&new_source_commitments_decompressed)
            .map(|(commitment, new_source_commitment)| {
                (
                    new_source_commitment.as_point().clone(),
                    commitment.commitment.as_point().clone(),
                )
            })
            .chain(value_commitments.into_iter())
            .chain(
                iter::repeat((RistrettoPoint::identity(), CompressedRistretto::identity()))
                    .take(n_dud_commitments),
            )
            .collect();

        // 3. Verify the aggregated RangeProof
        trace!("verifying range proof");

        // range proof will be verified in batch by caller

        Ok((transcript, final_commitments))
    }

    pub async fn verify_batch<'a, T: AsRef<Transaction>, E, B: BlockchainVerificationState<'a, E>>(
        txs: &'a [T],
        state: &mut B,
    ) -> Result<(), VerificationError<E>> {
        trace!("Verifying batch of {} transactions", txs.len());
        let mut sigma_batch_collector = BatchCollector::default();
        let mut prepared = Vec::with_capacity(txs.len());
        for tx in txs {
            let (transcript, commitments) = tx.as_ref().pre_verify(state, &mut sigma_batch_collector).await?;
            prepared.push((transcript, commitments));
        }

        sigma_batch_collector
            .verify()
            .map_err(|_| ProofVerificationError::GenericProof)?;

        RangeProof::verify_batch(
            txs.iter()
                .zip(&mut prepared)
                .map(|(tx, (transcript, commitments))| {
                    tx.as_ref().range_proof
                        .verification_view(transcript, commitments, 64)
                }),
            &BP_GENS,
            &PC_GENS,
        )
        .map_err(ProofVerificationError::from)?;

        Ok(())
    }

    /// Verify one transaction. Use `verify_batch` to verify a batch of transactions.
    pub async fn verify<'a, E, B: BlockchainVerificationState<'a, E>>(
        &'a self,
        state: &mut B,
    ) -> Result<(), VerificationError<E>> {
        let mut sigma_batch_collector = BatchCollector::default();
        let (mut transcript, commitments) = self.pre_verify(state, &mut sigma_batch_collector).await?;

        trace!("Verifying sigma proofs");
        sigma_batch_collector
            .verify()
            .map_err(|_| ProofVerificationError::GenericProof)?;

        trace!("Verifying range proof");
        RangeProof::verify_multiple(
            &self.range_proof,
            &BP_GENS,
            &PC_GENS,
            &mut transcript,
            &commitments,
            BULLET_PROOF_SIZE,
        )
        .map_err(ProofVerificationError::from)?;

        Ok(())
    }

    // Apply the transaction to the state
    async fn apply<'b, 'a: 'b, E, B: BlockchainApplyState<'a, E>>(
        &'a self,
        tx_hash: &'a Hash,
        state: &mut B,
    ) -> Result<(), VerificationError<E>> {
        trace!("Applying transaction data");
        // Update nonce
        state.update_account_nonce(self.get_source(), self.nonce + 1).await
            .map_err(VerificationError::State)?;

        // Apply receiver balances
        match &self.data {
            TransactionType::Transfers(transfers) => {
                for transfer in transfers {
                    // Update receiver balance
                    let current_bal = state
                        .get_receiver_balance(
                            Cow::Borrowed(transfer.get_destination()),
                            Cow::Borrowed(transfer.get_asset()),
                        ).await
                        .map_err(VerificationError::State)?;
    
                    let receiver_ct = transfer
                        .get_ciphertext(Role::Receiver)
                        .decompress()
                        .map_err(ProofVerificationError::from)?;
    
                    *current_bal += receiver_ct;
                }
            },
            TransactionType::Burn(payload) => {
                if payload.asset == XELIS_ASSET {
                    state.add_burned_coins(payload.amount).await
                        .map_err(VerificationError::State)?;
                }
            },
            TransactionType::MultiSig(payload) => {
                state.set_multisig_state(&self.source, payload).await.map_err(VerificationError::State)?;
            },
            TransactionType::InvokeContract(payload) => {
                state.load_contract_module(&payload.contract).await
                    .map_err(VerificationError::State)?;

                let (module, environment) = state.get_contract_module_with_environment(&payload.contract).await
                    .map_err(VerificationError::State)?;

                let block_hash = state.get_block_hash();
                let block = state.get_block();
                let random = DeterministicRandom::new(&payload.contract, block_hash, tx_hash);
                let mut chain_state = ChainState {
                    mainnet: false,
                    debug_mode: false,
                    contract: &payload.contract,
                    block_hash,
                    tx_hash,

                    random,
                    deposits: &payload.deposits,
                    transfers: Vec::new(),
                };

                // Total used gas by the VM
                let (used_gas, success, exit_code) = {
                    // Create the VM
                    let mut vm = VM::new(module, environment);
                    for constant in payload.parameters.iter() {
                        let decompressed = constant.decompress(module.structs(), module.enums())
                            .context("decompress param")?;

                        vm.push_stack(decompressed)
                            .context("push param")?;
                    }

                    // Invoke the entry chunk
                    // This is the first chunk to be called
                    vm.invoke_entry_chunk(payload.chunk_id)
                        .context("invoke entry chunk")?;

                    let context = vm.context_mut();

                    // Set the gas limit for the VM
                    context.set_gas_limit(payload.max_gas);

                    // Configure the context
                    // Note that the VM already include the environment in Context
                    context.insert_ref(&self);
                    context.insert_ref(&block);
                    context.insert_mut(&mut chain_state);

                    // We need to handle the result of the VM
                    let res = vm.run();

                    // To be sure that we don't have any overflow
                    // We take the minimum between the gas used and the max gas
                    let gas_usage = vm.context()
                        .current_gas_usage()
                        .min(payload.max_gas);

                    let (success, exit_code) = match res {
                        Ok(res) => {
                            debug!("Invoke contract {} from TX {} result: {:#}", payload.contract, tx_hash, res);
                            // If the result return 0 as exit code, it means that everything went well
                            let exit_code = res.as_u64().ok();
                            (exit_code == Some(0), exit_code)
                        },
                        Err(err) => {
                            debug!("Invoke contract {} from TX {} error: {:#}", payload.contract, tx_hash, err);
                            (false, None)
                        }
                    };

                    (gas_usage, success, exit_code)
                };

                if success {
                    for transfer in chain_state.transfers {
                        let current_bal = state
                            .get_receiver_balance(
                                Cow::Owned(transfer.destination.clone()),
                                Cow::Owned(transfer.asset.clone()),
                            ).await
                            .map_err(VerificationError::State)?;
    
                        *current_bal += Scalar::from(transfer.amount);

                        // Track the output
                        let output = ContractOutput::Transfer {
                            destination: transfer.destination,
                            asset: transfer.asset,
                            amount: transfer.amount,
                        };
                        state.add_contract_output(&payload.contract, tx_hash, output).await
                            .map_err(VerificationError::State)?;
                    }
                }

                // We store the result of the contract execution
                state.add_contract_result(&payload.contract, tx_hash, exit_code).await
                    .map_err(VerificationError::State)?;

                if used_gas > 0 {
                    // Part of the gas is burned
                    let burned_gas = used_gas * TRANSACTION_FEE_BURN_PERCENT / 100;
                    // Part of the gas is given to the miners as fees
                    let gas_fee = used_gas.checked_sub(burned_gas)
                        .ok_or(VerificationError::GasOverflow)?;
                    // The remaining gas is refunded to the sender
                    let refund_gas = payload.max_gas.checked_sub(used_gas)
                        .ok_or(VerificationError::GasOverflow)?;
    
                    debug!("Invoke contract used gas: {}, burned: {}, fee: {}, refund: {}", used_gas, burned_gas, gas_fee, refund_gas);
                    state.add_burned_coins(burned_gas).await
                        .map_err(VerificationError::State)?;

                    state.add_gas_fee(gas_fee).await
                        .map_err(VerificationError::State)?;
    
                    if refund_gas > 0 {
                        // If we have some funds to refund, we add it to the sender balance
                        // But to prevent any front running, we add to the sender balance by considering him as a receiver.
                        let balance = state.get_receiver_balance(Cow::Borrowed(self.get_source()), Cow::Owned(XELIS_ASSET)).await
                            .map_err(VerificationError::State)?;

                        *balance += Scalar::from(refund_gas);

                        // Track the refund
                        let output = ContractOutput::RefundGas { amount: refund_gas };
                        state.add_contract_output(&payload.contract, tx_hash, output).await
                            .map_err(VerificationError::State)?;
                    }
                }
            },
            TransactionType::DeployContract(module) => {
                state.set_contract_module(tx_hash.clone(), module).await
                    .map_err(VerificationError::State)?;
            }
        }

        Ok(())
    }

    /// Assume the tx is valid, apply it to `state`. May panic if a ciphertext is ill-formed.
    pub async fn apply_without_verify<'a, E, B: BlockchainApplyState<'a, E>>(
        &'a self,
        tx_hash: &'a Hash,
        state: &mut B,
    ) -> Result<(), VerificationError<E>> {
        let transfers_decompressed = if let TransactionType::Transfers(transfers) = &self.data {
            transfers
                .iter()
                .map(DecompressedTransferCt::decompress)
                .collect::<Result<_, DecompressionError>>()
                .map_err(ProofVerificationError::from)?
        } else {
            vec![]
        };

        // We don't verify any proof, we just apply the transaction
        for commitment in &self.source_commitments {
            let asset = &commitment.asset;
            let current_bal_sender = state
                .get_sender_balance(
                    &self.source,
                    asset,
                    &self.reference,
                ).await.map_err(VerificationError::State)?;

            let output = self.get_sender_output_ct(asset, &transfers_decompressed)
                .map_err(ProofVerificationError::from)?;

            // Compute the new final balance for account
            *current_bal_sender -= &output;

            // Update source balance
            state.add_sender_output(
                &self.source,
                &commitment.asset,
                output,
            ).await.map_err(VerificationError::State)?;
        }

        self.apply(tx_hash, state).await
    }

    /// Verify only that the final sender balance is the expected one for each commitment
    /// Then apply ciphertexts to the state
    /// Checks done are: commitment eq proofs only
    pub async fn apply_with_partial_verify<'a, E, B: BlockchainApplyState<'a, E>>(
        &'a self,
        tx_hash: &'a Hash,
        state: &mut B
    ) -> Result<(), VerificationError<E>> {
        trace!("apply with partial verify");
        let mut sigma_batch_collector = BatchCollector::default();

        let transfers_decompressed = if let TransactionType::Transfers(transfers) = &self.data {
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

        let mut transcript = Self::prepare_transcript(self.version, &self.source, self.fee, self.nonce);

        trace!("verifying commitments eq proofs");

        // This contains sender balance updated, output ciphertext, asset commitment
        let mut commitments_changes = Vec::new();

        for (commitment, new_source_commitment) in self
            .source_commitments
            .iter()
            .zip(&new_source_commitments_decompressed)
        {
            // Ciphertext containing all the funds spent for this commitment
            let output = self.get_sender_output_ct(&commitment.asset, &transfers_decompressed)
                .map_err(ProofVerificationError::from)?;

            // Retrieve the balance of the sender
            let mut source_verification_ciphertext = state
                .get_sender_balance(&self.source, &commitment.asset, &self.reference).await
                .map_err(VerificationError::State)?
                .clone();

            // Compute the new final balance for account
            source_verification_ciphertext -= &output;
            transcript.new_commitment_eq_proof_domain_separator();
            transcript.append_hash(b"new_source_commitment_asset", &commitment.asset);
            transcript
                .append_commitment(b"new_source_commitment", &commitment.commitment);

            commitment.proof.pre_verify(
                &owner,
                &source_verification_ciphertext,
                &new_source_commitment,
                &mut transcript,
                &mut sigma_batch_collector,
            )?;

            commitments_changes.push((source_verification_ciphertext, output, &commitment.asset));
        }

        trace!("Verifying sigma proofs");
        sigma_batch_collector
            .verify()
            .map_err(|_| ProofVerificationError::GenericProof)?;

        // Proofs are correct, apply
        for (source_verification_ciphertext, output, asset) in commitments_changes {
            // Update sender final balance for asset
            let current_ciphertext = state
                .get_sender_balance(&self.source, asset, &self.reference)
                .await
                .map_err(VerificationError::State)?;
            *current_ciphertext = source_verification_ciphertext;

            // Update sender output for asset
            state
                .add_sender_output(
                    &self.source,
                    asset,
                    output,
                ).await
                .map_err(VerificationError::State)?;
        }

        self.apply(tx_hash, state).await
    }
}