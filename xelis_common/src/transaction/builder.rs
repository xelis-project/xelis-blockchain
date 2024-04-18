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
    account::CiphertextCache,
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
            PC_GENS,
            BULLET_PROOF_SIZE,
        },
        Address,
        Hash,
        ProtocolTranscript,
        HASH_SIZE,
        SIGNATURE_SIZE
    },
    serializer::{Reader, ReaderError, Serializer, Writer},
    utils::calculate_tx_fee
};
use thiserror::Error;
use super::{
    aead::{derive_aead_key_from_opening, PlaintextData},
    BurnPayload,
    Reference,
    Role,
    SourceCommitment,
    Transaction,
    TransactionType,
    TransferPayload,
    EXTRA_DATA_LIMIT_SIZE,
    MAX_TRANSFER_COUNT
};

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
    #[error("Encrypted extra data is too large")]
    EncryptedExtraDataTooLarge,
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

pub trait FeeHelper {
    type Error;

    /// Get the fee multiplier from wallet if wanted
    fn get_fee_multiplier(&self) -> f64 {
        1f64
    }

    /// Verify if the account exists or if we should pay more fees for account creation
    fn account_exists(&self, account: &CompressedPublicKey) -> Result<bool, Self::Error>;
}

/// If the returned balance and ct do not match, the build function will panic and/or
/// the proof will be invalid.
pub trait AccountState: FeeHelper {

    /// Used to verify if the address is on the same chain
    fn is_mainnet(&self) -> bool;

    /// Get the balance from the source
    fn get_account_balance(&self, asset: &Hash) -> Result<u64, Self::Error>;

    /// Block topoheight at which the transaction is being built
    fn get_reference(&self) -> Reference;

    /// Get the balance ciphertext from the source
    fn get_account_ciphertext(&self, asset: &Hash) -> Result<CiphertextCache, Self::Error>;

    /// Update the balance and the ciphertext
    fn update_account_balance(&mut self, asset: &Hash, new_balance: u64, ciphertext: Ciphertext) -> Result<(), Self::Error>;

    /// Get the nonce of the account
    fn get_nonce(&self) -> Result<u64, Self::Error>;

    /// Update account nonce
    fn update_nonce(&mut self, new_nonce: u64) -> Result<(), Self::Error>;
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
    fee_builder: FeeBuilder
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

    pub fn used_keys(&self) -> HashSet<CompressedPublicKey> {
        let mut used_keys = HashSet::new();

        match &self {
            TransactionTypeBuilder::Transfers(transfers) => {
                for transfer in transfers {
                    used_keys.insert(transfer.destination.get_public_key().clone());
                }
            }
            TransactionTypeBuilder::Burn(_) => {}
        }

        used_keys
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
    reference: Reference,
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
            reference: self.reference,
            signature,
        }
    }
}

impl TransactionBuilder {
    pub fn new(version: u8, source: CompressedPublicKey, data: TransactionTypeBuilder, fee_builder: FeeBuilder) -> Self {
        Self {
            version,
            source,
            data,
            fee_builder,
        }
    }

    /// Estimate by hand the bytes size of a final TX
    // Returns bytes size and transfers count
    fn estimate_size(&self) -> usize {
        let assets_used = self.data.used_assets().len();
        // Version byte
        let mut size = 1
        // Source Public Key
        + self.source.size()
        // Transaction type byte
        + 1
        // Fee u64
        + 8
        // Nonce u64
        + 8
        // Reference (hash, topo)
        + HASH_SIZE + 8
        // Commitments byte length
        + 1
        // We have one source commitment per asset spent
        // assets * (commitment, asset, proof)
        + assets_used * (RISTRETTO_COMPRESSED_SIZE + HASH_SIZE + (RISTRETTO_COMPRESSED_SIZE * 3 + SCALAR_SIZE * 3))
        // Signature
        + SIGNATURE_SIZE
        ;

        let transfers_count = match &self.data {
            TransactionTypeBuilder::Transfers(transfers) => {
                // Transfers count byte
                size += 1;
                for transfer in transfers {
                    size += transfer.asset.size()
                    + transfer.destination.get_public_key().size()
                    // Commitment, sender handle, receiver handle
                    + (RISTRETTO_COMPRESSED_SIZE * 3)
                    // Ct Validity Proof
                    + (RISTRETTO_COMPRESSED_SIZE * 2 + SCALAR_SIZE * 2)
                    // Extra data byte flag
                    + 1;

                    if let Some(extra_data) = &transfer.extra_data {
                        // 2 represents u16 length
                        size += 2 + extra_data.size();
                    }
                }
                transfers.len()
            }
            TransactionTypeBuilder::Burn(payload) => {
                // Payload size
                size += payload.size();
                0
            }
        };

        // Range Proof
        let lg_n = (BULLET_PROOF_SIZE * (transfers_count + assets_used)).next_power_of_two().trailing_zeros() as usize;
        // Fixed size of the range proof
        size += RISTRETTO_COMPRESSED_SIZE * 4 + SCALAR_SIZE * 3
        // u16 bytes length
        + 2
        // Inner Product Proof
        // scalars
        + SCALAR_SIZE * 2
        // G_vec len
        + 2 * RISTRETTO_COMPRESSED_SIZE * lg_n;

        size
    }

    // Estimate the fees for this TX
    pub fn estimate_fees<B: FeeHelper>(&self, state: &mut B) -> Result<u64, GenerationError<B::Error>> {
        let calculated_fee = match self.fee_builder {
            FeeBuilder::Multiplier(multiplier) => {
                // Compute the size and transfers count
                let size = self.estimate_size();
                let (transfers, new_addresses) = if let TransactionTypeBuilder::Transfers(transfers) = &self.data {
                    let mut new_addresses = 0;
                    for transfer in transfers {
                        if !state.account_exists(&transfer.destination.get_public_key()).map_err(GenerationError::State)? {
                            new_addresses += 1;
                        }
                    }

                    (transfers.len(), new_addresses)
                } else {
                    (0, 0)
                };

                let expected_fee = calculate_tx_fee(size, transfers, new_addresses);
                (expected_fee as f64 * multiplier) as u64
            },
            // If the value is set, use it
            FeeBuilder::Value(value) => value
        };

        Ok(calculated_fee)
    }

    fn get_new_source_ct(&self, mut ct: Ciphertext, fee: u64, asset: &Hash, transfers: &[TransferWithCommitment]) -> Ciphertext {
        if asset == &XELIS_ASSET {
            // Fees are applied to the native blockchain asset only.
            ct -= Scalar::from(fee);
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
    pub fn get_transaction_cost(&self, fee: u64, asset: &Hash) -> u64 {
        let mut cost = 0;

        if *asset == XELIS_ASSET {
            // Fees are applied to the native blockchain asset only.
            cost += fee;
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
        let fee = self.estimate_fees(state)?;

        // Get the nonce
        let nonce = state.get_nonce().map_err(GenerationError::State)?;
        state.update_nonce(nonce + 1).map_err(GenerationError::State)?;

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

        let reference = state.get_reference();
        let mut transcript = Transaction::prepare_transcript(self.version, &self.source, fee, nonce);

        let mut range_proof_openings: Vec<_> =
            iter::repeat_with(|| PedersenOpening::generate_new().as_scalar())
                .take(used_assets.len())
                .collect();

        let mut range_proof_values: Vec<_> = used_assets
            .iter()
            .map(|asset| {
                let cost = self.get_transaction_cost(fee, &asset);
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
                    .take_ciphertext()
                    .map_err(|err| GenerationError::Proof(err.into()))?;

                let commitment =
                    PedersenCommitment::new_with_opening(source_new_balance, &new_source_opening)
                    .compress();

                let new_source_ciphertext =
                    self.get_new_source_ct(source_current_ciphertext, fee, &asset, &transfers);

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

                    // Encrypt the extra data if it exists
                    let extra_data = if let Some(extra_data) = transfer.inner.extra_data {
                        let bytes = extra_data.to_bytes();
                        let key = derive_aead_key_from_opening(&transfer.amount_opening);
                        let cipher = PlaintextData(bytes).encrypt_in_place(&key);
                        if cipher.0.len() > EXTRA_DATA_LIMIT_SIZE {
                            return Err(GenerationError::EncryptedExtraDataTooLarge);
                        }

                        Some(cipher)
                    } else {
                        None
                    };

                    Ok(TransferPayload {
                        commitment,
                        receiver_handle,
                        sender_handle,
                        destination: transfer.inner.destination.to_public_key(),
                        asset: transfer.inner.asset,
                        ct_validity_proof,
                        extra_data,
                    })
                })
                .collect::<Result<Vec<_>, GenerationError<B::Error>>>()?;

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
            BULLET_PROOF_SIZE,
        )
        .map_err(ProofGenerationError::from)?;

        let transaction = TransactionSigner {
            version: self.version,
            source: self.source,
            data,
            fee,
            nonce,
            source_commitments,
            reference,
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

        writer.write_u8(self.source_commitments.len() as u8);
        for commitment in &self.source_commitments {
            commitment.write(writer);
        }

        self.range_proof.write(writer);
        self.reference.write(writer);
    }

    // Should never be called
    fn read(_: &mut Reader) -> Result<Self, ReaderError> {
        Err(ReaderError::InvalidValue)
    }
}

#[cfg(test)]
mod tests {
    use bulletproofs::RangeProof;

    use crate::{crypto::{elgamal::{RISTRETTO_COMPRESSED_SIZE, SCALAR_SIZE}, proofs::BULLET_PROOF_SIZE}, serializer::Serializer};

    #[test]
    fn estimate_range_proof_size() {
        let proof_hex = b"cc15f1b1e654ffd25bb89f4069303245d3c477ce93abb380eb4941096c06000006141de8f618c3392c5071bc3b76467bea32bc0d8fbf9257a3c44a59b596825f9a09332365fffdb56060d4fdfba8a513cbab3f607c0812aefec7124914cf796caa1a4263cdc0d3488e3e6b5bd04d524667e2b49bb8f55cf418fd8af8cd23ef667bd574ab23bf8c71b1bf9a5f52a2ca5a9320bf43a6be8bb2cc864a6745e6de07931382c2b90873b690e7da04b6fd9ddd3f22c060aed621da691bd54e0b6e9f0b3283b6fc7bcaa4ba06a7f3151a49ba5082462b8ba76b93b2934b6c99fe9e730572e026e9a85930896d0120d06115e60cb68bc6bd18335288ca01f8591924da7e563ac102237e476357b37ecd834715272c5eb705c5bc3799602d922cfa153665565926daf7df42276e834afe1fa444fabf17e7596f09936bcc27f913053fac3906ce8a10dbe1caf1c1e02428d8f2773fc307ae7c7d2fe63102e605c89efa730a4e217dd6b2481f49803efdc44b25d80236e0c10ecab006136ba423ec75bbf7532286a1d063e16e13903104e8274666169288cb9f65a414a04e3dacb7d368931e647a149554f3c78e326e111e5da221cb4e8152d3525f0b32ff2b814b7352647674f1a36e49f8603e3d3996910f52154b871c72138e288b00b471026638646f201c0c0b358872fa6bc81a2ce1c2f068b4513828eda4def4ae1c2e9c02ef58043412dd31411c5cec7acd9bfdcf5f8ead03f13801bc4bc529726e6b25f85b80db23fc8659a09b8c590a51ec015065d437e77d84b0d3c3d529d1c6301441d2dd335042f64b1ced343c32b25416bd5d43e4ff02d4382cc18f1f5cfc0144decc51ac0d9863f1124589ec6f0fe388b464db7db4d5f16ff101da37a3efed71a4d4514915eccc94dc7832bf4c0b52165ac937e5b0dff2d0a2e7b68802a8759e4bae58815f6e2ec7683006561f27f1855ad8840036c580c81ebadf36ddfdf7470996068c05f186a67cefb751e33b5624d577357372486bae3fd509aea9b6d4c72296afdd05";
        let proof = RangeProof::from_bytes(&hex::decode(proof_hex).unwrap()).unwrap();
        let transfers: usize = 1;
        let assets: usize = 1;
        // Range proof size has a fixed size 
        let mut size: usize = RISTRETTO_COMPRESSED_SIZE * 4 + SCALAR_SIZE * 3;
        // U16
        size += 2;
        // inner product scalars
        size += SCALAR_SIZE * 2;
        // G_vec len
        let lg_n = (BULLET_PROOF_SIZE * (transfers + assets)).next_power_of_two().trailing_zeros() as usize;
        size += 2 * RISTRETTO_COMPRESSED_SIZE * lg_n;
        assert!(proof.size() == size);
    }
}