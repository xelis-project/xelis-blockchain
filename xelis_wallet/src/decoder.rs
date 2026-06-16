use std::future::Future;

use async_trait::async_trait;
use indexmap::IndexMap;
use log::{debug, warn};
use xelis_common::{
    api::{RPCTransaction, RPCTransactionType},
    crypto::{Address, Hash, elgamal::{Ciphertext, DecryptHandle}},
    transaction::{
        ContractDeposit,
        Role,
        TxVersion,
        extra_data::{PlaintextExtraData, PlaintextFlag, UnknownExtraDataFormat}
    }
};
use crate::{
    entry::{DeployInvoke, EntryData, TransferIn, TransferOut},
    error::WalletError,
    storage::EncryptedStorage,
    wallet::{HistoryScanMode, Wallet}
};

// This module is responsible for decoding transactions in which we may be involved
#[async_trait]
pub trait DecoderProvider: Sync {
    // Check if we already stored this transaction in our database, to avoid doing heavy decryption work for nothing
    async fn has_tx_stored(&self, hash: &Hash) -> Result<bool, WalletError>;

    // Decrypt a ciphertext of an asset, and return the amount if we are able to decrypt it
    async fn decrypt_ciphertext_of_asset(&self, ciphertext: Ciphertext, asset: &Hash) -> Result<Option<u64>, WalletError>;

    // Decrypt extra data of a transaction, and return the plaintext if we are able to decrypt it
    fn decrypt_extra_data(&self, cipher: UnknownExtraDataFormat, handle: Option<&DecryptHandle>, role: Role, version: TxVersion) -> Result<PlaintextExtraData, WalletError>;
}

#[async_trait]
impl DecoderProvider for Wallet {
    #[inline(always)]
    async fn has_tx_stored(&self, hash: &Hash) -> Result<bool, WalletError> {
        Wallet::has_tx_stored(self, hash).await.map_err(Into::into)
    }

    #[inline(always)]
    async fn decrypt_ciphertext_of_asset(&self, ciphertext: Ciphertext, asset: &Hash) -> Result<Option<u64>, WalletError> {
        Wallet::decrypt_ciphertext_of_asset(self, ciphertext, asset).await
    }

    #[inline(always)]
    fn decrypt_extra_data(&self, cipher: UnknownExtraDataFormat, handle: Option<&DecryptHandle>, role: Role, version: TxVersion) -> Result<PlaintextExtraData, WalletError> {
        Wallet::decrypt_extra_data(self, cipher, handle, role, version)
    }
}

pub struct StorageDecoderProvider<'a> {
    wallet: &'a Wallet,
    storage: &'a EncryptedStorage,
}

impl<'a> StorageDecoderProvider<'a> {
    pub fn new(wallet: &'a Wallet, storage: &'a EncryptedStorage) -> Self {
        Self {
            wallet,
            storage,
        }
    }
}

#[async_trait]
impl DecoderProvider for StorageDecoderProvider<'_> {
    async fn has_tx_stored(&self, hash: &Hash) -> Result<bool, WalletError> {
        self.storage.has_transaction(hash).map_err(Into::into)
    }

    async fn decrypt_ciphertext_of_asset(&self, ciphertext: Ciphertext, asset: &Hash) -> Result<Option<u64>, WalletError> {
        let max_supply = self.storage.get_asset(asset).await?
            .get_max_supply();
        self.wallet.decrypt_ciphertext_with(ciphertext, max_supply.get_max()).await
    }

    fn decrypt_extra_data(&self, cipher: UnknownExtraDataFormat, handle: Option<&DecryptHandle>, role: Role, version: TxVersion) -> Result<PlaintextExtraData, WalletError> {
        self.wallet.decrypt_extra_data(cipher, handle, role, version)
    }
}

// Decode a transaction in which we may be part
// returns None if we are not part of it
pub async fn decode_transaction<'a, P, F, Fut>(
    provider: &P,
    address: &Address,
    tx: &'a RPCTransaction<'_>,
    scan_mode: HistoryScanMode,
    mut on_asset_detected: F,
) -> Result<Option<EntryData>, WalletError>
where
    P: DecoderProvider,
    F: FnMut(&'a Hash) -> Fut,
    Fut: Future<Output = Result<(), WalletError>> + 'a,
{
    let is_owner = tx.source.get_public_key() == address.get_public_key();

    let entry: Option<EntryData> = match &tx.data {
        RPCTransactionType::Burn(payload) => {
            if is_owner {
                let payload = payload.as_ref();
                on_asset_detected(&payload.asset).await?;

                Some(EntryData::Burn { asset: payload.asset.clone(), amount: payload.amount, fee: tx.fee, nonce: tx.nonce })
            } else {
                None
            }
        },
        RPCTransactionType::Transfers(txs) => {
            let mut transfers_in: Vec<TransferIn> = Vec::new();
            let mut transfers_out: Vec<TransferOut> = Vec::new();

            // Used to check only once if we have processed this TX already
            let mut checked = is_owner;
            for (i, transfer) in txs.iter().enumerate() {
                let destination = transfer.destination.clone().to_public_key();
                if is_owner || destination == *address.get_public_key() {
                    let asset = transfer.asset.as_ref();
                    on_asset_detected(asset).await?;

                    if !scan_mode.all() {
                        continue;
                    }

                    // Check only once if we have processed this TX already
                    if !checked {
                        // Check if we already stored this TX
                        if provider.has_tx_stored(&tx.hash).await? {
                            debug!("Transaction {} was already stored, skipping it", tx.hash);
                            return Ok(None);
                        }
                        checked = true;
                    }

                    // Get the right handle
                    let (role, handle) = if is_owner {
                        (Role::Sender, transfer.sender_handle.as_ref())
                    } else {
                        (Role::Receiver, transfer.receiver_handle.as_ref())
                    };

                    // Decompress commitment it if possible
                    let commitment = transfer.commitment.as_ref().decompress()?;

                    // Same for handle
                    let handle = handle.decompress()?;

                    let extra_data = if let Some(cipher) = transfer.extra_data.as_ref().clone() {
                        match provider.decrypt_extra_data(cipher,  Some(&handle), role, tx.version) {
                            Ok(e) => Some(e),
                            Err(e) => {
                                warn!("Error while decrypting extra data of TX {}: {}", tx.hash, e);
                                Some(PlaintextExtraData::new(None, None, PlaintextFlag::Failed))
                            }
                        }
                    } else {
                        None
                    };

                    debug!("Decrypting amount from TX {} of asset {}", tx.hash, asset);
                    let ciphertext = Ciphertext::new(commitment, handle);
                    let amount = match provider.decrypt_ciphertext_of_asset(ciphertext, asset).await? {
                        Some(v) => v,
                        None => {
                            warn!("Couldn't decrypt the ciphertext of transfer #{} for asset {} in TX {}. Skipping it", i, asset, tx.hash);
                            continue;
                        }
                    };

                    if is_owner {
                        let transfer = TransferOut::new(destination, asset.clone(), amount, extra_data);
                        transfers_out.push(transfer);
                    } else {
                        let transfer = TransferIn::new(asset.clone(), amount, extra_data);
                        transfers_in.push(transfer);
                    }
                }
            }

            if is_owner && !transfers_out.is_empty() { // check that we are owner of this TX
                Some(EntryData::Outgoing { transfers: transfers_out, fee: tx.fee, nonce: tx.nonce })
            } else if !transfers_in.is_empty() { // otherwise, check that we received one or few transfers from it
                Some(EntryData::Incoming { from: tx.source.clone().to_public_key(), transfers: transfers_in })
            } else { // this TX has nothing to do with us, nothing to save
                None
            }
        },
        RPCTransactionType::MultiSig(payload) => {
            if is_owner {
                let payload = payload.as_ref();

                Some(EntryData::MultiSig { participants: payload.participants.clone(), threshold: payload.threshold, fee: tx.fee, nonce: tx.nonce })
            } else {
                None
            }
        },
        RPCTransactionType::InvokeContract(payload) => {
            if is_owner {
                let payload = payload.as_ref();
                let mut deposits = IndexMap::new();

                for (asset, deposit) in payload.deposits.0.iter() {
                    on_asset_detected(&asset).await?;

                    if !scan_mode.all() {
                        continue;
                    }

                    match deposit {
                        ContractDeposit::Public(amount) => {
                            deposits.insert(asset.clone(), *amount);
                        },
                        ContractDeposit::Private { commitment, sender_handle, ..} => {
                            let commitment = commitment.decompress()?;
                            let handle = sender_handle.decompress()?;
                            let ciphertext = Ciphertext::new(commitment, handle);
                            let amount = match provider.decrypt_ciphertext_of_asset(ciphertext, asset).await? {
                                Some(v) => v,
                                None => {
                                    warn!("Couldn't decrypt deposit ciphertext for asset {}. Fallback to zero", asset);
                                    0
                                }
                            };
                            deposits.insert(asset.clone(), amount);
                        }
                    }
                }

                Some(EntryData::InvokeContract { contract: payload.contract.clone(), deposits, received: IndexMap::new(), entry_id: payload.entry_id, fee: tx.fee, max_gas: payload.max_gas, nonce: tx.nonce })
            } else {
                None
            }
        },
        RPCTransactionType::DeployContract(payload) => {
            if is_owner {
                let payload = payload.as_ref();
                let invoke = if let Some(invoke) = payload.invoke.as_ref() {
                    let max_gas = invoke.max_gas;
                    let mut deposits = IndexMap::new();
                    for (asset, deposit) in invoke.deposits.0.iter() {
                        on_asset_detected(&asset).await?;

                        if !scan_mode.all() {
                            continue;
                        }


                        match deposit {
                            ContractDeposit::Public(amount) => {
                                deposits.insert(asset.clone(), *amount);
                            },
                            ContractDeposit::Private { commitment, sender_handle, ..} => {
                                let commitment = commitment.decompress()?;
                                let handle = sender_handle.decompress()?;
                                let ciphertext = Ciphertext::new(commitment, handle);
                                let amount = match provider.decrypt_ciphertext_of_asset(ciphertext, asset).await? {
                                    Some(v) => v,
                                    None => {
                                        warn!("Couldn't decrypt deposit ciphertext for asset {}. Skipping it", asset);
                                        continue;
                                    }
                                };
                                deposits.insert(asset.clone(), amount);
                            }
                        }
                    }

                    Some(DeployInvoke {
                        max_gas,
                        deposits,
                    })
                } else {
                    None
                };

                Some(EntryData::DeployContract { fee: tx.fee, nonce: tx.nonce, invoke })
            } else {
                None
            }
        },
        RPCTransactionType::Blob(payload) => {
            let role = if is_owner {
                Some(Role::Sender)
            } else if payload.destinations.contains(address) {
                Some(Role::Receiver)
            } else {
                None
            };

            if let Some(role) = role {
                let data = payload.data.as_ref().clone();
                let decrypted = match provider.decrypt_extra_data(data,  None, role, tx.version) {
                    Ok(e) => e,
                    Err(e) => {
                        warn!("Error while decrypting extra data of TX {}: {}", tx.hash, e);
                        PlaintextExtraData::new(None, None, PlaintextFlag::Failed)
                    }
                };
                let destinations = payload.destinations
                    .iter()
                    .map(|address| address.clone().to_public_key())
                    .collect();
                Some(if is_owner {
                    EntryData::OutgoingBlob {
                        destinations,
                        fee: tx.fee,
                        nonce: tx.nonce,
                        data: decrypted
                    }
                } else {
                    EntryData::IncomingBlob {
                        from: tx.source.get_public_key().clone(),
                        destinations,
                        data: decrypted
                    }
                })
            } else {
                None
            }
        }
    };

    Ok(entry)
}
