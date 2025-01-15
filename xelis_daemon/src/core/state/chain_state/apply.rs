use std::{
    borrow::Cow,
    collections::{hash_map::Entry, HashMap},
    ops::{Deref, DerefMut}
};
use async_trait::async_trait;
use log::{debug, trace};
use xelis_common::{
    account::{BalanceType, Nonce, VersionedNonce},
    block::{Block, BlockVersion, TopoHeight},
    contract::{ChainState as ContractChainState, ContractCache, ContractOutput, DeterministicRandom},
    crypto::{elgamal::Ciphertext, Hash, PublicKey},
    transaction::{
        verify::{BlockchainApplyState, BlockchainVerificationState, ContractEnvironment},
        InvokeContractPayload,
        MultiSigPayload,
        Reference
    }
};
use xelis_vm::Environment;
use crate::core::{
    error::BlockchainError,
    storage::{Storage, VersionedContract, VersionedContractBalance, VersionedContractData, VersionedMultiSig}
};

use super::{ChainState, StorageReference, Echange};

// Chain State that can be applied to the mutable storage
pub struct ApplicableChainState<'a, S: Storage> {
    inner: ChainState<'a, S>,
    block_hash: &'a Hash,
    block: &'a Block,
    contracts_outputs: HashMap<&'a Hash, Vec<ContractOutput>>,
    contracts_cache: HashMap<&'a Hash, ContractCache>, 
    burned_supply: u64,
}

#[async_trait]
impl<'a, S: Storage> BlockchainVerificationState<'a, BlockchainError> for ApplicableChainState<'a, S> {
    /// Pre-verify the TX
    async fn pre_verify_tx<'b>(
        &'b mut self,
        tx: &xelis_common::transaction::Transaction,
    ) -> Result<(), BlockchainError> {
        self.inner.pre_verify_tx(tx).await
    }

    /// Get the balance ciphertext for a receiver account
    async fn get_receiver_balance<'b>(
        &'b mut self,
        account: Cow<'a, PublicKey>,
        asset: Cow<'a, Hash>,
    ) -> Result<&'b mut Ciphertext, BlockchainError> {
        self.inner.get_receiver_balance(account, asset).await
    }

    /// Get the balance ciphertext used for verification of funds for the sender account
    async fn get_sender_balance<'b>(
        &'b mut self,
        account: &'a PublicKey,
        asset: &'a Hash,
        reference: &Reference,
    ) -> Result<&'b mut Ciphertext, BlockchainError> {
        self.inner.get_sender_balance(account, asset, reference).await
    }

    /// Apply new output to a sender account
    async fn add_sender_output(
        &mut self,
        account: &'a PublicKey,
        asset: &'a Hash,
        output: Ciphertext,
    ) -> Result<(), BlockchainError> {
        self.inner.add_sender_output(account, asset, output).await
    }

    /// Get the nonce of an account
    async fn get_account_nonce(
        &mut self,
        account: &'a PublicKey
    ) -> Result<Nonce, BlockchainError> {
        self.inner.get_account_nonce(account).await
    }

    async fn update_account_nonce(
        &mut self,
        account: &'a PublicKey,
        new_nonce: Nonce
    ) -> Result<(), BlockchainError> {
        self.inner.update_account_nonce(account, new_nonce).await
    }

    /// Get the block version
    fn get_block_version(&self) -> BlockVersion {
        self.block_version
    }

    async fn set_multisig_state(
        &mut self,
        account: &'a PublicKey,
        config: &MultiSigPayload
    ) -> Result<(), BlockchainError> {
        self.inner.set_multisig_state(account, config).await
    }

    async fn get_multisig_state(
        &mut self,
        account: &'a PublicKey
    ) -> Result<Option<&MultiSigPayload>, BlockchainError> {
        self.inner.get_multisig_state(account).await
    }

    async fn get_environment(&mut self) -> Result<&Environment, BlockchainError> {
        self.inner.get_environment().await
    }

    async fn set_contract_module(
        &mut self,
        hash: &'a Hash,
        module: &'a xelis_vm::Module
    ) -> Result<(), BlockchainError> {
        self.inner.set_contract_module(hash, module).await
    }

    async fn load_contract_module(
        &mut self,
        hash: &'a Hash
    ) -> Result<(), BlockchainError> {
        self.inner.load_contract_module(hash).await
    }

    async fn get_contract_module_with_environment(
        &self,
        hash: &'a Hash
    ) -> Result<(&xelis_vm::Module, &Environment), BlockchainError> {
        self.inner.get_contract_module_with_environment(hash).await
    }
}

#[async_trait]
impl<'a, S: Storage> BlockchainApplyState<'a, S, BlockchainError> for ApplicableChainState<'a, S> {
    /// Track burned supply
    async fn add_burned_coins(&mut self, amount: u64) -> Result<(), BlockchainError> {
        self.burned_supply += amount;
        Ok(())
    }

    /// Track miner fees
    async fn add_gas_fee(&mut self, amount: u64) -> Result<(), BlockchainError> {
        self.gas_fee += amount;
        Ok(())
    }

    fn get_block_hash(&self) -> &Hash {
        &self.block_hash
    }

    fn get_block(&self) -> &Block {
        self.block
    }

    fn is_mainnet(&self) -> bool {
        self.inner.storage.is_mainnet()
    }

    async fn set_contract_outputs(
        &mut self,
        tx_hash: &'a Hash,
        outputs: Vec<ContractOutput>
    ) -> Result<(), BlockchainError> {
        match self.contracts_outputs.entry(tx_hash) {
            Entry::Occupied(mut o) => {
                o.get_mut().extend(outputs);
            },
            Entry::Vacant(e) => {
                e.insert(outputs);
            }
        };

        Ok(())
    }

    async fn get_contract_environment_for<'b>(&'b mut self, payload: &'b InvokeContractPayload, tx_hash: &'b Hash) -> Result<(ContractEnvironment<'b, S>, ContractChainState<'b>), BlockchainError> {
        // Find the contract module in our cache
        // We don't use the function `get_contract_module_with_environment` because we need to return the mutable storage
        let module = self.inner.contracts.get(&payload.contract)
            .ok_or_else(|| BlockchainError::ContractNotFound(payload.contract.clone()))
            .and_then(|(_, module)| module.as_ref()
                .map(|m| m.as_ref())
                .ok_or_else(|| BlockchainError::ContractNotFound(payload.contract.clone()))
            )?;

        // Find the contract cache in our cache map
        let cache = self.contracts_cache.get(&payload.contract);

        // Create a deterministic random for the contract
        let random = DeterministicRandom::new(&payload.contract, &self.block_hash, tx_hash);

        let state = ContractChainState {
            debug_mode: true,
            mainnet: self.inner.storage.is_mainnet(),
            contract: &payload.contract,
            topoheight: self.inner.topoheight,
            block_hash: self.block_hash,
            block: self.block,
            deposits: &payload.deposits,
            random,
            tx_hash,
            cache,
            changes: ContractCache::new(),
        };

        let contract_environment = ContractEnvironment {
            environment: self.inner.environment,
            module,
            provider: self.inner.storage.as_mut(),
        };

        Ok((contract_environment, state))
    }

    async fn merge_contract_cache(
        &mut self,
        hash: &'a Hash,
        cache: ContractCache
    ) -> Result<(), BlockchainError> {
        match self.contracts_cache.entry(hash) {
            Entry::Occupied(mut o) => {
                let current = o.get_mut();
                current.merge(cache);
            },
            Entry::Vacant(e) => {
                e.insert(cache);
            }
        };

        Ok(())
    }
}

impl<'a, S: Storage> Deref for ApplicableChainState<'a, S> {
    type Target = ChainState<'a, S>;

    fn deref(&self) -> &ChainState<'a, S> {
        &self.inner
    }
}

impl<'a, S: Storage> DerefMut for ApplicableChainState<'a, S> {
    fn deref_mut(&mut self) -> &mut ChainState<'a, S> {
        &mut self.inner
    }
}

impl<'a, S: Storage> AsRef<ChainState<'a, S>> for ApplicableChainState<'a, S> {
    fn as_ref(&self) -> &ChainState<'a, S> {
        &self.inner
    }
}

impl<'a, S: Storage> AsMut<ChainState<'a, S>> for ApplicableChainState<'a, S> {
    fn as_mut(&mut self) -> &mut ChainState<'a, S> {
        &mut self.inner
    }
}

impl<'a, S: Storage> ApplicableChainState<'a, S> {
    pub fn new(
        storage: &'a mut S,
        environment: &'a Environment,
        stable_topoheight: TopoHeight,
        topoheight: TopoHeight,
        block_version: BlockVersion,
        burned_supply: u64,
        block_hash: &'a Hash,
        block: &'a Block,
    ) -> Self {
        Self {
            inner: ChainState::with(
                StorageReference::Mutable(storage),
                environment,
                stable_topoheight,
                topoheight,
                block_version,
            ),
            burned_supply,
            contracts_outputs: HashMap::new(),
            contracts_cache: HashMap::new(),
            block_hash,
            block
        }
    }

    // Get the storage used by the chain state
    pub fn get_mut_storage(&mut self) -> &mut S {
        self.inner.storage.as_mut()
    }

    // Get the contract outputs for TX
    pub fn get_contract_outputs_for_tx(&self, tx_hash: &Hash) -> Option<&Vec<ContractOutput>> {
        self.contracts_outputs.get(tx_hash)
    }

    // This function is called after the verification of all needed transactions
    // This will consume ChainState and apply all changes to the storage
    // In case of incoming and outgoing transactions in same state, the final balance will be computed
    pub async fn apply_changes(mut self) -> Result<(), BlockchainError> {
        // Apply changes for sender accounts
        for (key, account) in &mut self.inner.accounts {
            trace!("Saving nonce {} for {} at topoheight {}", account.nonce, key.as_address(self.inner.storage.is_mainnet()), self.inner.topoheight);
            self.inner.storage.set_last_nonce_to(key, self.inner.topoheight, &account.nonce).await?;

            // Save the multisig state if needed
            if let Some((state, multisig)) = account.multisig.as_ref().filter(|(state, _)| state.should_be_stored()) {
                trace!("Saving multisig for {} at topoheight {}", key.as_address(self.inner.storage.is_mainnet()), self.inner.topoheight);
                let multisig = multisig.as_ref().map(|v| Cow::Borrowed(v));
                let versioned = VersionedMultiSig::new(multisig, state.get_topoheight());
                self.inner.storage.set_last_multisig_to(key, self.inner.topoheight, versioned).await?;
            }

            let balances = self.inner.receiver_balances.entry(Cow::Borrowed(key)).or_insert_with(HashMap::new);
            // Because account balances are only used to verify the validity of ZK Proofs, we can't store them
            // We have to recompute the final balance for each asset using the existing current balance
            // Otherwise, we could have a front running problem
            // Example: Alice sends 100 to Bob, Bob sends 100 to Charlie
            // But Bob built its ZK Proof with the balance before Alice's transaction
            for (asset, echange) in account.assets.drain() {
                trace!("{} {} updated for {} at topoheight {}", echange.version, asset, key.as_address(self.inner.storage.is_mainnet()), self.inner.topoheight);
                let Echange { mut version, output_sum, output_balance_used, new_version, .. } = echange;
                trace!("sender output sum: {:?}", output_sum.compress());
                match balances.entry(Cow::Borrowed(asset)) {
                    Entry::Occupied(mut o) => {
                        trace!("{} already has a balance for {} at topoheight {}", key.as_address(self.inner.storage.is_mainnet()), asset, self.inner.topoheight);
                        // We got incoming funds while spending some
                        // We need to split the version in two
                        // Output balance is the balance after outputs spent without incoming funds
                        // Final balance is the balance after incoming funds + outputs spent
                        // This is a necessary process for the following case:
                        // Alice sends 100 to Bob in block 1000
                        // But Bob build 2 txs before Alice, one to Charlie and one to David
                        // First Tx of Blob is in block 1000, it will be valid
                        // But because of Alice incoming, the second Tx of Bob will be invalid
                        let final_version = o.get_mut();

                        // We got input and output funds, mark it
                        final_version.set_balance_type(BalanceType::Both);

                        // We must build output balance correctly
                        // For that, we use the same balance before any inputs
                        // And deduct outputs
                        // let clean_version = self.storage.get_new_versioned_balance(key, asset, self.topoheight).await?;
                        // let mut output_balance = clean_version.take_balance();
                        // *output_balance.computable()? -= &output_sum;

                        // Determine which balance to use as next output balance
                        // This is used in case TXs that are built at same reference, but
                        // executed in differents topoheights have the output balance reported
                        // to the next topoheight each time to stay valid during ZK Proof verification
                        let output_balance = version.take_balance_with(output_balance_used);

                        // Set to our final version the new output balance
                        final_version.set_output_balance(Some(output_balance));

                        // Build the final balance
                        // All inputs are already added, we just need to substract the outputs
                        let final_balance = final_version.get_mut_balance().computable()?;
                        *final_balance -= output_sum;
                    },
                    Entry::Vacant(e) => {
                        trace!("{} has no balance for {} at topoheight {}", key.as_address(self.inner.storage.is_mainnet()), asset, self.inner.topoheight);
                        // We have no incoming update for this key
                        // Select the right final version
                        // For that, we must check if we used the output balance and/or if we are not on the last version 
                        let version = if output_balance_used || !new_version {
                            // We must fetch again the version to sum it with the output
                            // This is necessary to build the final balance
                            let (mut new_version, _) = self.inner.storage.get_new_versioned_balance(key, asset, self.inner.topoheight).await?;
                            // Substract the output sum
                            trace!("{} has no balance for {} at topoheight {}, substract output sum", key.as_address(self.inner.storage.is_mainnet()), asset, self.inner.topoheight);
                            *new_version.get_mut_balance().computable()? -= output_sum;

                            if self.inner.block_version == BlockVersion::V0 {
                                new_version.set_balance_type(BalanceType::Output);
                            } else {
                                // Report the output balance to the next topoheight
                                // So the edge case where:
                                // Balance at topo 1000 is referenced
                                // Balance updated at topo 1001 as input
                                // TX A is built with reference 1000 but executed at topo 1002
                                // TX B reference 1000 but output balance is at topo 1002 and it include the final balance of (TX A + input at 1001)
                                // So we report the output balance for next TX verification
                                new_version.set_output_balance(Some(version.take_balance_with(output_balance_used)));
                                new_version.set_balance_type(BalanceType::Both);
                            }

                            new_version
                        } else {
                            // Version was based on final balance, all good, nothing to do
                            version.set_balance_type(BalanceType::Output);
                            version
                        };

                        // We have some output, mark it

                        e.insert(version);
                    }
                }
            }
        }

        // Apply all the contract storage changes
        for (contract, cache) in self.contracts_cache {
            // Apply all storage changes
            for (key, (state, value)) in cache.storage {
                if state.should_be_stored() {
                    trace!("Saving contract data {} key {} at topoheight {}", contract, key, self.inner.topoheight);
                    self.inner.storage.set_last_contract_data_to(&contract, &key, self.inner.topoheight, VersionedContractData::new(value, state.get_topoheight())).await?;
                }
            }

            // Apply all the transfers
            for transfer in cache.transfers {
                trace!("Transfering {} {} to {} at topoheight {}", transfer.amount, transfer.asset, transfer.destination.as_address(self.inner.storage.is_mainnet()), self.inner.topoheight);
                let receiver_balance = self.inner.internal_get_receiver_balance(Cow::Owned(transfer.destination), Cow::Owned(transfer.asset)).await?;
                *receiver_balance += transfer.amount;
            }

            for (asset, data) in cache.balances {
                if let Some((state, balance)) = data {
                    if state.should_be_stored() {
                        trace!("Saving contract balance {} for {} at topoheight {}", balance, asset, self.inner.topoheight);
                        self.inner.storage.set_last_contract_balance_to(&contract, &asset, self.inner.topoheight, VersionedContractBalance::new(balance, state.get_topoheight())).await?;
                    }
                }
            }
        }

        // Also store the contracts updated
        for (hash, (state, module)) in self.inner.contracts {
            if state.should_be_stored() {
                trace!("Saving contract {} at topoheight {}", hash, self.inner.topoheight);
                self.inner.storage.set_last_contract_to(&hash, self.inner.topoheight, VersionedContract::new(module, state.get_topoheight())).await?;
            }
        }

        // Apply all the contract outputs
        for (key, outputs) in self.contracts_outputs {
            self.inner.storage.set_contract_outputs_for_tx(&key, outputs).await?;
        }

        // Apply all balances changes at topoheight
        // We injected the sender balances in the receiver balances previously
        for (account, balances) in self.inner.receiver_balances {
            for (asset, version) in balances {
                trace!("Saving versioned balance {} for {} at topoheight {}", version, account.as_address(self.inner.storage.is_mainnet()), self.inner.topoheight);
                self.inner.storage.set_last_balance_to(&account, &asset, self.inner.topoheight, &version).await?;
            }

            // If the account has no nonce set, set it to 0
            if !self.inner.accounts.contains_key(account.as_ref()) && !self.inner.storage.has_nonce(&account).await? {
                debug!("{} has now a balance but without any nonce registered, set default (0) nonce", account.as_address(self.inner.storage.is_mainnet()));
                self.inner.storage.set_last_nonce_to(&account, self.inner.topoheight, &VersionedNonce::new(0, None)).await?;
            }

            // Mark it as registered at this topoheight
            if !self.inner.storage.is_account_registered_for_topoheight(&account, self.inner.topoheight).await? {
                self.inner.storage.set_account_registration_topoheight(&account, self.inner.topoheight).await?;
            }
        }

        trace!("Saving burned supply {} at topoheight {}", self.burned_supply, self.inner.topoheight);
        self.inner.storage.set_burned_supply_at_topo_height(self.inner.topoheight, self.burned_supply)?;

        Ok(())
    }
}
