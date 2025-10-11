use std::{
    borrow::Cow,
    collections::{hash_map::Entry, HashMap},
    ops::{Deref, DerefMut},
    sync::Arc
};
use anyhow::Context;
use async_trait::async_trait;
use log::{debug, trace, warn};
use indexmap::{IndexMap, IndexSet};
use xelis_common::{
    account::{BalanceType, Nonce, VersionedNonce},
    asset::VersionedAssetData,
    block::{Block, BlockVersion, TopoHeight},
    config::{EXTRA_BASE_FEE_BURN_PERCENT, FEE_PER_KB, XELIS_ASSET},
    contract::{
        vm::{self, ContractCaller, InvokeContract},
        AssetChanges,
        ChainState as ContractChainState,
        ContractCache,
        ContractEventTracker,
        ContractLog,
        ModuleMetadata,
        ScheduledExecution
    },
    crypto::{elgamal::Ciphertext, Hash, PublicKey},
    serializer::Serializer,
    transaction::{
        verify::{BlockchainApplyState, BlockchainContractState, BlockchainVerificationState, ContractEnvironment},
        ContractDeposit,
        MultiSigPayload,
        Reference,
        Transaction
    },
    utils::format_xelis,
    versioned_type::VersionedState
};
use xelis_vm::{Environment, Module};
use crate::core::{
    blockchain::tx_kb_size_rounded,
    state::verify_fee,
    error::BlockchainError,
    storage::{
        types::TopoHeightMetadata,
        Storage,
        VersionedContract,
        VersionedContractBalance,
        VersionedContractData,
        VersionedMultiSig,
        VersionedSupply
    }
};

use super::{ChainState, StorageReference, Echange};

struct ContractManager<'a> {
    // logs per caller hash
    logs: HashMap<Cow<'a, Hash>, Vec<ContractLog>>,
    caches: HashMap<Hash, ContractCache>,
    // global assets cache
    assets: HashMap<Hash, Option<AssetChanges>>,
    tracker: ContractEventTracker,
    modules: HashMap<Hash, Option<Arc<Module>>>,
    // Planned executions for the current block
    executions_at_block_end: IndexSet<ScheduledExecution>,
    executions_at_topoheight: HashMap<TopoHeight, IndexSet<ScheduledExecution>>,
}

// Chain State that can be applied to the mutable storage
pub struct ApplicableChainState<'a, S: Storage> {
    inner: ChainState<'a, S>,
    block_hash: &'a Hash,
    block: &'a Block,
    contract_manager: ContractManager<'a>,
    total_fees: u64,
    total_fees_burned: u64,
}

#[async_trait]
impl<'a, S: Storage> BlockchainVerificationState<'a, BlockchainError> for ApplicableChainState<'a, S> {
    /// Verify the TX fee and returns, if required, how much we should refund from
    /// `fee_limit` (left over of fees)
    async fn handle_tx_fee<'b>(&'b mut self, tx: &Transaction, tx_hash: &Hash) -> Result<u64, BlockchainError> {
        let tx_size = tx.size();
        let (mut fees_paid, refund) = verify_fee(self.storage.as_ref(), tx, tx_size, self.topoheight, self.tx_base_fee, self.block_version).await?;
        // Starting V3: burn a % of the extra base fee
        if self.block_version >= BlockVersion::V3 {
            // The extra base fee is (TX FEE PER KB - MIN. FEE PER KB)
            let extra_base_fee = self.tx_base_fee - FEE_PER_KB;
            let tx_base_fee = extra_base_fee * tx_kb_size_rounded(tx.size()) as u64;
            // The burned part is computed above the extra base fee
            let burned_part = tx_base_fee * EXTRA_BASE_FEE_BURN_PERCENT / 100;

            debug!(
                "TX {} fees paid: {} XEL, computed TX base fee: {} XEL, extra base fee: {} XEL, burned part: {} XEL",
                tx_hash,
                format_xelis(fees_paid),
                format_xelis(tx_base_fee),
                format_xelis(extra_base_fee),
                format_xelis(burned_part),
            );

            // Burn a part of the fee
            self.total_fees_burned += burned_part;

            // Remove the burned part from fee
            fees_paid -= burned_part;
        }

        self.total_fees += fees_paid;

        Ok(refund)
    }

    /// Pre-verify the TX
    async fn pre_verify_tx<'b>(
        &'b mut self,
        tx: &Transaction,
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

    async fn get_environment(&mut self) -> Result<&Environment<ModuleMetadata>, BlockchainError> {
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
    ) -> Result<bool, BlockchainError> {
        self.inner.load_contract_module(hash).await
    }

    async fn get_contract_module_with_environment(
        &self,
        hash: &'a Hash
    ) -> Result<(&xelis_vm::Module, &Environment<ModuleMetadata>), BlockchainError> {
        self.inner.get_contract_module_with_environment(hash).await
    }
}

#[async_trait]
impl<'a, S: Storage> BlockchainApplyState<'a, S, BlockchainError> for ApplicableChainState<'a, S> {
    /// Track burned supply
    async fn add_burned_coins(&mut self, asset: &Hash, amount: u64) -> Result<(), BlockchainError> {
        let changes = self.get_asset_changes_for(asset, false).await?;

        let new_supply = changes.circulating_supply.1.checked_sub(amount)
            .context("Circulating supply is lower than burn")?;

        changes.circulating_supply.1 = new_supply;
        changes.circulating_supply.0.mark_updated();

        Ok(())
    }

    /// Track miner fees
    async fn add_gas_fee(&mut self, amount: u64) -> Result<(), BlockchainError> {
        self.gas_fee += amount;
        Ok(())
    }

    /// Add burned XELIS fee
    async fn add_burned_fee(&mut self, amount: u64) -> Result<(), BlockchainError> {
        self.total_fees_burned += amount;
        Ok(())
    }

    fn is_mainnet(&self) -> bool {
        self.inner.storage.is_mainnet()
    }
}

#[async_trait]
impl<'a, S: Storage> BlockchainContractState<'a, S, BlockchainError> for ApplicableChainState<'a, S> {
    async fn set_contract_logs(
        &mut self,
        caller: ContractCaller<'a>,
        logs: Vec<ContractLog>
    ) -> Result<(), BlockchainError> {
        match self.contract_manager.logs.entry(caller.get_hash()) {
            Entry::Occupied(mut o) => {
                o.get_mut().extend(logs);
            },
            Entry::Vacant(e) => {
                e.insert(logs);
            }
        };

        Ok(())
    }

    async fn get_contract_environment_for<'b>(
        &'b mut self,
        contract: Cow<'b, Hash>,
        deposits: Option<&'b IndexMap<Hash, ContractDeposit>>,
        caller: ContractCaller<'b>
    ) -> Result<(ContractEnvironment<'b, S>, ContractChainState<'b>), BlockchainError> {
        debug!("get contract environment for contract {} from caller {}", contract, caller.get_hash());

        // Find the contract module in our cache
        // We don't use the function `get_contract_module_with_environment` because we need to return the mutable storage
        let module = self.inner.contracts.get(&contract)
            .ok_or_else(|| BlockchainError::ContractNotFound(contract.as_ref().clone()))
            .and_then(|(_, module)| module.as_ref()
                .map(|m| m.as_ref())
                .ok_or_else(|| BlockchainError::ContractNotFound(contract.as_ref().clone()))
            )?;

        // Find the contract cache in our cache map
        let mut cache = self.contract_manager.caches.get(&contract)
            .cloned()
            .unwrap_or_default();

        // We need to add the deposits to the balances
        if let Some(deposits) = deposits {
            for (asset, deposit) in deposits.iter() {
                match deposit {
                    ContractDeposit::Public(amount) => match cache.balances.entry(asset.clone()) {
                        Entry::Occupied(mut o) => match o.get_mut() {
                            Some((mut state, balance)) => {
                                state.mark_updated();
                                *balance += amount;
                            },
                            None => {
                                // Balance was already fetched and we didn't had any balance before
                                o.insert(Some((VersionedState::New, *amount)));
                            }
                        },
                        Entry::Vacant(e) => {
                            debug!("loading balance {} for contract {} at maximum topoheight {}", asset, contract, self.topoheight);
                            let (mut state, balance) = self.storage.get_contract_balance_at_maximum_topoheight(&contract, asset, self.topoheight).await?
                                .map(|(topo, balance)| (VersionedState::FetchedAt(topo), balance.take()))
                                .unwrap_or((VersionedState::New, 0));
    
                            state.mark_updated();
                            e.insert(Some((state, balance + amount)));
                        }
                    },
                    ContractDeposit::Private { .. } => {
                        // TODO: we need to add the private deposit to the balance
                    }
                }
            }
        }

        let mainnet = self.inner.storage.is_mainnet();
        let state = ContractChainState {
            // TODO: only available on mainnet & enabled by a config
            debug_mode: !mainnet,
            mainnet,
            // We only provide the current contract cache available
            // others can be lazily added to it
            caches: [(contract.as_ref().clone(), cache)].into_iter().collect(),
            entry_contract: contract,
            topoheight: self.inner.topoheight,
            block_hash: self.block_hash,
            block: self.block,
            caller,
            outputs: Vec::new(),
            // Event trackers
            tracker: self.contract_manager.tracker.clone(),
            // Assets cache owned by this contract
            assets: self.contract_manager.assets.clone(),
            modules: self.contract_manager.modules.clone(),
            // Global caches (all contracts)
            global_caches: &self.contract_manager.caches,
            // This is not shared across TXs, so we create
            // a new empty map each time
            // But the ordering is important, so IndexMap is used
            injected_gas: IndexMap::new(),
            // Scheduled executions for any topoheight
            scheduled_executions: self.contract_manager.executions_at_topoheight.clone(),
            planned_executions: self.contract_manager.executions_at_block_end.clone(),
            allow_executions: true,
        };

        let contract_environment = ContractEnvironment {
            environment: self.inner.environment,
            module,
            provider: self.inner.storage.as_mut(),
        };

        Ok((contract_environment, state))
    }

    /// Retrieve the contract balance used to pay gas
    async fn get_contract_balance_for_gas<'b>(
        &'b mut self,
        contract: &'b Hash,
    ) -> Result<&'b mut (VersionedState, u64), BlockchainError> {
        debug!("get contract {} balance for gas", contract);

        let cache = match self.contract_manager.caches.entry(contract.clone()) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(e) => e.insert(Default::default())
        };

        Ok(match cache.balances.entry(XELIS_ASSET) {
            Entry::Occupied(e) => e.into_mut()
                .as_mut()
                .ok_or_else(|| BlockchainError::NoContractBalance)?,
            Entry::Vacant(e) => {
                debug!("loading gas balance for contract {} at maximum topoheight {}", contract, self.inner.topoheight);
                let (mut state, balance) = self.inner.storage.get_contract_balance_at_maximum_topoheight(contract, &XELIS_ASSET, self.inner.topoheight).await?
                    .map(|(topo, balance)| (VersionedState::FetchedAt(topo), balance.take()))
                    .unwrap_or((VersionedState::New, 0));

                state.mark_updated();
                e.insert(None)
                    .insert((state, balance))
            }
        })
    }

    async fn set_modules_cache(
        &mut self,
        modules: HashMap<Hash, Option<Arc<Module>>>,
    ) -> Result<(), BlockchainError> {
        self.contract_manager.modules = modules;

        Ok(())
    }

    async fn merge_contract_changes(
        &mut self,
        caches: HashMap<Hash, ContractCache>,
        tracker: ContractEventTracker,
        assets: HashMap<Hash, Option<AssetChanges>>,
        executions_block_end: IndexSet<ScheduledExecution>,
        executions_topoheight: HashMap<TopoHeight, IndexSet<ScheduledExecution>>,
    ) -> Result<(), BlockchainError> {
        for (contract, mut cache) in caches {
            cache.clean_up();

            match self.contract_manager.caches.entry(contract) {
                Entry::Occupied(mut o) => {
                    let current = o.get_mut();
                    *current = cache;
                },
                Entry::Vacant(e) => {
                    e.insert(cache);
                }
            };
        }

        self.contract_manager.tracker = tracker;
        self.contract_manager.assets = assets;
        self.contract_manager.executions_at_block_end = executions_block_end;
        self.contract_manager.executions_at_topoheight = executions_topoheight;

        Ok(())
    }

    async fn remove_contract_module(
        &mut self,
        hash: &'a Hash
    ) -> Result<(), BlockchainError> {
        self.remove_contract_module_internal(hash).await
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
        environment: &'a Environment<ModuleMetadata>,
        stable_topoheight: TopoHeight,
        topoheight: TopoHeight,
        block_version: BlockVersion,
        block_hash: &'a Hash,
        block: &'a Block,
        tx_base_fee: u64,
    ) -> Self {
        Self {
            inner: ChainState::with(
                StorageReference::Mutable(storage),
                environment,
                stable_topoheight,
                topoheight,
                block_version,
                tx_base_fee,
            ),
            total_fees: 0,
            total_fees_burned: 0,
            contract_manager: ContractManager {
                logs: HashMap::new(),
                caches: HashMap::new(),
                assets: HashMap::new(),
                modules: HashMap::new(),
                tracker: ContractEventTracker::default(),
                executions_at_block_end: IndexSet::new(),
                executions_at_topoheight: HashMap::new(),
            },
            block_hash,
            block
        }
    }

    // total fees to be paid to the miner
    #[inline]
    pub fn get_total_fees(&self) -> u64 {
        self.total_fees
    }

    // Load the asset changes for supply changes
    pub async fn get_asset_changes_for(&mut self, asset: &Hash, default: bool) -> Result<&mut AssetChanges, BlockchainError> {
        match self.contract_manager.assets.entry(asset.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let topoheight = self.inner.topoheight;
                let changes = match self.inner.storage.get_asset_at_maximum_topoheight(asset, topoheight).await? {
                    Some((topo, data)) => {
                        let (supply_state, supply) = match self.inner.storage.get_circulating_supply_for_asset_at_maximum_topoheight(asset, topoheight).await? {
                            Some((topo, supply)) => (VersionedState::FetchedAt(topo), supply.take()),
                            None => {
                                // if default is not enabled,
                                // return an error about supply
                                if !default {
                                    return Err(BlockchainError::NoCirculatingSupply(asset.clone()))
                                }

                                (VersionedState::New, 0)
                            }
                        };

                        Some(AssetChanges {
                            data: (VersionedState::FetchedAt(topo), data.take()),
                            circulating_supply: (supply_state, supply),
                        })
                    },
                    None => None
                };

                entry.insert(changes)
            }
        }.as_mut().ok_or_else(|| BlockchainError::AssetNotFound(asset.clone()))
    }

    // Get the storage used by the chain state
    pub fn get_mut_storage(&mut self) -> &mut S {
        self.inner.storage.as_mut()
    }

    // Get the contracts cache
    pub fn get_contracts_cache(&self) -> &HashMap<Hash, ContractCache> {
        &self.contract_manager.caches
    }

    // Get the contract tracker
    pub fn get_contract_tracker(&self) -> &ContractEventTracker {
        &self.contract_manager.tracker
    } 

    // Get the contract outputs for TX
    pub fn get_contract_logs_for_tx(&self, tx_hash: &Hash) -> Option<&Vec<ContractLog>> {
        self.contract_manager.logs.get(tx_hash)
    }

    async fn remove_contract_module_internal(
        &mut self,
        hash: &'a Hash
    ) -> Result<(), BlockchainError> {
        let (state, contract) = self.inner.contracts.get_mut(hash)
            .ok_or_else(|| BlockchainError::ContractNotFound(hash.clone()))?;

        state.mark_updated();
        *contract = None;

        Ok(())
    }

    // Execute the given list of scheduled executions
    async fn process_executions(&mut self, executions: impl Iterator<Item = ScheduledExecution>) -> Result<(), BlockchainError> {
        for execution in executions {
            debug!("processing scheduled execution of contract {} with caller {}", execution.contract, execution.hash);

            if let Err(e) = vm::invoke_contract(
                ContractCaller::Scheduled(Cow::Owned(execution.hash.clone()), Cow::Owned(execution.contract.clone())),
                self,
                Cow::Owned(execution.contract.clone()),
                None,
                execution.params.into_iter(),
                execution.max_gas,
                InvokeContract::Chunk(execution.chunk_id, false),
            ).await {
                warn!("failed to process scheduled execution of contract {} with caller {}: {}", execution.contract, execution.hash, e);
            }
        }

        Ok(())
    }

    // Execute all the block end scheduled executions
    pub async fn process_executions_at_block_end(&mut self) -> Result<(), BlockchainError> {
        trace!("process executions at block end");

        let executions = std::mem::take(&mut self.contract_manager.executions_at_block_end);
        self.process_executions(executions.into_iter()).await
    }

    // Execute all scheduled executions for current topoheight
    pub async fn process_scheduled_executions(&mut self) -> Result<(), BlockchainError> {
        trace!("process executions at block end");

        let topoheight = self.inner.topoheight;

        // Do it in batches of 64 to avoid loading too much in memory at once
        let mut skip = 0;
        loop {
            let executions = self.storage.get_contract_scheduled_executions_at_topoheight(topoheight).await?
                .skip(skip)
                .take(64)
                .collect::<Result<Vec<_>, _>>()?;

            if executions.is_empty() {
                break;
            }

            skip += executions.len();
            self.process_executions(executions.into_iter()).await?;
        }

        debug!("finished processing {} scheduled executions for topoheight {}", skip, topoheight);

        Ok(())
    }

    // This function is called after the verification of all needed transactions
    // This will consume ChainState and apply all changes to the storage
    // In case of incoming and outgoing transactions in same state, the final balance will be computed
    pub async fn apply_changes(mut self, past_emitted_supply: u64, block_reward: u64) -> Result<(), BlockchainError> {
        trace!("apply changes");

        // Copy the value to prevent immutable borrow
        let total_fees_burned = self.total_fees_burned;
        // if we have some burned fees, reduce it from supply
        if total_fees_burned > 0 {
            self.add_burned_coins(&XELIS_ASSET, total_fees_burned).await?;
        }

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

        // Apply the assets
        for (asset, changes) in self.contract_manager.assets {
            if let Some(changes) = changes {
                let (state, data) = changes.data;
                if state.should_be_stored() {
                    trace!("Saving asset {} at topoheight {}", asset, self.inner.topoheight);
                    self.inner.storage.add_asset(&asset, self.inner.topoheight, VersionedAssetData::new(data, state.get_topoheight())).await?;
                }

                let (state, supply) = changes.circulating_supply;
                if state.should_be_stored() {
                    trace!("Saving supply {} for {} at topoheight {} with prev {:?}", supply, asset, self.inner.topoheight, state.get_topoheight());
                    self.inner.storage.set_last_circulating_supply_for_asset(&asset, self.inner.topoheight, &VersionedSupply::new(supply, state.get_topoheight())).await?;
                }
            }
        }

        // Start by storing the contracts
        debug!("Storing contracts");
        for (hash, (state, module)) in self.inner.contracts.iter() {
            if state.should_be_stored() {
                trace!("Saving contract {} at topoheight {}", hash, self.inner.topoheight);
                // Prevent cloning the value
                let module = module.as_ref()
                    .map(|v| Cow::Borrowed(v.as_ref()));
                self.inner.storage.set_last_contract_to(&hash, self.inner.topoheight, &VersionedContract::new(module, state.get_topoheight())).await?;
            }
        }

        debug!("Storing contract storage changes");
        // Apply all the contract storage changes
        for (contract, cache) in self.contract_manager.caches {
            // Apply all storage changes
            for (key, value) in cache.storage {
                if let Some((state, value)) = value {
                    if state.should_be_stored() {
                        trace!("Saving contract data {} key {} at topoheight {}", contract, key, self.inner.topoheight);
                        self.inner.storage.set_last_contract_data_to(&contract, &key, self.inner.topoheight, &VersionedContractData::new(value, state.get_topoheight())).await?;
                    }
                }
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

        debug!("applying external transfers");
        // Apply all the transfers to the receiver accounts
        for (key, assets) in self.contract_manager.tracker.aggregated_transfers {
            for (asset, amount) in assets {
                trace!("Transfering {} {} to {} at topoheight {}", amount, asset, key.as_address(self.inner.storage.is_mainnet()), self.inner.topoheight);
                let receiver_balance = self.inner.internal_get_receiver_balance(Cow::Owned(key.clone()), Cow::Owned(asset)).await?;
                *receiver_balance += amount;
            }
        }

        // Apply all the contract outputs
        debug!("storing contract outputs");
        for (key, logs) in self.contract_manager.logs {
            self.inner.storage.set_contract_logs_for_tx(&key, &logs).await?;
        }

        // Apply all scheduled executions at their topoheight
        debug!("applying scheduled executions at topoheights");
        for (execution_topoheight, executions) in self.contract_manager.executions_at_topoheight {
            for execution in executions {
                trace!("storing scheduled execution of contract {} with caller {} at topoheight {}", execution.contract, execution.hash, self.inner.topoheight);
                self.inner.storage.set_contract_scheduled_execution_at_topoheight(&execution.contract, self.inner.topoheight, &execution, execution_topoheight).await?;
            }
        }

        // Apply all balances changes at topoheight
        // We injected the sender balances in the receiver balances previously
        debug!("applying balances");
        for (account, balances) in self.inner.receiver_balances {
            // If the account has no nonce set, set it to 0
            if !self.inner.accounts.contains_key(account.as_ref()) && !self.inner.storage.has_nonce(&account).await? {
                debug!("{} has now a balance but without any nonce registered, set default (0) nonce", account.as_address(self.inner.storage.is_mainnet()));
                self.inner.storage.set_last_nonce_to(&account, self.inner.topoheight, &VersionedNonce::new(0, None)).await?;
            }

            // Mark it as registered at this topoheight
            if !self.inner.storage.is_account_registered_for_topoheight(&account, self.inner.topoheight).await? {
                self.inner.storage.set_account_registration_topoheight(&account, self.inner.topoheight).await?;
            }

            for (asset, version) in balances {
                trace!("Saving versioned balance {} for {} at topoheight {}", version, account.as_address(self.inner.storage.is_mainnet()), self.inner.topoheight);
                self.inner.storage.set_last_balance_to(&account, &asset, self.inner.topoheight, &version).await?;
            }
        }

        // Finally, update the topoheight metadata
        debug!("updating topoheight metadata to {}", self.inner.topoheight);
        let emitted_supply = past_emitted_supply + block_reward;
        let metadata = TopoHeightMetadata {
            block_reward,
            emitted_supply,
            total_fees: self.total_fees,
            total_fees_burned,
        };

        self.inner.storage.set_metadata_at_topoheight(self.inner.topoheight, metadata).await?;

        Ok(())
    }
}
