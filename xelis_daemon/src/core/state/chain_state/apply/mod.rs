mod finalized;
mod contract;
mod provider;

use std::{
    borrow::Cow,
    collections::{HashMap, hash_map::Entry},
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
use anyhow::Context;
use async_trait::async_trait;
use log::{Level, debug, trace, warn};
use indexmap::{IndexMap, IndexSet};
use xelis_common::{
    account::Nonce,
    block::{Block, BlockVersion, TopoHeight},
    config::{EXTRA_BASE_FEE_BURN_PERCENT, FEE_PER_KB, XELIS_ASSET},
    contract::{
        AssetChanges,
        ChainState as ContractChainState,
        ChainStateChanges,
        ContractCache,
        ContractEventTracker,
        ContractLogs,
        ContractMetadata,
        ContractModule,
        ContractVersion,
        EventCallbackRegistration,
        ExecutionsChanges,
        ExecutionsManager,
        InterContractPermission,
        ScheduledExecution,
        Source,
        vm::{self, ContractCaller, ContractError, InvokeContract}
    },
    crypto::{Hash, PublicKey, elgamal::Ciphertext},
    serializer::Serializer,
    transaction::{
        ContractDeposit,
        MultiSigPayload,
        Reference,
        Transaction,
        verify::{
            BlockchainApplyState,
            BlockchainContractState,
            BlockchainVerificationState,
            ContractEnvironment
        }
    },
    utils::format_xelis,
    versioned::VersionedState
};
use xelis_vm::{Environment, ValueCell};
use crate::core::{
    blockchain::{ContractEnvironments, tx_kb_size_rounded},
    state::verify_fee,
    error::BlockchainError,
};

use super::ChainState;

pub use finalized::*;
pub use contract::ContractManager;
pub use provider::ApplicableChainStateProvider;

fn calculate_burned_extra_base_fee(tx_extra_base_fee: u64) -> Result<u64, BlockchainError> {
    Ok(tx_extra_base_fee.checked_mul(EXTRA_BASE_FEE_BURN_PERCENT)
        .ok_or(BlockchainError::ConsensusOverflow)? / 100)
}

// Chain State that can be applied to the mutable storage
// 's is the storage lifetime, 'b is the block data lifetime
pub struct ApplicableChainState<'s, 'b, P: ApplicableChainStateProvider> {
    inner: ChainState<'s, 'b, P>,
    block_hash: &'b Hash,
    block: &'b Block,
    is_side_block: bool,
    contract_manager: ContractManager<'b>,
    total_fees: u64,
    total_fees_burned: u64,
    // Transactions links to store: tx hash -> (blocks linked, executed in, contract)
    transactions_links: HashMap<&'b Hash, (IndexSet<&'b Hash>, Option<&'b Hash>, Option<&'b Hash>)>,
    // used for logs of contracts are executed in block
    log_level: Level,
}

#[async_trait]
impl<'s, 'b, P: ApplicableChainStateProvider> BlockchainVerificationState<'b, BlockchainError> for ApplicableChainState<'s, 'b, P> {
    /// Verify the TX fee and returns, if required, how much we should refund from
    /// `fee_limit` (left over of fees)
    async fn handle_tx_fee<'c>(&'c mut self, tx: &Transaction, tx_hash: &Hash) -> Result<u64, BlockchainError> {
        let tx_size = tx.size();
        let (mut fees_paid, refund) = verify_fee(self.provider, tx, tx_size, self.topoheight, self.tx_base_fee, self.block_version).await?;
        // Starting V3: burn a % of the extra base fee
        if self.block_version >= BlockVersion::V3 {
            // The extra base fee is (TX FEE PER KB - MIN. FEE PER KB)
            let extra_base_fee = self.tx_base_fee.checked_sub(FEE_PER_KB)
                .ok_or(BlockchainError::ConsensusOverflow)?;
            let tx_extra_base_fee = extra_base_fee.checked_mul(tx_kb_size_rounded(tx.size()) as u64)
                .ok_or(BlockchainError::ConsensusOverflow)?;
            // The burned part is computed above the extra base fee
            let burned_part = calculate_burned_extra_base_fee(tx_extra_base_fee)?;

            // Remove the burned part from fee
            fees_paid = fees_paid.checked_sub(burned_part)
                .ok_or(BlockchainError::ConsensusOverflow)?;

            debug!(
                "TX {} fees: {}, fees paid: {} XEL, computed TX base fee: {} XEL, extra base fee: {} XEL, burned part: {} XEL",
                tx_hash,
                format_xelis(tx.get_fee()),
                format_xelis(fees_paid),
                format_xelis(tx_extra_base_fee),
                format_xelis(extra_base_fee),
                format_xelis(burned_part),
            );

            // Burn a part of the fee
            self.total_fees_burned = self.total_fees_burned.checked_add(burned_part)
                .ok_or(BlockchainError::ConsensusOverflow)?;
        }

        self.total_fees = self.total_fees.checked_add(fees_paid)
            .ok_or(BlockchainError::ConsensusOverflow)?;

        Ok(refund)
    }

    /// Pre-verify the TX
    async fn pre_verify_tx<'c>(
        &'c mut self,
        tx: &Transaction,
    ) -> Result<(), BlockchainError> {
        self.inner.pre_verify_tx(tx).await
    }

    async fn pre_verify_tx_dynamic<'c>(
        &'c mut self,
        tx: &Transaction,
    ) -> Result<(), BlockchainError> {
        self.inner.pre_verify_tx_dynamic(tx).await
    }

    /// Get the balance ciphertext for a receiver account
    async fn get_receiver_balance<'c>(
        &'c mut self,
        account: Cow<'b, PublicKey>,
        asset: Cow<'b, Hash>,
    ) -> Result<&'c mut Ciphertext, BlockchainError> {
        self.inner.get_receiver_balance(account, asset).await
    }

    /// Get the balance ciphertext used for verification of funds for the sender account
    async fn get_sender_balance<'c>(
        &'c mut self,
        account: &'b PublicKey,
        asset: &'b Hash,
        reference: &Reference,
    ) -> Result<&'c mut Ciphertext, BlockchainError> {
        self.inner.get_sender_balance(account, asset, reference).await
    }

    /// Apply new output to a sender account
    async fn add_sender_output(
        &mut self,
        account: &'b PublicKey,
        asset: &'b Hash,
        output: Ciphertext,
    ) -> Result<(), BlockchainError> {
        self.inner.add_sender_output(account, asset, output).await
    }

    /// Get the nonce of an account
    async fn get_account_nonce(
        &mut self,
        account: &'b PublicKey
    ) -> Result<Nonce, BlockchainError> {
        self.inner.get_account_nonce(account).await
    }

    async fn update_account_nonce(
        &mut self,
        account: &'b PublicKey,
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
        account: &'b PublicKey,
        config: &MultiSigPayload
    ) -> Result<(), BlockchainError> {
        self.inner.set_multisig_state(account, config).await
    }

    async fn get_multisig_state(
        &mut self,
        account: &'b PublicKey
    ) -> Result<Option<&MultiSigPayload>, BlockchainError> {
        self.inner.get_multisig_state(account).await
    }

    async fn get_environment(&mut self, version: ContractVersion) -> Result<&Environment<ContractMetadata>, BlockchainError> {
        self.inner.get_environment(version).await
    }

    async fn set_contract_module(
        &mut self,
        hash: &'b Hash,
        module: &'b ContractModule
    ) -> Result<(), BlockchainError> {
        self.inner.set_contract_module(hash, module).await
    }

    async fn load_contract_module(
        &mut self,
        hash: Cow<'b, Hash>
    ) -> Result<bool, BlockchainError> {
        self.inner.load_contract_module(hash).await
    }

    async fn is_contract_module_new(
        &mut self,
        hash: Cow<'b, Hash>
    ) -> Result<bool, BlockchainError> {
        self.inner.is_contract_module_new(hash).await
    }

    async fn get_contract_module_with_environment(
        &self,
        hash: &'b Hash
    ) -> Result<(&xelis_vm::Module, &Environment<ContractMetadata>), BlockchainError> {
        self.inner.get_contract_module_with_environment(hash).await
    }
}

#[async_trait]
impl<'s, 'b, 'ty, P: ApplicableChainStateProvider> BlockchainApplyState<'b, 'ty, P, BlockchainError> for ApplicableChainState<'s, 'b, P> {
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
        self.gas_fee = self.gas_fee.checked_add(amount)
            .ok_or(BlockchainError::GasOverflow)?;
        Ok(())
    }

    /// Add burned XELIS fee
    async fn add_burned_fee(&mut self, amount: u64) -> Result<(), BlockchainError> {
        self.total_fees_burned = self.total_fees_burned.checked_add(amount)
            .ok_or(BlockchainError::ConsensusOverflow)?;
        Ok(())
    }

    fn is_mainnet(&self) -> bool {
        self.inner.provider.is_mainnet()
    }
}

#[async_trait]
impl<'s, 'b, 'ty, P: ApplicableChainStateProvider> BlockchainContractState<'b, 'ty, P, BlockchainError> for ApplicableChainState<'s, 'b, P> {
    async fn set_contract_logs(
        &mut self,
        caller: ContractCaller<'b>,
        logs: ContractLogs
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

    async fn get_contract_environment_for<'c>(
        &'c mut self,
        contract_hash: Cow<'c, Hash>,
        deposits: Option<&'c IndexMap<Hash, ContractDeposit>>,
        caller: ContractCaller<'c>,
        permission: Cow<'c, InterContractPermission>,
    ) -> Result<(ContractEnvironment<'c, 'ty, P>, ContractChainState<'c>), BlockchainError> {
        debug!("get contract environments for contract {} from caller {}", contract_hash, caller.get_hash());

        // Find the contract module in our cache
        // We don't use the function `get_contract_module_with_environment` because we need to return the mutable storage
        let contract = self.inner.internal_get_contract_module(&contract_hash).await?;

        // Starting V6, we fully clone the contract, not just its references
        // Find the contract cache in our cache map
        // We apply the deposits below in case we have any
        let mut cache = self.contract_manager.caches.get(&contract_hash)
            .map(|c| c.clone_with(self.block_version < BlockVersion::V6))
            .unwrap_or_default();

        // We need to add the deposits to the balances
        if let Some(deposits) = deposits {
            for (asset, deposit) in deposits.iter() {
                match deposit {
                    ContractDeposit::Public(amount) => match cache.balances.entry(asset.clone()) {
                        Entry::Occupied(mut o) => match o.get_mut() {
                            Some((mut state, balance)) => {
                                state.mark_updated();
                                *balance = balance.checked_add(*amount)
                                    .ok_or(BlockchainError::ContractError(ContractError::BalanceOverflow))?;
                            },
                            None => {
                                // Balance was already fetched and we didn't had any balance before
                                o.insert(Some((VersionedState::New, *amount)));
                            }
                        },
                        Entry::Vacant(e) => {
                            debug!("loading balance {} for contract {} at maximum topoheight {}", asset, contract_hash, self.topoheight);
                            let (mut state, balance) = self.inner.provider.get_contract_balance_at_maximum_topoheight(&contract_hash, asset, self.inner.topoheight).await?
                                .map(|(topo, balance)| (VersionedState::FetchedAt(topo), balance.take()))
                                .unwrap_or((VersionedState::New, 0));
    
                            state.mark_updated();
                            let balance = balance.checked_add(*amount)
                                .ok_or(BlockchainError::ContractError(ContractError::BalanceOverflow))?;
                            e.insert(Some((state, balance)));
                        }
                    },
                    ContractDeposit::Private { .. } => {
                        // TODO: we need to add the private deposit to the balance
                    }
                }
            }
        }

        let mainnet = self.inner.provider.is_mainnet();

        // We initialize the cache map with only the current contract
        // because we've applied the deposits for it
        let caches = [
            (contract_hash.as_ref().clone(), cache)
        ].into();

        let state = ContractChainState {
            log_level: self.log_level,
            mainnet,
            entry_contract: contract_hash,
            topoheight: self.inner.topoheight,
            block_hash: self.block_hash,
            block: self.block,
            block_version: self.block.get_version(),
            caller,
            logs: ContractLogs::default(),
            changes: ChainStateChanges {
                caches,
                // Event trackers
                tracker: self.contract_manager.tracker.clone(),
                // Assets cache owned by this contract
                assets: self.contract_manager.assets.clone(),
                ..Default::default()
            },
            global_modules: &self.inner.contracts,
            // Global caches (all contracts)
            global_caches: &self.contract_manager.caches,
            // This is not shared across TXs, so we create
            // a new empty map each time
            // But the ordering is important, so IndexMap is used
            injected_gas: IndexMap::new(),
            // Scheduled executions for any topoheight
            executions: ExecutionsManager {
                global_executions: &self.contract_manager.executions.executions,
                changes: Default::default(),
                allow_executions: true,
            },
            permission,
            gas_fee_allowance: 0,
            environments: Cow::Borrowed(self.inner.environments),
            loaded_modules: Default::default(),
        };

        let environment = self.environments.get(&contract.version)
            .ok_or(BlockchainError::ContractEnvironmentNotFound(contract.version))?;

        let contract_environment = ContractEnvironment {
            environment,
            module: &contract.module,
            version: contract.version,
            provider: self.inner.provider,
            _phantom: PhantomData,
        };

        Ok((contract_environment, state))
    }

    /// Retrieve the contract balance used to pay gas
    async fn get_contract_balance_for_gas<'c>(
        &'c mut self,
        contract: &'c Hash,
    ) -> Result<&'c mut (VersionedState, u64), BlockchainError> {
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
                let (mut state, balance) = self.inner.provider.get_contract_balance_at_maximum_topoheight(contract, &XELIS_ASSET, self.inner.topoheight).await?
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
        modules: HashMap<Hash, Option<(VersionedState, Option<ContractModule>)>>,
    ) -> Result<(), BlockchainError> {
        for (hash, value) in modules {
            debug!("set module cache for contract {}", hash);
            self.inner.contracts.insert(
                Cow::Owned(hash),
                value.map(|(state, module)| (state, module.map(Cow::Owned)))
            );
        }

        Ok(())
    }

    async fn merge_contract_changes(
        &mut self,
        changes: ChainStateChanges,
        mut executions_changes: ExecutionsChanges,
    ) -> Result<(), BlockchainError> {
        for (contract, mut cache) in changes.caches {
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

        self.contract_manager.tracker = changes.tracker;
        self.contract_manager.assets = changes.assets;

        for (hash, execution) in executions_changes.executions {
            self.contract_manager.executions.executions.insert(hash, execution);
        }

        self.contract_manager.executions.at_topoheight.append(&mut executions_changes.at_topoheight);
        self.contract_manager.executions.block_end.append(&mut executions_changes.block_end);

        self.contract_manager.events.extend(changes.events);

        for (key, mut listeners) in changes.events_listeners {
            match self.contract_manager.events_listeners.entry(key) {
                Entry::Occupied(mut o) => {
                    o.get_mut().append(&mut listeners);
                },
                Entry::Vacant(e) => {
                    e.insert(listeners);
                }
            };
        }

        self.add_gas_fee(changes.extra_gas_fee).await?;

        Ok(())
    }

    async fn remove_contract_module(
        &mut self,
        hash: &'b Hash
    ) -> Result<(), BlockchainError> {
        self.remove_contract_module_internal(hash).await
    }

    async fn post_contract_execution(
        &mut self,
        caller: &ContractCaller<'b>,
        contract: &Hash,
    ) -> Result<(), BlockchainError> {
        trace!("post contract execution for caller {} on contract {}", caller.get_hash(), contract);
        self.execute_callback_events(caller.get_hash().as_ref()).await
    }
}

impl<'s, 'b, P: ApplicableChainStateProvider> Deref for ApplicableChainState<'s, 'b, P> {
    type Target = ChainState<'s, 'b, P>;

    fn deref(&self) -> &ChainState<'s, 'b, P> {
        &self.inner
    }
}

impl<'s, 'b, P: ApplicableChainStateProvider> DerefMut for ApplicableChainState<'s, 'b, P> {
    fn deref_mut(&mut self) -> &mut ChainState<'s, 'b, P> {
        &mut self.inner
    }
}

impl<'s, 'b, P: ApplicableChainStateProvider> AsRef<ChainState<'s, 'b, P>> for ApplicableChainState<'s, 'b, P> {
    fn as_ref(&self) -> &ChainState<'s, 'b, P> {
        &self.inner
    }
}

impl<'s, 'b, P: ApplicableChainStateProvider> AsMut<ChainState<'s, 'b, P>> for ApplicableChainState<'s, 'b, P> {
    fn as_mut(&mut self) -> &mut ChainState<'s, 'b, P> {
        &mut self.inner
    }
}

impl<'s, 'b, P: ApplicableChainStateProvider> ApplicableChainState<'s, 'b, P> {
    pub fn new(
        storage: &'s P,
        environments: &'s ContractEnvironments,
        stable_topoheight: TopoHeight,
        topoheight: TopoHeight,
        block_version: BlockVersion,
        block_hash: &'b Hash,
        block: &'b Block,
        is_side_block: bool,
        tx_base_fee: u64,
        base_height: u64,
        log_level: Level,
    ) -> Self {
        Self {
            inner: ChainState::new(
                storage,
                environments,
                stable_topoheight,
                topoheight,
                topoheight,
                block_version,
                tx_base_fee,
                base_height,
            ),
            total_fees: 0,
            total_fees_burned: 0,
            contract_manager: ContractManager::default(),
            block_hash,
            block,
            is_side_block,
            transactions_links: HashMap::new(),
            log_level,
        }
    }

    // Returns if the TX was already executed
    #[inline]
    pub fn link_tx_to_block(&mut self, tx_hash: &'b Hash, block_hash: &'b Hash, contract: Option<&'b Hash>) -> bool {
        let (set, executed, contract_called) = self.transactions_links.entry(tx_hash)
            .or_insert_with(|| (IndexSet::new(), None, None));

        set.insert(block_hash);
        if let Some(contract) = contract {
            *contract_called = Some(contract);
        }

        executed.is_some()
    }

    // Mark the TX as executed in the given block
    #[inline]
    pub fn mark_tx_as_executed_in_block(&mut self, tx_hash: &'b Hash, block_hash: &'b Hash) -> Result<(), BlockchainError> {
        let (set, executed, _) = self.transactions_links.get_mut(tx_hash)
            .ok_or(BlockchainError::NoLinkedBlocksForTransaction)?;

        set.insert(block_hash);

        if executed.is_some() {
            return Err(BlockchainError::TransactionAlreadyExecuted(tx_hash.clone()));
        }

        *executed = Some(block_hash);

        Ok(())
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
                let changes = match self.inner.provider.get_asset_at_maximum_topoheight(asset, topoheight).await? {
                    Some((topo, data)) => {
                        let (supply_state, supply) = match self.inner.provider.get_circulating_supply_for_asset_at_maximum_topoheight(asset, topoheight).await? {
                            Some((topo, supply)) => (VersionedState::FetchedAt(topo), supply.take()),
                            None => {
                                // if default is not enabled,
                                // return an error about supply
                                if !default {
                                    return Err(BlockchainError::UnknownAssetCirculatingSupply(asset.clone()))
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

    // Get the contracts cache
    pub fn get_contracts_cache(&self) -> &HashMap<Hash, ContractCache> {
        &self.contract_manager.caches
    }

    // Get the contract tracker
    pub fn get_contract_tracker(&self) -> &ContractEventTracker {
        &self.contract_manager.tracker
    } 

    // Get the contract outputs for TX
    pub fn get_contract_logs_for_tx(&self, tx_hash: &Hash) -> Option<&ContractLogs> {
        self.contract_manager.logs.get(tx_hash)
    }

    async fn remove_contract_module_internal(
        &mut self,
        hash: &'b Hash
    ) -> Result<(), BlockchainError> {
        debug!("Removing contract module for contract {}", hash);

        let (state, contract) = self.inner.internal_get_versioned_contract(Cow::Borrowed(hash)).await?
            .as_mut()
            .ok_or_else(|| BlockchainError::ContractNotFound(hash.clone()))?;

        state.mark_updated();
        *contract = None;

        Ok(())
    }

    // Execute all the callback events registered during contract executions
    async fn execute_callback_events(&mut self, caller: &Hash) -> Result<(), BlockchainError> {
        debug!("executing callback events after processing execution {}", caller);

        while let Some(event) = self.contract_manager.events.pop_front() {
            debug!("executing event callback {} for contract {}", event.event_id, event.contract);

            // If we've already processed those from storage, we must handle those pending in memory
            let contract_key = (event.contract.clone(), event.event_id);
            let callbacks = match self.contract_manager.events_processed.entry(contract_key.clone()) {
                Entry::Occupied(_) => {
                    debug!("event {} for contract {} already processed from storage, getting pending callbacks from memory", event.event_id, event.contract);
                    // we don't need to include them into our processed list, because we just delete them from registrations
                    self.contract_manager.events_listeners.remove(&contract_key)
                        .unwrap_or_default()
                },
                Entry::Vacant(entry) => {
                    debug!("event {} for contract {} not yet processed, loading from storage", event.event_id, event.contract);
                    let topoheight = self.inner.topoheight;
                    let mut callbacks = self.inner.provider.get_event_callbacks_available_at_maximum_topoheight(&event.contract, event.event_id, topoheight).await?;

                    // Sort by contract hash to have a deterministic order
                    callbacks.sort_by(|a, b| a.0.cmp(&b.0));

                    // Only storage callbacks need a tombstone written on apply
                    entry.insert(
                        callbacks.iter()
                            .map(|(contract, _)| contract.clone())
                            .collect()
                    );

                    // Also fire listeners registered in this same block before the event was emitted.
                    // They are consumed here, removed from events_listeners, and must NOT be added
                    // to events_processed because they were never stored (no tombstone needed).
                    let mem_callbacks = self.contract_manager.events_listeners
                        .remove(&contract_key)
                        .unwrap_or_default();
                    callbacks.extend(mem_callbacks);
                    callbacks.sort_by(|a, b| a.0.cmp(&b.0));

                    callbacks
                }
            };

            for (listener_contract, mut callback) in callbacks {
                debug!("processing event callback of {}", listener_contract);
                if self.block_version >= BlockVersion::V7
                    && !self.collateralize_legacy_event_callback(&listener_contract, &mut callback).await?
                {
                    warn!(
                        "skipping unfunded or invalid legacy event callback of {} with max gas {}",
                        listener_contract,
                        callback.max_gas,
                    );
                    continue;
                }

                self.process_execution(
                    Cow::Owned(listener_contract.clone()),
                    ContractCaller::EventCallback(Cow::Owned(caller.clone()), Cow::Owned(event.contract.clone())),
                    callback.gas_sources,
                    callback.max_gas,
                    callback.chunk_id,
                    event.params.iter().map(|v| v.deep_clone()),
                    // disable the post hook execution to prevent stack overflow
                    false,
                ).await?;
            }
        }

        Ok(())
    }

    // Event callback registrations made by a non-transaction caller before V7
    // recorded Source::Contract without reserving the corresponding balance.
    // At V7, collateralize those pending legacy registrations before execution.
    // New V7 registrations use Source::ContractBalance and were already debited.
    async fn collateralize_legacy_event_callback(
        &mut self,
        listener_contract: &Hash,
        callback: &mut EventCallbackRegistration,
    ) -> Result<bool, BlockchainError> {
        if callback.gas_sources.len() != 1 {
            return Ok(false);
        }

        let Some((source, gas)) = callback.gas_sources.first().map(|(source, gas)| (source.clone(), *gas)) else {
            return Ok(false);
        };

        if gas == 0 || gas != callback.max_gas {
            return Ok(false);
        }

        match source {
            Source::Contract(contract) => {
                if &contract != listener_contract {
                    return Ok(false);
                }

                let (state, balance) = self.get_contract_balance_for_gas(&contract).await?;
                if *balance < gas {
                    return Ok(false);
                }

                state.mark_updated();
                *balance = balance.checked_sub(gas)
                    .ok_or(BlockchainError::GasOverflow)?;

                callback.gas_sources = [(
                    Source::ContractBalance(contract),
                    gas,
                )].into();
                Ok(true)
            },
            Source::ContractBalance(contract) => Ok(&contract == listener_contract),
            Source::AccountBalance(_) => Ok(true),
            Source::Account(_) => Ok(false),
        }
    }

    // V7 account-funded liabilities carry Source::AccountBalance. An unmarked
    // Source::Account may have been created before V7 from unbacked injected
    // headroom, so it cannot safely execute or refund after the fork. When such
    // a legacy execution also has contract-funded sources, return only those
    // independently collateralized contract amounts.
    async fn prepare_scheduled_execution_for_v7(
        &mut self,
        execution: &ScheduledExecution,
    ) -> Result<bool, BlockchainError> {
        if self.block_version < BlockVersion::V7 {
            return Ok(true);
        }

        let mut total_sources = 0u64;
        let mut has_legacy_account_source = false;
        let mut contract_refunds = HashMap::<Hash, u64>::new();

        for (source, gas) in execution.gas_sources.iter() {
            total_sources = match total_sources.checked_add(*gas) {
                Some(total) => total,
                None => return Ok(false),
            };

            match source {
                Source::Account(_) => {
                    has_legacy_account_source = true;
                },
                Source::AccountBalance(_) => {},
                Source::Contract(contract) => {
                    if contract != &execution.contract {
                        return Ok(false);
                    }

                    let refund = contract_refunds.entry(contract.clone()).or_insert(0);
                    *refund = match refund.checked_add(*gas) {
                        Some(refund) => refund,
                        None => return Ok(false),
                    };
                },
                Source::ContractBalance(_) => return Ok(false),
            }
        }

        if total_sources != execution.max_gas {
            return Ok(false);
        }

        if !has_legacy_account_source {
            return Ok(true);
        }

        for (contract, refund) in contract_refunds.iter() {
            let (_, balance) = self.get_contract_balance_for_gas(contract).await?;
            if balance.checked_add(*refund).is_none() {
                return Ok(false);
            }
        }

        for (contract, refund) in contract_refunds {
            let (state, balance) = self.get_contract_balance_for_gas(&contract).await?;
            state.mark_updated();
            *balance = balance.checked_add(refund)
                .ok_or(BlockchainError::GasOverflow)?;
        }

        Ok(false)
    }

    // Execute the given list of scheduled executions
    async fn process_execution(
        &mut self,
        contract: Cow<'b, Hash>,
        caller: ContractCaller<'b>,
        gas_sources: IndexMap<Source, u64>,
        max_gas: u64,
        chunk_id: u16,
        params: impl DoubleEndedIterator<Item = ValueCell> + ExactSizeIterator,
        post_hook: bool,
    ) -> Result<(), BlockchainError> {
        debug!("processing scheduled execution of contract {} with caller {}", contract, caller.get_hash());

        if !self.load_contract_module(contract.clone()).await? {
            warn!("failed to load contract module for scheduled execution of contract {} with caller {}", contract, caller.get_hash());
            vm::refund_gas_sources(self, gas_sources, 0, max_gas).await
                .map_err(|err| match err {
                    vm::ContractStateError::State(err) => err,
                    vm::ContractStateError::Contract(err) => BlockchainError::ContractError(err),
                })?;
            return Ok(());
        }

        if let Err(e) = vm::invoke_contract(
            caller.clone(),
            self,
            contract.clone(),
            None,
            params,
            gas_sources,
            max_gas,
            InvokeContract::Chunk(chunk_id, false),
            Cow::Owned(InterContractPermission::All),
            post_hook,
        ).await {
            warn!("failed to process execution of contract {} with caller {}: {}", contract, caller.get_hash(), e);
        }

        Ok(())
    }

    // Execute all the block end scheduled executions
    pub async fn process_executions_at_block_end(&mut self) -> Result<(), BlockchainError> {
        trace!("process executions at block end");

        // We loop over it,
        // Contract can't re define a block at end execution
        // But it is used by the listener events callbacks
        loop {
            let executions = std::mem::take(&mut self.contract_manager.executions.block_end);
            if executions.is_empty() {
                debug!("no more block end scheduled executions to process");
                break;
            }

            for execution in executions {
                let execution = self.contract_manager.executions.executions.remove(&execution)
                    .ok_or(BlockchainError::ScheduledExecutionNotFound)?;

                debug!(
                    "executing block-end scheduled execution {} for contract {} at topoheight {}",
                    execution.hash,
                    execution.contract,
                    self.inner.topoheight,
                );

                if !self.prepare_scheduled_execution_for_v7(&execution).await? {
                    warn!(
                        "skipping invalid or legacy-unmarked block-end scheduled execution {}",
                        execution.hash,
                    );
                    continue;
                }

                self.process_execution(
                    Cow::Owned(execution.contract.clone()),
                    ContractCaller::Scheduled(Cow::Owned(execution.hash.as_ref().clone()), Cow::Owned(execution.contract.clone())),
                    execution.gas_sources,
                    execution.max_gas,
                    execution.chunk_id,
                    execution.params.into_iter(),
                    true,
                ).await?;
            }
        }

        Ok(())
    }

    // Execute all scheduled executions for current topoheight
    pub async fn process_scheduled_executions(&mut self) -> Result<(), BlockchainError> {
        trace!("process executions at block end");

        let topoheight = self.inner.topoheight;

        let mut executions = self.inner.provider.get_contract_scheduled_executions_for_execution_topoheight(topoheight).await?;

        executions.sort();

        for hash in executions.iter() {
            let execution = self.inner.provider.get_contract_scheduled_execution_at_topoheight(hash, topoheight).await?;

            debug!(
                "executing scheduled execution {} for contract {} at execution topoheight {}",
                execution.hash,
                execution.contract,
                topoheight,
            );

            if !self.prepare_scheduled_execution_for_v7(&execution).await? {
                warn!(
                    "skipping invalid or legacy-unmarked scheduled execution {} at topoheight {}",
                    execution.hash,
                    topoheight,
                );
                continue;
            }

            self.process_execution(
                Cow::Owned(execution.contract.clone()),
                ContractCaller::Scheduled(Cow::Owned(execution.hash.as_ref().clone()), Cow::Owned(execution.contract.clone())),
                execution.gas_sources,
                execution.max_gas,
                execution.chunk_id,
                execution.params.into_iter(),
                true,
            ).await?;
        }

        debug!("finished processing {} scheduled executions for topoheight {}", executions.len(), topoheight);

        Ok(())
    }

    // This function is called after the verification of all needed transactions
    // This will consume ChainState and apply all changes to the storage
    // In case of incoming and outgoing transactions in same state, the final balance will be computed
    pub async fn finalize(mut self, past_emitted_supply: u64, block_reward: u64) -> Result<FinalizedChainState<'b>, BlockchainError> {
        trace!("apply changes");

        // Copy the value to prevent immutable borrow
        let total_fees_burned = self.total_fees_burned;
        // if we have some burned fees, reduce it from supply
        if total_fees_burned > 0 {
            self.add_burned_coins(&XELIS_ASSET, total_fees_burned).await?;
        }

        Ok(FinalizedChainState {
            block_hash: self.block_hash,
            is_side_block: self.is_side_block,
            contract_manager: self.contract_manager,
            total_fees: self.total_fees.checked_add(self.inner.gas_fee)
                .ok_or(BlockchainError::ConsensusOverflow)?,
            total_fees_burned: self.total_fees_burned,
            transactions_links: self.transactions_links,
            receiver_balances: self.inner.receiver_balances,
            accounts: self.inner.accounts,
            topoheight: self.inner.topoheight,
            contracts: self.inner.contracts,
            block_version: self.inner.block_version,
            past_emitted_supply,
            block_reward,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, collections::HashMap, sync::Arc};

    use indexmap::IndexSet;
    use silex_assembler::Assembler;
    use xelis_common::{
        block::{Block, BlockHeader, BlockVersion, EXTRA_NONCE_SIZE},
        contract::{
            build_environment,
            CallbackEvent,
            ContractLog,
            ContractModule,
            ContractVersion,
            EventCallbackRegistration,
            ScheduledExecution,
            ScheduledExecutionKind,
            Source,
        },
        crypto::{Hash, KeyPair},
        network::Network,
        versioned::VersionedState,
    };
    use xelis_vm::Primitive;

    use crate::core::storage::MemoryStorage;

    use super::*;

    fn module_returning(exit_code: u64) -> ContractModule {
        let mut assembler = Assembler::new(
            r#"
                #callback internal
                CONSTANT 0
                RETURN
            "#,
        );
        assembler.add_constant(Primitive::U64(exit_code).into());

        ContractModule {
            version: ContractVersion::V1,
            module: Arc::new(assembler.assemble().expect("assemble callback module")),
        }
    }

    #[tokio::test]
    async fn event_callback_executes_listener_contract() {
        let storage = MemoryStorage::new(Network::Devnet, 1);
        let environments = HashMap::from([(
            ContractVersion::V1,
            Arc::new(build_environment::<MemoryStorage>(ContractVersion::V1).build()),
        )]);
        let block_hash = Hash::new([1u8; 32]);
        let miner = KeyPair::new().get_public_key().compress();
        let block_header = BlockHeader::new(
            BlockVersion::V3,
            0,
            0,
            IndexSet::new(),
            [0u8; EXTRA_NONCE_SIZE],
            miner,
            IndexSet::new(),
        );
        let block = Block::new(block_header, Vec::new());

        let mut state = ApplicableChainState::new(
            &storage,
            &environments,
            0,
            1,
            BlockVersion::V3,
            &block_hash,
            &block,
            false,
            0,
            0,
            Level::Info,
        );

        let emitter = Hash::new([2u8; 32]);
        let listener = Hash::new([3u8; 32]);
        state.inner.contracts.insert(
            Cow::Owned(emitter.clone()),
            Some((VersionedState::New, Some(Cow::Owned(module_returning(1))))),
        );
        state.inner.contracts.insert(
            Cow::Owned(listener.clone()),
            Some((VersionedState::New, Some(Cow::Owned(module_returning(0))))),
        );

        state.contract_manager.events.push_back(CallbackEvent {
            contract: emitter.clone(),
            event_id: 7,
            params: Vec::new(),
        });
        state.contract_manager.events_listeners.insert(
            (emitter, 7),
            vec![(
                listener.clone(),
                EventCallbackRegistration::new(0, 1_000, Source::Contract(listener)),
            )],
        );

        let caller = Hash::new([4u8; 32]);
        state.execute_callback_events(&caller)
            .await
            .expect("execute callback event");

        let exit_codes = state.contract_manager.logs.get(&Cow::Owned(caller))
            .expect("callback logs")
            .iter()
            .filter_map(|log| match log {
                ContractLog::ExitCode(code) => Some(*code),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(exit_codes, vec![Some(0)]);
    }

    #[tokio::test]
    async fn missing_event_callback_module_refunds_reserved_gas() {
        let storage = MemoryStorage::new(Network::Devnet, 1);
        let environments = HashMap::from([(
            ContractVersion::V1,
            Arc::new(build_environment::<MemoryStorage>(ContractVersion::V1).build()),
        )]);
        let block_hash = Hash::new([1u8; 32]);
        let miner = KeyPair::new().get_public_key().compress();
        let block_header = BlockHeader::new(
            BlockVersion::V6,
            0,
            0,
            IndexSet::new(),
            [0u8; EXTRA_NONCE_SIZE],
            miner,
            IndexSet::new(),
        );
        let block = Block::new(block_header, Vec::new());

        let mut state = ApplicableChainState::new(
            &storage,
            &environments,
            0,
            1,
            BlockVersion::V6,
            &block_hash,
            &block,
            false,
            0,
            0,
            Level::Info,
        );

        let emitter = Hash::new([2u8; 32]);
        let listener = Hash::new([3u8; 32]);
        state.inner.contracts.insert(
            Cow::Owned(listener.clone()),
            Some((VersionedState::New, None)),
        );

        state.contract_manager.events.push_back(CallbackEvent {
            contract: emitter.clone(),
            event_id: 7,
            params: Vec::new(),
        });
        state.contract_manager.events_listeners.insert(
            (emitter, 7),
            vec![(
                listener.clone(),
                EventCallbackRegistration::new(0, 1_000, Source::Contract(listener.clone())),
            )],
        );

        let caller = Hash::new([4u8; 32]);
        state.execute_callback_events(&caller)
            .await
            .expect("execute callback event");

        let refunded = {
            let (_, balance) = state.get_contract_balance_for_gas(&listener)
                .await
                .expect("listener gas balance");
            *balance
        };
        assert_eq!(refunded, 1_000);
        assert!(
            state.contract_manager.logs.get(&Cow::Owned(caller)).is_none(),
            "missing module should not emit callback logs"
        );
    }

    #[tokio::test]
    async fn v7_legacy_contract_callback_requires_collateral_before_execution() {
        let storage = MemoryStorage::new(Network::Devnet, 1);
        let environments = HashMap::from([(
            ContractVersion::V1,
            Arc::new(build_environment::<MemoryStorage>(ContractVersion::V1).build()),
        )]);
        let block_hash = Hash::new([1u8; 32]);
        let miner = KeyPair::new().get_public_key().compress();
        let block_header = BlockHeader::new(
            BlockVersion::V7,
            0,
            0,
            IndexSet::new(),
            [0u8; EXTRA_NONCE_SIZE],
            miner,
            IndexSet::new(),
        );
        let block = Block::new(block_header, Vec::new());

        let mut state = ApplicableChainState::new(
            &storage,
            &environments,
            0,
            1,
            BlockVersion::V7,
            &block_hash,
            &block,
            false,
            0,
            0,
            Level::Info,
        );

        let emitter = Hash::new([2u8; 32]);
        let listener = Hash::new([3u8; 32]);
        state.inner.contracts.insert(
            Cow::Owned(listener.clone()),
            Some((VersionedState::New, Some(Cow::Owned(module_returning(0))))),
        );

        state.contract_manager.events.push_back(CallbackEvent {
            contract: emitter.clone(),
            event_id: 7,
            params: Vec::new(),
        });
        state.contract_manager.events_listeners.insert(
            (emitter.clone(), 7),
            vec![(
                listener.clone(),
                EventCallbackRegistration::new(0, 1_000, Source::Contract(listener.clone())),
            )],
        );

        let unfunded_caller = Hash::new([4u8; 32]);
        state.execute_callback_events(&unfunded_caller)
            .await
            .expect("process unfunded legacy callback");
        assert!(
            state.contract_manager.logs.get(&Cow::Owned(unfunded_caller)).is_none(),
            "an unfunded legacy callback must be consumed without execution or refund"
        );

        {
            let (_, balance) = state.get_contract_balance_for_gas(&listener)
                .await
                .expect("listener balance");
            *balance = 1_000;
        }

        state.contract_manager.events.push_back(CallbackEvent {
            contract: emitter.clone(),
            event_id: 7,
            params: Vec::new(),
        });
        state.contract_manager.events_listeners.insert(
            (emitter, 7),
            vec![(
                listener.clone(),
                EventCallbackRegistration::new(0, 1_000, Source::Contract(listener.clone())),
            )],
        );

        let funded_caller = Hash::new([5u8; 32]);
        state.execute_callback_events(&funded_caller)
            .await
            .expect("execute funded legacy callback");
        assert!(
            state.contract_manager.logs.get(&Cow::Owned(funded_caller)).is_some(),
            "a collateralized legacy callback must execute"
        );

        let remaining_balance = {
            let (_, balance) = state.get_contract_balance_for_gas(&listener)
                .await
                .expect("listener balance after callback");
            *balance
        };
        assert_eq!(
            remaining_balance + state.inner.get_gas_fee() + state.total_fees_burned,
            1_000,
            "legacy callback collateral must conserve across refund, fee, and burn"
        );

        let legacy_account = KeyPair::new().get_public_key().compress();
        let mut legacy_account_callback = EventCallbackRegistration::new(
            0,
            1_000,
            Source::Account(legacy_account),
        );
        assert!(
            !state.collateralize_legacy_event_callback(&listener, &mut legacy_account_callback)
                .await
                .expect("validate legacy account callback"),
            "legacy account callbacks cannot be proven funded and must be rejected at V7"
        );

        let mut v7_callback = EventCallbackRegistration::new(
            0,
            1_000,
            Source::ContractBalance(listener.clone()),
        );
        let balance_before_validation = {
            let (_, balance) = state.get_contract_balance_for_gas(&listener)
                .await
                .expect("listener balance before v7 validation");
            *balance
        };
        assert!(
            state.collateralize_legacy_event_callback(&listener, &mut v7_callback)
                .await
                .expect("validate v7 callback"),
            "a marked V7 callback must not require collateralization again"
        );
        let balance_after_validation = {
            let (_, balance) = state.get_contract_balance_for_gas(&listener)
                .await
                .expect("listener balance after v7 validation");
            *balance
        };
        assert_eq!(
            balance_after_validation,
            balance_before_validation,
            "validating a marked V7 callback must not debit its contract twice"
        );
    }

    #[tokio::test]
    async fn v7_rejects_legacy_account_scheduled_execution_and_refunds_backed_contract_part() {
        let storage = MemoryStorage::new(Network::Devnet, 1);
        let environments = HashMap::from([(
            ContractVersion::V1,
            Arc::new(build_environment::<MemoryStorage>(ContractVersion::V1).build()),
        )]);
        let block_hash = Hash::new([1u8; 32]);
        let miner = KeyPair::new().get_public_key().compress();
        let block_header = BlockHeader::new(
            BlockVersion::V7,
            0,
            0,
            IndexSet::new(),
            [0u8; EXTRA_NONCE_SIZE],
            miner,
            IndexSet::new(),
        );
        let block = Block::new(block_header, Vec::new());

        let mut state = ApplicableChainState::new(
            &storage,
            &environments,
            0,
            1,
            BlockVersion::V7,
            &block_hash,
            &block,
            false,
            0,
            0,
            Level::Info,
        );

        let contract = Hash::new([2u8; 32]);
        let legacy_account = KeyPair::new().get_public_key().compress();
        let execution_hash = Arc::new(Hash::new([3u8; 32]));
        let legacy_execution = ScheduledExecution {
            hash: execution_hash,
            contract: contract.clone(),
            chunk_id: 0,
            params: Vec::new(),
            max_gas: 1_000,
            kind: ScheduledExecutionKind::TopoHeight(1),
            gas_sources: [
                (Source::Account(legacy_account), 600),
                (Source::Contract(contract.clone()), 400),
            ].into(),
        };

        assert!(
            !state.prepare_scheduled_execution_for_v7(&legacy_execution)
                .await
                .expect("prepare legacy scheduled execution"),
            "a legacy account source must make the execution ineligible at V7"
        );
        let refunded_contract_balance = {
            let (_, balance) = state.get_contract_balance_for_gas(&contract)
                .await
                .expect("contract refund balance");
            *balance
        };
        assert_eq!(
            refunded_contract_balance,
            400,
            "the independently backed contract portion must be returned exactly once"
        );

        let wrong_domain_execution = ScheduledExecution {
            hash: Arc::new(Hash::new([5u8; 32])),
            contract: contract.clone(),
            chunk_id: 0,
            params: Vec::new(),
            max_gas: 250,
            kind: ScheduledExecutionKind::TopoHeight(1),
            gas_sources: [(Source::ContractBalance(contract.clone()), 250)].into(),
        };
        assert!(
            !state.prepare_scheduled_execution_for_v7(&wrong_domain_execution)
                .await
                .expect("reject event-only marker on scheduled execution"),
            "scheduled executions must reject the event-callback funding marker"
        );
        let balance_after_wrong_marker = {
            let (_, balance) = state.get_contract_balance_for_gas(&contract)
                .await
                .expect("contract balance after wrong marker");
            *balance
        };
        assert_eq!(
            balance_after_wrong_marker,
            400,
            "rejecting an unbacked marker must not issue a refund"
        );

        let marked_account = KeyPair::new().get_public_key().compress();
        let v7_execution = ScheduledExecution {
            hash: Arc::new(Hash::new([4u8; 32])),
            contract,
            chunk_id: 0,
            params: Vec::new(),
            max_gas: 1_000,
            kind: ScheduledExecutionKind::TopoHeight(1),
            gas_sources: [(Source::AccountBalance(marked_account), 1_000)].into(),
        };
        assert!(
            state.prepare_scheduled_execution_for_v7(&v7_execution)
                .await
                .expect("prepare v7 scheduled execution"),
            "a marked V7 account reservation must remain executable"
        );
    }
}
