use std::{
    borrow::Cow,
    collections::{HashMap, VecDeque, hash_map::Entry},
    marker::PhantomData,
    sync::Arc
};

use anyhow::Context;
use async_trait::async_trait;
use curve25519_dalek::{ristretto::CompressedRistretto, traits::Identity};
use indexmap::{IndexMap, IndexSet};
use log::warn;
use xelis_builder::EnvironmentBuilder;
use xelis_vm::{Environment, Module};

use super::MockStorageProvider;

use crate::{
    account::Nonce,
    block::{Block, BlockHeader, BlockVersion, EXTRA_NONCE_SIZE},
    config::XELIS_ASSET,
    contract::{
        build_environment,
        vm::{self, ContractCaller, InvokeContract},
        AssetChanges,
        CallbackEvent,
        ChainState as ContractChainState,
        ChainStateChanges,
        ContractCache,
        ContractEnvironments,
        ContractEventTracker,
        ContractLog,
        ContractMetadata,
        ContractModule,
        ContractVersion,
        EventCallbackRegistration,
        ExecutionsChanges,
        ExecutionsManager,
        InterContractPermission,
        Source,
    },
    crypto::{
        elgamal::{Ciphertext, CompressedPublicKey},
        Hash,
        PublicKey,
    },
    transaction::{
        verify::{
            BlockchainApplyState,
            BlockchainContractState,
            BlockchainVerificationState,
            ContractEnvironment,
        },
        ContractDeposit,
        MultiSigPayload,
        Reference,
        Transaction,
    },
    versioned::VersionedState,
};

#[derive(Debug, Clone)]
pub struct MockAccount {
    pub balances: HashMap<Hash, Ciphertext>,
    pub nonce: Nonce,
}

#[derive(Debug, Clone)]
pub struct MockChainState {
    pub assets: HashMap<Hash, Option<AssetChanges>>,
    pub tracker: ContractEventTracker,
    pub events: VecDeque<CallbackEvent>,
    pub events_listeners: HashMap<(Hash, u64), Vec<(Hash, EventCallbackRegistration)>>,
    pub accounts: HashMap<PublicKey, MockAccount>,
    pub multisig: HashMap<PublicKey, MultiSigPayload>,
    pub contracts: HashMap<Cow<'static, Hash>, Option<(VersionedState, Option<Cow<'static, ContractModule>>)>>,
    pub contract_logs: HashMap<Hash, Vec<ContractLog>>,
    pub burned_coins: HashMap<Hash, u64>,
    pub gas_fee: u64,
    pub burned_fee: u64,
    pub env_builders: HashMap<ContractVersion, Arc<EnvironmentBuilder<'static, ContractMetadata>>>,
    pub environments: ContractEnvironments,
    pub provider: MockStorageProvider,
    pub mainnet: bool,
    pub block_hash: Hash,
    pub block: Block,
    pub contract_caches: HashMap<Hash, ContractCache>,
    pub executions: ExecutionsChanges,
}

impl MockChainState {
    pub fn with(version: BlockVersion) -> Self {
        let header = BlockHeader::new(
            version,
            0,
            0,
            IndexSet::new(),
            [0u8; EXTRA_NONCE_SIZE],
            CompressedPublicKey::new(CompressedRistretto::identity()),
            IndexSet::new(),
        );

        let env_builders: HashMap<ContractVersion, Arc<EnvironmentBuilder<ContractMetadata>>> =
            ContractVersion::variants()
                .into_iter()
                .map(|version| {
                    let env = build_environment::<MockStorageProvider>(version);
                    (version, Arc::new(env))
                })
                .collect();

        Self {
            assets: HashMap::new(),
            tracker: Default::default(),
            events: VecDeque::new(),
            events_listeners: HashMap::new(),
            accounts: HashMap::new(),
            multisig: HashMap::new(),
            contracts: HashMap::new(),
            contract_logs: HashMap::new(),
            burned_coins: HashMap::new(),
            gas_fee: 0,
            burned_fee: 0,
            environments: env_builders
                .iter()
                .map(|(version, env)| (*version, Arc::new(env.environment().clone())))
                .collect(),
            env_builders,
            provider: MockStorageProvider::default(),
            mainnet: false,
            block_hash: Hash::zero(),
            block: Block::new(header, Vec::new()),
            contract_caches: HashMap::new(),
            executions: ExecutionsChanges::default(),
        }
    }

    pub fn new() -> Self {
        Self::with(BlockVersion::V3)
    }

    pub async fn on_post_execution(&mut self, caller: &Hash) -> Result<(), anyhow::Error> {
        while let Some(event) = self.events.pop_front() {
            let contract_key = (event.contract.clone(), event.event_id);
            if let Some(listeners) = self.events_listeners.remove(&contract_key) {
                for (contract, callback) in listeners {
                    if !self.load_contract_module(Cow::Owned(contract.clone())).await? {
                        return Err(anyhow::anyhow!(
                            "contract module {} not found for event callback",
                            contract
                        ));
                    }

                    if let Err(e) = vm::invoke_contract(
                        ContractCaller::EventCallback(
                            Cow::Owned(caller.clone()),
                            Cow::Owned(event.contract.clone()),
                        ),
                        self,
                        Cow::Owned(contract.clone()),
                        None,
                        event.params.iter().map(|p| p.deep_clone()),
                        [(Source::Contract(contract.clone()), callback.max_gas)].into_iter().collect(),
                        callback.max_gas,
                        InvokeContract::Chunk(callback.chunk_id, false),
                        Cow::Owned(InterContractPermission::All),
                        false,
                    )
                    .await
                    {
                        warn!(
                            "failed to process execution of contract {} with caller {}: {}",
                            contract,
                            caller,
                            e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    pub fn set_contract_balance(&mut self, contract: &Hash, asset: &Hash, new_balance: u64) {
        let cache = self
            .contract_caches
            .entry(contract.clone())
            .or_insert_with(Default::default);

        match cache.balances.entry(asset.clone()) {
            Entry::Occupied(mut o) => match o.get_mut() {
                Some((state, balance)) => {
                    state.mark_updated();
                    *balance = new_balance;
                }
                None => {
                    o.insert(Some((VersionedState::New, new_balance)));
                }
            },
            Entry::Vacant(v) => {
                v.insert(Some((VersionedState::New, new_balance)));
            }
        }
    }

    pub fn get_contract_balance(&self, contract: &Hash, asset: &Hash) -> u64 {
        self.contract_caches
            .get(contract)
            .and_then(|cache| cache.balances.get(asset))
            .and_then(|entry| entry.as_ref())
            .map(|(_, balance)| *balance)
            .unwrap_or(0)
    }

    pub fn set_account_balance(&mut self, account: &PublicKey, asset: &Hash, balance: Ciphertext) {
        let acct_state = self
            .accounts
            .entry(account.clone())
            .or_insert_with(|| MockAccount {
                balances: HashMap::new(),
                nonce: 0,
            });

        acct_state.balances.insert(asset.clone(), balance);
    }

    pub fn get_account_balance(&self, account: &PublicKey, asset: &Hash) -> Ciphertext {
        self.accounts
            .get(account)
            .and_then(|state| state.balances.get(asset))
            .cloned()
            .unwrap_or_else(Ciphertext::zero)
    }

    fn internal_load_contract_module(&self, hash: &Hash) -> Result<&ContractModule, anyhow::Error> {
        self.contracts
            .get(hash)
            .context("Contract module not found")?
            .as_ref()
            .context("Contract module not loaded")?
            .1
            .as_ref()
            .context("Contract module not available")
            .map(|m| m.as_ref())
    }

    pub fn internal_set_contract_module(&mut self, hash: Hash, module: ContractModule) {
        self.contracts.insert(
            Cow::Owned(hash),
            Some((VersionedState::New, Some(Cow::Owned(module)))),
        );
    }
}

#[async_trait]
impl<'a> BlockchainVerificationState<'a, anyhow::Error> for MockChainState {
    async fn handle_tx_fee<'b>(&'b mut self, tx: &Transaction, _: &Hash) -> Result<u64, anyhow::Error> {
        Ok(tx.get_fee_limit() - tx.get_fee())
    }

    async fn pre_verify_tx<'b>(&'b mut self, _: &Transaction) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn pre_verify_tx_dynamic<'b>(&'b mut self, _: &Transaction) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn get_receiver_balance<'b>(
        &'b mut self,
        account: Cow<'a, PublicKey>,
        asset: Cow<'a, Hash>,
    ) -> Result<&'b mut Ciphertext, anyhow::Error> {
        self.accounts
            .get_mut(&account)
            .and_then(|account| account.balances.get_mut(&asset))
            .context("Receiver account or balance not found")
    }

    async fn get_sender_balance<'b>(
        &'b mut self,
        account: &'a PublicKey,
        asset: &'a Hash,
        _: &Reference,
    ) -> Result<&'b mut Ciphertext, anyhow::Error> {
        self.accounts
            .get_mut(account)
            .and_then(|account| account.balances.get_mut(asset))
            .context("Sender account or balance not found")
    }

    async fn add_sender_output(
        &mut self,
        _: &'a PublicKey,
        _: &'a Hash,
        _: Ciphertext,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn get_account_nonce(&mut self, account: &'a PublicKey) -> Result<Nonce, anyhow::Error> {
        self.accounts
            .get(account)
            .map(|account| account.nonce)
            .context("Account not found")
    }

    async fn update_account_nonce(
        &mut self,
        account: &'a PublicKey,
        new_nonce: Nonce,
    ) -> Result<(), anyhow::Error> {
        self.accounts
            .get_mut(account)
            .map(|account| account.nonce = new_nonce)
            .context("Account not found")
    }

    fn get_block_version(&self) -> BlockVersion {
        BlockVersion::V0
    }

    async fn set_multisig_state(
        &mut self,
        account: &'a PublicKey,
        multisig: &MultiSigPayload,
    ) -> Result<(), anyhow::Error> {
        self.multisig.insert(account.clone(), multisig.clone());
        Ok(())
    }

    async fn get_multisig_state(
        &mut self,
        account: &'a PublicKey,
    ) -> Result<Option<&MultiSigPayload>, anyhow::Error> {
        Ok(self.multisig.get(account))
    }

    async fn get_environment(
        &mut self,
        version: ContractVersion,
    ) -> Result<&Environment<ContractMetadata>, anyhow::Error> {
        Ok(&self.environments[&version])
    }

    async fn set_contract_module(
        &mut self,
        hash: &'a Hash,
        module: &'a ContractModule,
    ) -> Result<(), anyhow::Error> {
        match self.contracts.entry(Cow::Owned(hash.clone())) {
            Entry::Occupied(mut o) => match o.get_mut() {
                Some((state, m)) => {
                    state.mark_updated();
                    *m = Some(Cow::Owned(module.clone()));
                }
                None => {
                    o.insert(Some((VersionedState::New, Some(Cow::Owned(module.clone())))));
                }
            },
            Entry::Vacant(v) => {
                v.insert(Some((VersionedState::New, Some(Cow::Owned(module.clone())))));
            }
        };

        Ok(())
    }

    async fn load_contract_module(&mut self, hash: Cow<'a, Hash>) -> Result<bool, anyhow::Error> {
        Ok(self.contracts.contains_key(&hash))
    }

    async fn get_contract_module_with_environment(
        &self,
        contract: &'a Hash,
    ) -> Result<(&Module, &Environment<ContractMetadata>), anyhow::Error> {
        let module = self.internal_load_contract_module(contract)?;
        Ok((&module.module, &self.environments[&module.version]))
    }
}

#[async_trait]
impl<'a, 'ty> BlockchainContractState<'a, 'ty, MockStorageProvider, anyhow::Error> for MockChainState {
    async fn set_contract_logs(
        &mut self,
        caller: ContractCaller<'a>,
        logs: Vec<ContractLog>,
    ) -> Result<(), anyhow::Error> {
        let hash = caller.get_hash().into_owned();
        match self.contract_logs.entry(hash) {
            Entry::Occupied(mut o) => {
                o.get_mut().extend(logs);
            }
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
        caller: ContractCaller<'b>,
        permission: Cow<'b, InterContractPermission>,
    ) -> Result<(ContractEnvironment<'b, 'ty, MockStorageProvider>, crate::contract::ChainState<'b>), anyhow::Error> {
        let contract_module = self.internal_load_contract_module(&contract)?;

        let mut cache = self
            .contract_caches
            .get(&contract)
            .cloned()
            .unwrap_or_default();

        if let Some(deposits) = deposits {
            for (asset, deposit) in deposits.iter() {
                match deposit {
                    ContractDeposit::Public(amount) => match cache.balances.entry(asset.clone()) {
                        Entry::Occupied(mut o) => match o.get_mut() {
                            Some((state, balance)) => {
                                state.mark_updated();
                                *balance = balance.checked_add(*amount)
                                    .context("Overflow while applying contract deposit")?;
                            }
                            None => {
                                o.insert(Some((VersionedState::New, *amount)));
                            }
                        },
                        Entry::Vacant(e) => {
                            e.insert(Some((VersionedState::New, *amount)));
                        }
                    },
                    ContractDeposit::Private { .. } => {}
                }
            }
        }

        let environment = ContractEnvironment {
            environment: &self.environments[&contract_module.version],
            module: &contract_module.module,
            version: contract_module.version,
            provider: &self.provider,
            _phantom: PhantomData,
        };

        let chain_state = ContractChainState {
            debug_mode: true,
            mainnet: self.mainnet,
            entry_contract: contract,
            topoheight: 1,
            block_hash: &self.block_hash,
            block: &self.block,
            caller,
            logs: Vec::new(),
            global_caches: &self.contract_caches,
            global_modules: &self.contracts,
            injected_gas: IndexMap::new(),
            executions: ExecutionsManager {
                allow_executions: true,
                global_executions: &self.executions.executions,
                changes: Default::default(),
            },
            changes: ChainStateChanges {
                tracker: self.tracker.clone(),
                assets: self.assets.clone(),
                ..Default::default()
            },
            permission,
            gas_fee_allowance: 0,
            environments: Cow::Owned(HashMap::new()),
            loaded_modules: Default::default(),
            cache_clone_refs: self.block.get_version() < BlockVersion::V6,
        };

        Ok((environment, chain_state))
    }

    async fn set_modules_cache(
        &mut self,
        modules: HashMap<Hash, Option<(VersionedState, Option<ContractModule>)>>,
    ) -> Result<(), anyhow::Error> {
        for (hash, value) in modules {
            self.contracts.insert(
                Cow::Owned(hash),
                value.map(|(state, module)| (state, module.map(Cow::Owned))),
            );
        }

        Ok(())
    }

    async fn merge_contract_changes(
        &mut self,
        changes: ChainStateChanges,
        mut executions_changes: ExecutionsChanges,
    ) -> Result<(), anyhow::Error> {
        for (contract, mut cache) in changes.caches {
            cache.clean_up();

            match self.contract_caches.entry(contract) {
                Entry::Occupied(mut o) => {
                    let current = o.get_mut();
                    *current = cache;
                }
                Entry::Vacant(e) => {
                    e.insert(cache);
                }
            };
        }

        self.assets = changes.assets;
        self.tracker = changes.tracker;
        self.events.extend(changes.events);

        for (key, mut listeners) in changes.events_listeners {
            match self.events_listeners.entry(key) {
                Entry::Occupied(mut o) => {
                    o.get_mut().append(&mut listeners);
                }
                Entry::Vacant(e) => {
                    e.insert(listeners);
                }
            };
        }

        for (hash, execution) in executions_changes.executions {
            self.executions.executions.insert(hash, execution);
        }

        self.executions
            .at_topoheight
            .append(&mut executions_changes.at_topoheight);
        self.executions
            .block_end
            .append(&mut executions_changes.block_end);

        self.add_gas_fee(changes.extra_gas_fee).await
    }

    async fn get_contract_balance_for_gas<'b>(
        &'b mut self,
        contract: &'b Hash,
    ) -> Result<&'b mut (VersionedState, u64), anyhow::Error> {
        self.contract_caches
            .entry(contract.clone())
            .or_insert_with(Default::default)
            .balances
            .entry(XELIS_ASSET)
            .or_insert(Some((VersionedState::New, 0)))
            .as_mut()
            .context("Contract balance for gas not found")
    }

    async fn remove_contract_module(&mut self, hash: &'a Hash) -> Result<(), anyhow::Error> {
        self.contracts.remove(hash);
        Ok(())
    }

    async fn post_contract_execution(
        &mut self,
        caller: &ContractCaller<'a>,
        _: &Hash,
    ) -> Result<(), anyhow::Error> {
        self.on_post_execution(caller.get_hash().as_ref()).await
    }
}

#[async_trait]
impl<'a, 'ty> BlockchainApplyState<'a, 'ty, MockStorageProvider, anyhow::Error> for MockChainState {
    async fn add_burned_coins(&mut self, asset: &Hash, amount: u64) -> Result<(), anyhow::Error> {
        *self.burned_coins.entry(asset.clone()).or_insert(0) += amount;
        Ok(())
    }

    async fn add_gas_fee(&mut self, amount: u64) -> Result<(), anyhow::Error> {
        self.gas_fee += amount;
        Ok(())
    }

    async fn add_burned_fee(&mut self, amount: u64) -> Result<(), anyhow::Error> {
        self.burned_fee += amount;
        Ok(())
    }

    fn is_mainnet(&self) -> bool {
        self.mainnet
    }
}
