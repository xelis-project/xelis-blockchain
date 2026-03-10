mod providers;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use hashlink::LinkedHashSet;
use indexmap::{IndexMap, IndexSet};
use pooled_arc::*;
use xelis_common::{
    account::{VersionedBalance, VersionedNonce},
    asset::VersionedAssetData,
    block::{BlockHeader, TopoHeight},
    contract::{ContractLog, ScheduledExecution},
    crypto::{Hash, PublicKey},
    difficulty::{CumulativeDifficulty, Difficulty},
    immutable::Immutable,
    network::Network,
    transaction::Transaction,
    varuint::VarUint,
};
use xelis_vm::ValueCell;

use crate::core::storage::{VersionedContractModule, VersionedMultiSig};
use crate::core::{
    error::BlockchainError,
    storage::{
        cache::ChainCache,
        types::TopoHeightMetadata,
        ClientProtocolProvider,
        DagOrderProvider,
        DifficultyProvider,
        Storage,
        TransactionProvider,
        VersionedContractBalance,
        VersionedContractData,
        VersionedEventCallbackRegistration,
        VersionedSupply,
    },
};

#[derive(Clone, Default)]
pub(crate) struct AccountEntry {
    pub balances: HashMap<PooledArc<Hash>, BTreeMap<TopoHeight, VersionedBalance>>,
    pub nonces: BTreeMap<TopoHeight, VersionedNonce>,
    pub multisig: BTreeMap<TopoHeight, VersionedMultiSig<'static>>,
    pub registered_at: Option<TopoHeight>,
}

pub(crate) struct BlockEntry {
    pub header: Arc<BlockHeader>,
    pub metadata: BlockMetadata,
}

pub(crate) struct TransactionEntry {
    pub transaction: Arc<Transaction>,
    pub executed_in_block: Option<PooledArc<Hash>>,
    pub linked_blocks: LinkedHashSet<PooledArc<Hash>>,
}

// Internal asset structure
#[derive(Debug, Clone, Default)]
pub(crate) struct AssetEntry {
    data: BTreeMap<TopoHeight, VersionedAssetData>,
    supply: BTreeMap<TopoHeight, VersionedSupply>,
}

// Internal contract structure
#[derive(Debug, Clone, Default)]
pub(crate) struct ContractEntry {
    modules: BTreeMap<TopoHeight, VersionedContractModule<'static>>,
    data: HashMap<ValueCell, BTreeMap<TopoHeight, VersionedContractData>>,
    transactions: LinkedHashSet<PooledArc<Hash>>,
    balances: HashMap<PooledArc<Hash>, BTreeMap<TopoHeight, VersionedContractBalance>>,
    // Scheduled executions registered at said topoheight -> execution topoheight -> execution
    scheduled_executions: BTreeMap<TopoHeight, BTreeMap<TopoHeight, ScheduledExecution>>,
    // Event callbacks registered at said topoheight
    // (event id, contract listener) -> registration topoheight
    events_callbacks: BTreeMap<u64, BTreeMap<PooledArc<Hash>, BTreeMap<TopoHeight, VersionedEventCallbackRegistration>>>,
}

// Block metadata
#[derive(Debug, Clone)]
pub(crate) struct BlockMetadata {
    difficulty: Difficulty,
    cumulative_difficulty: CumulativeDifficulty,
    covariance: VarUint,
    size_ema: u32,
}

pub struct MemoryStorage {
    network: Network,
    cache: ChainCache,
    concurrency: usize,

    accounts: HashMap<PooledArc<PublicKey>, AccountEntry>,

    // Block data
    blocks: IndexMap<PooledArc<Hash>, BlockEntry>,
    blocks_at_height: BTreeMap<u64, IndexSet<PooledArc<Hash>>>,

    // Transactions
    transactions: HashMap<PooledArc<Hash>, TransactionEntry>,

    // DAG order
    topo_by_hash: HashMap<PooledArc<Hash>, TopoHeight>,
    hash_at_topo: BTreeMap<TopoHeight, PooledArc<Hash>>,

    // TopoHeight metadata
    topoheight_metadata: BTreeMap<TopoHeight, TopoHeightMetadata>,

    // Assets: hash -> entry with pointers
    assets: HashMap<PooledArc<Hash>, AssetEntry>,

    // Contracts: hash -> entry with pointers
    contracts: HashMap<PooledArc<Hash>, ContractEntry>,

    // Contract logs per caller (TX or Scheduled Execution hash): contract -> logs
    contract_logs: HashMap<PooledArc<Hash>, Vec<ContractLog>>,

    // All scheduled executions: execution_topoheight -> contracts -> registration topoheight
    // This is used to quickly retrieve all scheduled executions to execute at a given topoheight
    scheduled_executions_per_topoheight: BTreeMap<TopoHeight, HashMap<PooledArc<Hash>, TopoHeight>>,
}

impl MemoryStorage {
    pub fn new(network: Network, concurrency: usize) -> Self {
        Self {
            concurrency,
            network,
            cache: ChainCache::default(),
            blocks: IndexMap::new(),
            blocks_at_height: BTreeMap::new(),
            transactions: HashMap::new(),
            topo_by_hash: HashMap::new(),
            hash_at_topo: BTreeMap::new(),
            topoheight_metadata: BTreeMap::new(),
            assets: HashMap::new(),
            accounts: HashMap::new(),
            contracts: HashMap::new(),
            contract_logs: HashMap::new(),
            scheduled_executions_per_topoheight: BTreeMap::new(),
        }
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn delete_block_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(Hash, Immutable<BlockHeader>, Vec<(Hash, Immutable<Transaction>)>), BlockchainError> {
        let hash = self.get_hash_at_topo_height(topoheight).await?;
        let shared_hash = PooledArc::from_ref(&hash);

        self.hash_at_topo.remove(&topoheight);
        self.topo_by_hash.remove(&shared_hash);
        self.topoheight_metadata.remove(&topoheight);

        let block = self.get_block_header_by_hash(&hash).await?;
        let mut txs = Vec::new();

        for tx_hash in block.get_txs_hashes() {
            if let Ok(tx) = self.get_transaction(tx_hash).await {
                self.unmark_tx_from_executed(tx_hash).await?;
                txs.push((tx_hash.clone(), tx));
            }
        }

        Ok((hash, block, txs))
    }

    async fn get_size_on_disk(&self) -> Result<u64, BlockchainError> {
        Ok(0)
    }

    async fn estimate_size(&self) -> Result<u64, BlockchainError> {
        Ok(0)
    }

    async fn stop(&mut self) -> Result<(), BlockchainError> {
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), BlockchainError> {
        Ok(())
    }
}

