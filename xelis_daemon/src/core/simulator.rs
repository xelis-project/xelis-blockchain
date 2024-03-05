use std::{
    str::FromStr,
    fmt::{Display, Formatter},
    sync::Arc,
    time::Duration,
};
use log::{info, error};
use rand::{rngs::OsRng, Rng};
use tokio::time::interval;
use xelis_common::{
    crypto::KeyPair,
    config::TIPS_LIMIT,
    block::Block
};
use crate::config::BLOCK_TIME_MILLIS;
use super::{blockchain::Blockchain, storage::Storage};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Simulator {
    // Mine only one block every BLOCK_TIME
    Blockchain,
    // Mine random 1-5 blocks every BLOCK_TIME to enable BlockDAG
    BlockDag,
    // Same as blockDAG but generates much more blocks and TXs for stress test
    Stress,
}

impl FromStr for Simulator {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "blockchain" | "0" => Self::Blockchain,
            "blockdag" | "1" => Self::BlockDag,
            "stress" | "2" => Self::Stress,
            _ => return Err("Invalid simulator type".into())
        })
    }
}

impl Display for Simulator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match &self {
            Self::Blockchain => "blockchain",
            Self::BlockDag => "blockdag",
            Self::Stress => "stress",
        };
        write!(f, "{}", str)
    }
}

impl Simulator {
    // Start the Simulator mode to generate new blocks automatically
    // It generates random miner keys and mine blocks with them
    pub async fn start<S: Storage>(&self, blockchain: Arc<Blockchain<S>>) {
        let millis_interval = match self {
            Self::Stress => 300,
            _ => BLOCK_TIME_MILLIS
        };

        let mut interval = interval(Duration::from_millis(millis_interval));
        let mut rng = OsRng;
        let mut keys: Vec<KeyPair> = Vec::new();

        // Generate 100 random keys for mining
        for _ in 0..100 {
            keys.push(KeyPair::new());
        }

        loop {
            interval.tick().await;
            info!("Adding new simulated block...");
            // Number of blocks to generate
            let blocks_count = match self {
                Self::BlockDag => rng.gen_range(1..=TIPS_LIMIT),
                Self::Stress => rng.gen_range(1..=10),
                _ => 1
            };

            // Generate blocks
            let blocks = self.generate_blocks(blocks_count, &mut rng, &keys, &blockchain).await;

            // Add all blocks to the chain
            for block in blocks {
                match blockchain.add_new_block(block, false, false).await {
                    Ok(_) => {},
                    Err(e) => {
                        error!("Error while adding block: {}", e);
                    }
                }
            }

            // TODO
            // let max_txs = match self {
            //     Self::Stress => 200,
            //     _ => 15
            // };

            // self.generate_txs_in_mempool(max_txs, 15, 50, &mut rng, &keys, &blockchain).await;
        }
    }

    async fn generate_blocks(&self, max_blocks: usize, rng: &mut OsRng, keys: &Vec<KeyPair>, blockchain: &Arc<Blockchain<impl Storage>>) -> Vec<Block> {
        info!("Adding simulated blocks");
        let n = rng.gen_range(1..=max_blocks);
        let mut blocks = Vec::with_capacity(n);
        for _ in 0..n {
            let index = rng.gen_range(0..keys.len());
            let selected_key = keys[index].get_public_key();
            match blockchain.mine_block(&selected_key.compress()).await {
                Ok(block) => {
                    blocks.push(block);
                },
                Err(e) => error!("Error while mining block: {}", e)
            }
        }

        blocks
    }

    // TODO use transaction builder
    // async fn generate_txs_in_mempool(&self, max_txs: usize, max_transfers: usize, max_amount: u64, rng: &mut OsRng, keys: &Vec<KeyPair>, blockchain: &Arc<Blockchain<impl Storage>>) {
    //     info!("Adding simulated TXs in mempool");
    //     let n = rng.gen_range(0..max_txs);
    //     let mut local_nonces = HashMap::new();
    //     let mut local_balances = HashMap::new();
    //     for _ in 0..n {
    //         let index = rng.gen_range(0..keys.len());
    //         let keypair = &keys[index];

    //         let storage = blockchain.get_storage().read().await;
    //         if let Ok(true) = storage.has_nonce(keypair.get_public_key()).await {
    //             let mut transfers = Vec::new();
    //             // Total XEL spend for this tx
    //             let mut total_amount = FEE_PER_KB;
    //             // Generate all transfers
    //             for _ in 0..rng.gen_range(1..=max_transfers) {

    //                 // Prevent to send to ourself
    //                 let mut n = rng.gen_range(0..keys.len());
    //                 while n == index {
    //                     n = rng.gen_range(0..keys.len());
    //                 }

    //                 let amount = rng.gen_range(1..=max_amount);
    //                 total_amount += amount;

    //                 transfers.push(Transfer {
    //                     to: keys[n].get_public_key().clone(),
    //                     asset: XELIS_ASSET,
    //                     amount,
    //                     extra_data: None
    //                 });
    //             }

    //             // Check if we have enough balance
    //             match local_balances.entry(keypair.get_public_key()) {
    //                 Entry::Occupied(mut e) => {
    //                     let balance = e.get_mut();
    //                     if *balance < total_amount {
    //                         continue;
    //                     }
    //                     *balance -= total_amount;
    //                 },
    //                 Entry::Vacant(e) => {
    //                     let balance = storage.get_last_balance(keypair.get_public_key(), &XELIS_ASSET).await.map(|(_, v)| v.get_balance()).unwrap();
    //                     let balance = e.insert(balance);
    //                     if *balance < total_amount {
    //                         continue;
    //                     }
    //                     *balance -= total_amount;
    //                 }
    //             };

    //             let data = TransactionType::Transfer(transfers);

    //             // Get the last nonce for the key, it allow to have several txs from same sender
    //             let nonce = match local_nonces.entry(keypair.get_public_key()) {
    //                 Entry::Occupied(mut e) => {
    //                     let nonce = e.get_mut();
    //                     *nonce += 1;
    //                     *nonce
    //                 },
    //                 Entry::Vacant(e) => {
    //                     let (topo, version) = storage.get_last_nonce(keypair.get_public_key()).await.unwrap();
    //                     let nonce = version.get_nonce();
    //                     debug!("Loaded nonce from last nonce for {} is {} at topo {}", keypair.get_public_key(), nonce, topo);
    //                     e.insert(nonce);
    //                     nonce
    //                 }
    //             };

    //             // Check if this nonce is not already used
    //             {
    //                 let mempool = blockchain.get_mempool().read().await;
    //                 if mempool.is_nonce_used(&keypair.get_public_key(), nonce) {
    //                     debug!("Nonce {} already used for key {}", nonce, keypair.get_public_key());
    //                     continue;
    //                 }
    //             }

    //             let key = keypair.get_public_key().clone();
    //             // We create a fake signature because it is skipped in simulator mode
    //             let signature = keypair.sign(b"invalid");
    //             let tx = Transaction::new(key, data, FEE_PER_KB, nonce, signature);
    //             let hash = tx.hash();

    //             debug!("Simulated tx: {}, key: {}, nonce: {}, fee: {}", hash, tx.get_owner(), tx.get_nonce(), tx.get_fee());
    //             if let Err(e) = blockchain.add_tx_to_mempool_with_hash(tx, hash, false).await {
    //                 error!("Error while adding simulated tx to mempool: {}, key: {}", e, keypair.get_public_key());
    //             }
    //         }
    //     }
    // }
}