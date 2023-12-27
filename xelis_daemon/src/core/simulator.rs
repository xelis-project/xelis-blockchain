use std::{str::FromStr, fmt::{Display, Formatter}, sync::Arc, time::Duration, collections::{HashMap, hash_map::Entry}};

use log::{info, error};
use rand::{rngs::OsRng, Rng};
use tokio::time::interval;
use xelis_common::{crypto::key::KeyPair, transaction::{Transaction, TransactionType, Transfer}, config::{FEE_PER_KB, XELIS_ASSET}};

use crate::config::{BLOCK_TIME_MILLIS, DEV_PUBLIC_KEY};

use super::{blockchain::Blockchain, storage::Storage};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Simulator {
    // Mine only one block every BLOCK_TIME
    Blockchain,
    // Mine random 1-5 blocks every BLOCK_TIME to enable BlockDAG
    BlockDag
}

impl FromStr for Simulator {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "blockchain" | "0" => Self::Blockchain,
            "blockdag" | "1" => Self::BlockDag,
            _ => return Err("Invalid simulator type".into())
        })
    }
}

impl Display for Simulator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match &self {
            Self::Blockchain => "blockchain",
            Self::BlockDag => "blockdag"
        };
        write!(f, "{}", str)
    }
}

impl Simulator {
    // Start the Simulator mode to generate new blocks automatically
    // It generates random miner keys and mine blocks with them
    pub async fn start<S: Storage>(&self, blockchain: Arc<Blockchain<S>>) {
        let mut interval = interval(Duration::from_millis(BLOCK_TIME_MILLIS));
        let mut rng = OsRng;
        let mut keys: Vec<KeyPair> = Vec::new();

        // Generate 10 random keys for mining
        for _ in 0..10 {
            keys.push(KeyPair::new());
        }

        'main: loop {
            interval.tick().await;
            info!("Adding new simulated block...");
            // Number of blocks to generate
            let blocks_count = match self {
                Self::BlockDag => rng.gen_range(1..5),
                _ => 1
            };

            let mut blocks = Vec::with_capacity(blocks_count);
            for _ in 0..blocks_count {
                let index = rng.gen_range(0..keys.len());
                let selected_key = keys[index].get_public_key();
                match blockchain.mine_block(selected_key).await {
                    Ok(block) => {
                        blocks.push(block);
                    },
                    Err(e) => error!("Error while mining block: {}", e)
                }
            }

            // Add all blocks to the chain
            for block in blocks {
                match blockchain.add_new_block(block, false, false).await {
                    Ok(_) => {},
                    Err(e) => {
                        error!("Error while adding block: {}", e);
                        break 'main;
                    }
                }
            }

            // Generate new transactions for mempool
            let n = rng.gen_range(0..100);
            let mut local_nonces = HashMap::new();
            for _ in 0..n {
                let index = rng.gen_range(0..keys.len());
                let keypair = &keys[index];

                let storage = blockchain.get_storage().read().await;
                if let Ok(true) = storage.has_nonce(keypair.get_public_key()).await {
                    let data = TransactionType::Transfer(vec![
                        Transfer {
                            to: DEV_PUBLIC_KEY.clone(),
                            asset: XELIS_ASSET,
                            amount: 1,
                            extra_data: None
                        }
                    ]);

                    // Get the last nonce for the key, it allow to have several txs from same sender
                    let nonce = match local_nonces.entry(keypair.get_public_key()) {
                        Entry::Occupied(mut e) => {
                            let nonce = e.get_mut();
                            *nonce += 1;
                            *nonce
                        },
                        Entry::Vacant(e) => {
                            let nonce = storage.get_last_nonce(keypair.get_public_key()).await.map(|(_, v)| v.get_nonce()).unwrap();
                            e.insert(nonce);
                            nonce
                        }
                    };

                    let key = keypair.get_public_key().clone();
                    // We create a fake signature because it is skipped in simulator mode
                    let signature = keypair.sign(b"invalid");
                    let tx = Transaction::new(key, data, FEE_PER_KB, nonce, signature);
                    if let Err(e) = blockchain.add_tx_to_mempool(tx, false).await {
                        error!("Error while adding simulated tx to mempool: {}", e);
                    }
                }
            }
        }
    }
}