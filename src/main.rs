mod block;
mod globals;
mod difficulty;
mod blockchain;
mod config;
mod transaction;

use block::Block;
use globals::Hashable;
use blockchain::Blockchain;
use std::thread;
use std::sync::{Arc, Mutex};
use transaction::*;

fn main() {
    println!("Xelis Blockchain - Pre-Alpha");
    let mut blockchain = Blockchain::new();
    let registration_address = Transaction::new(0, globals::get_current_time(), TransactionData::Registration, "test".to_owned(), 0);
    let mut genesis_block = Block::new(0, globals::get_current_time(), [0; 32], config::MINIMUM_DIFFICULTY, [0; 32], vec![registration_address]);
    genesis_block.calculate_hash();
    blockchain.add_new_block(genesis_block);

    for _ in 0..15 {
        let mut block = blockchain.get_block_template();
        block.calculate_hash();
        blockchain.add_new_block(block);
    }

    println!("Blockchain ({} blocks, {} accounts) valid: {}", blockchain.get_current_height(), blockchain.get_mempool().len(), blockchain.check_validity());
}

//dirty code
fn multi_thread(blockchain: Blockchain) {
    let mut handles = vec![];
    let cpus = 1;//num_cpus::get();
    let arc = Arc::new(Mutex::new(blockchain));
    for thread in 0..cpus {
        let clone = Arc::clone(&arc);
        let handle = thread::spawn(move || {
            loop {
                let blockchain = clone.lock().unwrap();
                let mut block = blockchain.get_block_template();
                drop(blockchain);
                
                loop {
                    let hash = block.hash();
                    if difficulty::check_difficulty(&hash, block.difficulty) {
                        block.hash = hash;
                        println!("Thread #{} found block {} !", thread, block.height);
                        let mut blockchain = clone.lock().unwrap();
                        if blockchain.get_current_height() == block.height {
                            blockchain.add_new_block(block);
                        }
                        break;
                    } else {
                        block.nonce = block.nonce + 1;
                        block.timestamp = globals::get_current_time();
                    }

                    let blockchain = clone.lock().unwrap();
                    if blockchain.get_current_height() != block.height {
                        break;
                    }
                }
            }
            println!("Thread #{} finished!", thread);
        });
        handles.push(handle);
        println!("Thread #{} ready!", thread);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}