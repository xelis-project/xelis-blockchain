mod block;
mod globals;
mod difficulty;
mod blockchain;
mod config;
mod transaction;
mod address;

use globals::Hashable;
use blockchain::Blockchain;
use std::thread;
use std::sync::{Arc, Mutex};

const ADDRESS: &str = "slixe";

fn main() {
    println!("Xelis Blockchain - Pre-Alpha");

    let mut blockchain = Blockchain::new(ADDRESS.to_owned());
    let mut genesis_block = blockchain.get_block_template(ADDRESS.to_owned());

    genesis_block.calculate_hash();
    if let Err(e) = blockchain.add_new_block(genesis_block) {
        println!("Error on genesis block: {}", e);
    }

    for _ in 0..20 {
        let mut block = blockchain.get_block_template(ADDRESS.to_owned());
        block.calculate_hash();
        if let Err(e) = blockchain.add_new_block(block) {
            println!("Error on block: {}", e);
        }
    }

    if let Err(e) = blockchain.check_validity() {
        panic!("{} valid: {}", blockchain, e);
    }

    println!("Success!");
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
                let mut block = blockchain.get_block_template(ADDRESS.to_owned());
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