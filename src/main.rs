mod block;
mod globals;
mod difficulty;
mod blockchain;
mod config;
mod transaction;
mod address;
mod bech32;

use globals::Hashable;
use blockchain::Blockchain;
use std::thread;
use std::sync::{Arc, Mutex};

const ADDRESS: &str = "slixe";

fn main() {
    println!("Xelis Blockchain - Pre-Alpha");
    let data: [u8; 32] = rand::random();
    println!("Data generated: {}", hex::encode(data));
    let result = crate::bech32::convert_bits(&data, 8, 5, true);
    println!("Result: {}", hex::encode(&result));
    let test_encode = crate::bech32::encode(String::from("xls"), &result);
    println!("Address: {}", test_encode);

    let (hrp, data2) = crate::bech32::decode(&test_encode);
    let test = crate::bech32::convert_bits(&data2, 5, 8, false);
    println!("HRP: {}, data: {}", hrp, hex::encode(&test));

    let mut blockchain = Blockchain::new(ADDRESS.to_owned());
    let mut genesis_block = blockchain.get_block_template(ADDRESS.to_owned());

    if let Err(e) = genesis_block.calculate_hash() {
        panic!("Error while calculating hash for genesis block: {}", e);
    }

    if let Err(e) = blockchain.add_new_block(genesis_block) {
        panic!("Error on genesis block: {}", e);
    }

    for _ in 0..5 {
        let mut block = blockchain.get_block_template(ADDRESS.to_owned());
        if let Err(e) = block.calculate_hash() {
            panic!("Error while calculating hash for block {}: {}", block.height, e)
        }
        if let Err(e) = blockchain.add_new_block(block) {
            println!("Error on block: {}", e);
        }
    }

    if let Err(e) = blockchain.check_validity() {
        panic!("{} valid: {}", blockchain, e);
    }

    println!("Success!");
    println!("{}", serde_json::to_string_pretty(&blockchain).unwrap());
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
                    if difficulty::check_difficulty(&hash, block.difficulty).is_ok() {
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