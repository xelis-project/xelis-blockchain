mod block;
mod globals;
mod difficulty;
mod blockchain;
mod config;
mod transaction;
mod address;
mod bech32;

use globals::{as_address, Hashable};
use blockchain::Blockchain;
use transaction::*;
//use std::thread;
//use std::sync::{Arc, Mutex};
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use bech32::Bech32Error;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;

fn address_example() -> Result<(), Bech32Error> {
    let data: [u8; 32] = rand::random();
    println!("Data generated: {}", hex::encode(data));
    let result = crate::bech32::convert_bits(&data, 8, 5, true)?;
    println!("Result: {}", hex::encode(&result));
    let test_encode = crate::bech32::encode(crate::config::PREFIX_ADDRESS.to_owned(), &result)?;
    println!("Address: {}", test_encode);

    println!("Decoding generated address:");
    let (hrp, data2) = crate::bech32::decode(&test_encode)?;
    let test = crate::bech32::convert_bits(&data2, 5, 8, false)?;
    println!("HRP: {}, data: {}", hrp, hex::encode(&test));

    Ok(())
}

fn main() {
    println!("Xelis Blockchain - Pre-Alpha");
    /*if let Err(e) = address_example() {
        println!("Error: {}", e);
    }*/

    let mut csprng = OsRng {};
    let main_keypair: Keypair = Keypair::generate(&mut csprng);
    println!("Generated main address: {}", as_address(&main_keypair.public));
    let mut blockchain = Blockchain::new(main_keypair.public.clone());

    let dummy_keypair: Keypair = Keypair::generate(&mut csprng);
    println!("Generated dummy address: {}", as_address(&dummy_keypair.public));

    let mut tx_registration = match Transaction::new_registration(dummy_keypair.public) {
        Err(e) => panic!("Error on tx registration creation: {}", e),
        Ok(value) => value
    };
    if let Err(e) = tx_registration.sign_transaction(&dummy_keypair) {
        println!("Error while signing transaction: {}", e);
    }

    if let Err(e) = blockchain.add_tx_to_mempool(tx_registration) {
        println!("Error on tx registration for 'dummy' account: {}", e);
    }

    for _ in 0..5 {
        let mut block = blockchain.get_block_template(main_keypair.public);
        if let Err(e) = block.calculate_hash() {
            panic!("Error while calculating hash for block {}: {}", block.height, e)
        }
        println!("Block size: {} octets", block.size());
        if let Err(e) = blockchain.add_new_block(block) {
            println!("Error on block: {}", e);
        }

        let acc = match blockchain.get_account(&main_keypair.public) {
            Ok(v) => v,
            Err(e) => panic!("Error while retrieving account: {}", e)
        };
        let nonce = acc.get_nonce();
        for i in 0..5 {
            let mut tx = Transaction::new(nonce, TransactionData::Normal(vec![Tx {
                amount: 1 + i,
                to: dummy_keypair.public,
            }]), main_keypair.public.clone());
            if let Err(e) = tx.sign_transaction(&main_keypair) {
                println!("Error on signature: {}", e);
            }

            if let Err(e) = blockchain.add_tx_to_mempool(tx) {
                println!("Error on tx: {}", e);
            }
        }
    }

    if let Err(e) = blockchain.check_validity() {
        panic!("{} valid: {}", blockchain, e);
    }
    
    let path = Path::new("blockchain.json");
    let mut file = match File::create(&path) {
        Err(e) => panic!("couldn't create file: {}", e),
        Ok(file) => file,
    };

    match file.write_all(serde_json::to_string_pretty(&blockchain).unwrap().as_bytes()) {
        Err(e) => panic!("Couldn't write to file: {}", e),
        Ok(_) => println!("blockchain.json has been saved")
    };
}

//dirty code
/*
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
}*/