mod block;
mod globals;
mod difficulty;
mod blockchain;
mod config;
mod transaction;
mod crypto;

use crate::crypto::hash::Hashable;
use crate::crypto::key::KeyPair;
use blockchain::Blockchain;
use transaction::*;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;


fn main() {
    println!("Xelis Blockchain - pre-alpha");

    let main_keypair: KeyPair = KeyPair::new();
    println!("Generated main address: {}", main_keypair.get_public_key().to_address().unwrap());
    let mut blockchain = Blockchain::new(main_keypair.get_public_key().clone());

    let dummy_keypair: KeyPair = KeyPair::new();
    println!("Generated dummy address: {}", dummy_keypair.get_public_key().to_address().unwrap());

    let mut tx_registration = match Transaction::new_registration(dummy_keypair.get_public_key().clone()) {
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
        let mut block = blockchain.get_block_template(main_keypair.get_public_key().clone());
        if let Err(e) = block.calculate_hash() {
            panic!("Error while calculating hash for block {}: {}", block.height, e)
        }
        println!("Block size: {} octets", block.size());
        if let Err(e) = blockchain.add_new_block(block) {
            println!("Error on block: {}", e);
        }

        let acc = match blockchain.get_account(&main_keypair.get_public_key()) {
            Ok(v) => v,
            Err(e) => panic!("Error while retrieving account: {}", e)
        };
        let nonce = acc.get_nonce();
        for i in 0..5 {
            let mut tx = Transaction::new(nonce, TransactionData::Normal(vec![Tx {
                amount: 1 + i,
                to: dummy_keypair.get_public_key().clone(),
            }]), main_keypair.get_public_key().clone());
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