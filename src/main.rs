mod globals;
mod config;
mod crypto;
mod wallet;
mod core;

use crate::crypto::hash::Hashable;
use crate::crypto::key::{KeyPair, PublicKey};
use crate::core::blockchain::Blockchain;
use crate::core::transaction::*;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

fn mine_block(blockchain: &mut Blockchain, miner_key: &PublicKey) {
    let mut block = blockchain.get_block_template(miner_key.clone());
    if let Err(e) = block.calculate_hash() {
        panic!("Error while calculating hash for block {}: {}", block.height, e)
    }
    println!("Block size: {} octets", block.size());
    if let Err(e) = blockchain.add_new_block(block) {
        println!("Error on block: {}", e);
    }
}

fn sign_and_send_tx(blockchain: &mut Blockchain, mut transaction: Transaction, keypair: &KeyPair) {
    if let Err(e) = transaction.sign_transaction(keypair) {
        println!("Error while signing transaction: {}", e);
    }

    if let Err(e) = blockchain.add_tx_to_mempool(transaction) {
        println!("Error on adding tx to mempool: {}", e);
    }
}

fn create_registration_transaction(blockchain: &mut Blockchain, keypair: &KeyPair) {
    let tx_registration = match Transaction::new_registration(keypair.get_public_key().clone()) {
        Err(e) => panic!("Error on tx registration creation: {}", e),
        Ok(value) => value
    };
    
    sign_and_send_tx(blockchain, tx_registration, keypair);
}

fn main() {
    println!("Xelis Blockchain - pre-alpha");

    let main_keypair: KeyPair = KeyPair::new();
    println!("Generated main address: {}", main_keypair.get_public_key().to_address().unwrap());
    let mut blockchain = Blockchain::new(main_keypair.get_public_key().clone());

    let dummy_keypair: KeyPair = KeyPair::new();
    println!("Generated address: {}", dummy_keypair.get_public_key().to_address().unwrap());
    create_registration_transaction(&mut blockchain, &dummy_keypair);

    mine_block(&mut blockchain, main_keypair.get_public_key());

    let normal_tx = Transaction::new(0, TransactionData::Normal(vec![Tx {
        amount: 1000,
        to: dummy_keypair.get_public_key().clone()
    }]), main_keypair.get_public_key().clone());

    sign_and_send_tx(&mut blockchain, normal_tx, &main_keypair);

    for _ in 0..5 {
        mine_block(&mut blockchain, dummy_keypair.get_public_key());
    }

    if let Err(e) = blockchain.check_validity() {
        println!("{} valid: {}", blockchain, e);
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