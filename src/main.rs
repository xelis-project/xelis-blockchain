mod block;
mod globals;
mod difficulty;
mod blockchain;
mod config;
mod transaction;
mod crypto;

use crate::crypto::hash::Hashable;
use crate::crypto::key::{KeyPair, PublicKey};
use blockchain::Blockchain;
use transaction::*;
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

    /*let mut keys = vec![];
    for _ in 0..5/*2000*/ {
        let keypair: KeyPair = KeyPair::new();
        create_registration_transaction(&mut blockchain, &keypair);
        keys.push(keypair.get_public_key().clone());
    }*/

    for _ in 0..5 {
        /*let acc = match blockchain.get_account(&main_keypair.get_public_key()) {
            Ok(v) => v,
            Err(e) => panic!("Error while retrieving account: {}", e)
        };
        let nonce = acc.get_nonce();
        if blockchain.get_height() > 0 {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let r: u8 = rng.gen_range(0..20);
            for _ in 0..r as u64 {
                let to = keys[rng.gen_range(0..keys.len() - 1)];
                let mut tx = Transaction::new(nonce, TransactionData::Normal(vec![Tx {
                    amount: rng.gen_range(1..1000),
                    to: to,
                }]), main_keypair.get_public_key().clone());

                if let Err(e) = tx.sign_transaction(&main_keypair) {
                    println!("Error on signature: {}", e);
                }
    
                if let Err(e) = blockchain.add_tx_to_mempool(tx) {
                    println!("Error on tx: {}", e);
                }
            }
        }*/
        mine_block(&mut blockchain, main_keypair.get_public_key());
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