mod globals;
mod config;
mod crypto;
mod wallet;
mod core;
mod p2p;

use crate::globals::get_current_time;
use crate::crypto::hash::Hashable;
use crate::crypto::key::{KeyPair, PublicKey};
use crate::core::blockchain::Blockchain;
use crate::core::difficulty::check_difficulty;
use crate::core::transaction::*;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use crate::p2p::server::P2pServer;
use crate::p2p::single_thread_server::SingleThreadServer;
use crate::p2p::multi_thread_server::MultiThreadServer;

fn mine_block(blockchain: &mut Blockchain<SingleThreadServer>, miner_key: &PublicKey) {
    let mut block = blockchain.get_block_template(miner_key.clone());

    loop {
        let hash = block.hash();

        match check_difficulty(&hash, block.difficulty) {
            Ok(result) => {
                if result {
                    break;
                } else {
                    block.nonce += 1;
                    block.timestamp = get_current_time();
                }
            }
            Err(e) => {
                panic!("Error while calculating block hash PoW: {}", e);
            }
        }
    }

    match blockchain.build_complete_block_from_block(block) {
        Ok(complete_block) => {
            if let Err(e) = blockchain.add_new_block(complete_block) {
                println!("Error on block: {}", e);
            }
        },
        Err(e) => {
            println!("Error while building complete block: {}", e);
        }
    };

}

fn sign_and_send_tx(blockchain: &mut Blockchain<SingleThreadServer>, mut transaction: Transaction, keypair: &KeyPair) {
    println!("adding tx: {}, registration: {}", transaction.hash(), transaction.is_registration());

    if !transaction.is_registration() {
        if let Err(e) = transaction.sign_transaction(keypair) {
            println!("Error while signing transaction: {}", e);
        }
    }

    if let Err(e) = blockchain.add_tx_to_mempool(transaction) {
        println!("Error on adding tx to mempool: {}", e);
    }
}

fn create_registration_transaction(blockchain: &mut Blockchain<SingleThreadServer>, keypair: &KeyPair) {
    let tx_registration = match Transaction::new_registration(keypair.get_public_key().clone()) {
        Err(e) => panic!("Error on tx registration creation: {}", e),
        Ok(value) => value
    };
    
    sign_and_send_tx(blockchain, tx_registration, keypair);
}

fn main() {
    println!("Xelis Blockchain - pre-alpha");
    test_p2p();

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

    for _ in 0..50 {
        mine_block(&mut blockchain, dummy_keypair.get_public_key());
    }

    if let Err(e) = blockchain.check_validity() {
        println!("{} valid: {}", blockchain, e);
    } else {
        println!("Blockchain is valid!");
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

fn test_p2p() {
    use crate::config::{VERSION, NETWORK_ID, SEED_NODES};
    use crate::crypto::hash::Hash;
    use crate::p2p::handshake::Handshake;
    use std::net::{TcpStream, SocketAddr, Shutdown};
    use std::thread;
    use std::time::Duration;

    for i in 1..=4 {
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(i * 1000));
            let addr: SocketAddr = SEED_NODES[0].parse().unwrap();
            match TcpStream::connect(addr) {
                Ok(mut stream) => {
                    let handshake = Handshake::new(VERSION.to_owned(), Some(format!("user #{}", i)), NETWORK_ID, i, get_current_time(), 0, Hash::zero(), vec![String::from("127.0.0.1:2126")]);
                    let _ = stream.write(&handshake.to_bytes());
                    let msg: String = format!("Hello world from client {}", i);
                    for _ in 0..30 {
                        thread::sleep(Duration::from_millis(150));
                        let _ = stream.write(msg.as_bytes());
                    }
                    println!("DISCONNECTED!");
                    let _ = stream.shutdown(Shutdown::Both);
                },
                Err(e) => panic!("{}", e)
            };
        });
    }

    let server: MultiThreadServer = P2pServer::new(1337, Some(String::from("Server 1337")), 17, String::from("127.0.0.1:2125"));
    server.start();

    loop {}
}