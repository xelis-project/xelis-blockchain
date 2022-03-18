mod globals;
mod config;
mod crypto;
mod wallet;
mod core;
mod p2p;

use crate::core::blockchain::Blockchain;
use std::thread;

fn main() {
    nodeB();
}

fn nodeA() {
    println!("Xelis Blockchain - pre-alpha");
    let blockchain = match Blockchain::new(Some(String::from("Node A")), String::from("127.0.0.1:2125")) {
        Ok(v) => v,
        Err(e) => panic!("Error occured on blockchain: {}", e)
    };
    let key = blockchain.get_dev_address().clone();
    for _ in 0..10 {
        if let Err(e) = blockchain.mine_block(key.clone()) {
            println!("Error while mining block: {}", e);
        }
    }
    loop {}
}

fn nodeB() {
    println!("Xelis Blockchain - pre-alpha");
    let blockchain = match Blockchain::new(Some(String::from("Node B")), String::from("127.0.0.1:2126")) {
        Ok(v) => v,
        Err(e) => panic!("Error occured on blockchain: {}", e)
    };

    loop {}
}