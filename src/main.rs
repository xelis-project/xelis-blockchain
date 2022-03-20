mod globals;
mod config;
mod crypto;
mod wallet;
mod core;
mod p2p;

use crate::core::blockchain::Blockchain;
use std::thread;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "a" {
        nodeA();
    } else {
        nodeB();
    }
}

fn nodeA() {
    println!("Xelis Blockchain - pre-alpha");
    let blockchain = match Blockchain::new(Some(String::from("Node A")), String::from("127.0.0.1:2125")) {
        Ok(v) => v,
        Err(e) => panic!("Error occured on blockchain: {}", e)
    };
    let key = blockchain.get_dev_address().clone();
    loop {
        if let Err(e) = blockchain.mine_block(key.clone()) {
            println!("Error while mining block: {}", e);
        }
    }
}

fn nodeB() {
    println!("Xelis Blockchain - pre-alpha");
    let blockchain = match Blockchain::new(Some(String::from("Node B")), String::from("127.0.0.1:2126")) {
        Ok(v) => v,
        Err(e) => panic!("Error occured on blockchain: {}", e)
    };

    loop {}
}