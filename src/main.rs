mod globals;
mod config;
mod crypto;
mod wallet;
mod core;
mod p2p;

use crate::core::blockchain::Blockchain;
use std::thread;
use std::env;
use std::time::Duration;

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
    thread::sleep(Duration::from_millis(1000));
    loop {
        if blockchain.is_synced() {
            if let Err(e) = blockchain.mine_block(&key) {
                println!("Error while mining block: {}", e);
            }
        } else {
            thread::sleep(Duration::from_millis(1000));
        }
    }
}

fn nodeB() {
    println!("Xelis Blockchain - pre-alpha");
    let blockchain = match Blockchain::new(Some(String::from("Node B")), String::from("127.0.0.1:2126")) {
        Ok(v) => v,
        Err(e) => panic!("Error occured on blockchain: {}", e)
    };

    thread::sleep(Duration::from_secs(100000))
}