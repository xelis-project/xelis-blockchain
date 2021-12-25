mod globals;
mod config;
mod crypto;
mod wallet;
mod core;
mod p2p;

use crate::core::blockchain::Blockchain;

fn main() {
    println!("Xelis Blockchain - pre-alpha");
    let mut blockchain: Blockchain = Blockchain::new();
    let key = blockchain.get_dev_address().clone();
    for _ in 0..10 {
        if let Err(e) = blockchain.mine_block(key.clone()) {
            println!("Error while mining block: {}", e);
        }
    }
    
    if let Err(e) = blockchain.check_validity() {
        println!("Error, blockchain is not valid: {}", e)
    }
}