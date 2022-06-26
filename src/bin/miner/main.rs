use serde_json::Value;
use xelis_blockchain::{core::{json_rpc::JsonRPCClient, block::Block, serializer::Serializer, difficulty::check_difficulty}, rpc::rpc::{GetBlockTemplateParams, GetBlockTemplateResult, SubmitBlockParams}, config::DEV_ADDRESS, globals::get_current_timestamp, crypto::{hash::Hashable, address::Address}};
use xelis_blockchain::config::VERSION;
use clap::Parser;

const DEFAULT_DAEMON_ADDRESS: &str = "http://127.0.0.1:8080";

#[derive(Parser)]
#[clap(version = VERSION, about = "XELIS Daemon")]
pub struct MinerConfig {
    /// Wallet address to mine and receive block rewards on
    #[clap(short, long, default_value_t = String::from(DEV_ADDRESS))]
    miner_address: String,
    /// Daemon address to connect to for mining
    #[clap(short, long, default_value_t = String::from(DEFAULT_DAEMON_ADDRESS))]
    daemon_address: String
}

fn main() {
    let config: MinerConfig = MinerConfig::parse();
    let client = JsonRPCClient::new(format!("{}/json_rpc", config.daemon_address));
    let get_block_template = GetBlockTemplateParams { address: Address::from_string(&config.miner_address).unwrap() };
    loop {
        println!("Requesting block template");
        let block_template: GetBlockTemplateResult = client.call_with("get_block_template", &get_block_template).unwrap();
        let mut block = Block::from_hex(block_template.template).unwrap();
        let mut hash = block.hash();
        while !check_difficulty(&hash, block_template.difficulty).unwrap() {
            block.nonce += 1;
            block.timestamp = get_current_timestamp();
            hash = block.hash();
        }

        println!("Sending block with hash {}", hash);
        match client.call_with::<SubmitBlockParams, Value>("submit_block", &SubmitBlockParams { block_template: block.to_hex(), block_hashing_blob: "".into()}) {
            Ok(_) => {
                println!("Block successfully accepted!");
            }
            Err(e) => {
                println!("Error whille adding new block: {:?}", e);
            }
        };
    }
}