use argh::FromArgs;
use xelis_blockchain::{core::{json_rpc::JsonRPCClient, block::Block, serializer::Serializer, difficulty::check_difficulty}, rpc::rpc::{GetBlockTemplateParams, GetBlockTemplateResult, SubmitBlockParams}, config::DEV_ADDRESS, globals::get_current_time, crypto::hash::Hashable};


const DEFAULT_DAEMON_ADDRESS: &str = "http://127.0.0.1:8080";
#[derive(FromArgs)]
/// XELIS Miner
pub struct MinerConfig {
    /// miner address to get rewards
    #[argh(option, default = "xelis_blockchain::config::DEV_ADDRESS.to_string()")]
    miner_address: String,
    /// daemon address to get and submit blocks
    #[argh(option, default = "DEFAULT_DAEMON_ADDRESS.to_string()")]
    daemon_address: String
}

fn main() {
    let config: MinerConfig = argh::from_env();
    let client = JsonRPCClient::new(format!("{}/json_rpc", config.daemon_address));
    let get_block_template = GetBlockTemplateParams { address: config.miner_address };
    loop {
        println!("Requesting block template");
        let block_template: GetBlockTemplateResult = client.call_with("get_block_template", &get_block_template).unwrap();
        let mut block = Block::from_hex(block_template.template).unwrap();
        let mut hash = block.hash();
        while !check_difficulty(&hash, block_template.difficulty).unwrap() {
            block.nonce += 1;
            block.timestamp = get_current_time();
            hash = block.hash();
        }

        println!("Sending block with hash {}", hash);
        client.notify_with("submit_block", SubmitBlockParams { block_template: block.to_hex(), block_hashing_blob: "".into()}).unwrap();
    }
}