use xelis_blockchain::wallet::Wallet;

fn main() {
    let wallet = Wallet::new();
    println!("Wallet address generated: {}", wallet.get_address());
}