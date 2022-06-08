use xelis_blockchain::wallet::wallet::Wallet;

fn main() {
    println!("test wallet");
    let wallet = Wallet::new();
    println!("New address: {}", wallet.get_address());
}