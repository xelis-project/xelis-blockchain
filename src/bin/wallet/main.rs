use xelis_blockchain::wallet::Wallet;

fn main() {
    println!("test wallet");
    let wallet = Wallet::new(format!("http://{}/json_rpc", "127.0.0.1:8080"));
    println!("New address: {}", wallet.get_address());
    let tx_registration = wallet.create_tx_registration();
    if let Err(e) = wallet.send_transaction(&tx_registration) {
        println!("Error: {}", e);
    }
}