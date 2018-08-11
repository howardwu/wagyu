extern crate bitcoin;

use bitcoin::{BitcoinWallet, network::Network};

fn main() {
    let wallet = BitcoinWallet::new(Network::Mainnet);
    println!("{}", wallet);
}
