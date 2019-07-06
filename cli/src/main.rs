//! # Wagu CLI
//!
//! A command-line tool to generate cryptocurrency wallets.

extern crate arrayvec;
extern crate base58;
#[macro_use(value_t)]
extern crate clap;
extern crate digest;
extern crate either;
extern crate lazy_static;
extern crate safemem;
extern crate serde;
extern crate serde_json;
extern crate tiny_keccak;

extern crate bitcoin;
extern crate ethereum;
extern crate model;
extern crate monero;
extern crate zcash;

use bitcoin::address::Format as BitcoinFormat;
use bitcoin::{BitcoinAddress, BitcoinPrivateKey};
use ethereum::address::Format as EthereumFormat;
use ethereum::{EthereumAddress, EthereumPrivateKey};

use zcash::address::Format as ZcashFormat;
use zcash::{ZcashAddress, ZcashPrivateKey};

use model::{Address, PrivateKey};

use monero::builder::WalletBuilder as MoneroWalletBuilder;

use clap::{App, Arg};
use serde::Serialize;

fn main() {
    let network_vals = ["mainnet", "testnet"];
    let matches = App::new("wagu")
       .version("v0.6.0")
       .about("Generate a wallet for any cryptocurrency

Supported Currencies: Bitcoin, Ethereum, Monero, Zcash (t-address)")
       .author("Argus Developer <team@argus.dev>")
       .arg(Arg::with_name("currency")
            .required(true)
            .help("Name of the currency to generate a wallet for (e.g. bitcoin, ethereum, monero, zcash)"))
        .arg(Arg::with_name("network")
            .short("N")
            .long("network")
            .takes_value(true)
            .possible_values(&network_vals)
            .help("Network of wallet(s) to generate (e.g. mainnet, testnet)"))
       .arg(Arg::with_name("count") 
            .short("n")
            .long("count")
            .takes_value(true)
            .help("Number of wallets to generate"))
        .arg(Arg::with_name("compressed")
            .short("c")
            .long("compressed")
            .help("Enabling this flag generates a wallet which corresponds to a compressed public key"))
        .arg(Arg::with_name("json")
            .short("j")
            .long("json")
            .help("Enabling this flag prints the wallet in JSON format"))
        .arg(Arg::with_name("segwit")
            .long("segwit")
            .conflicts_with("network")
            .help("Enabling this flag generates a wallet with a SegWit address"))
       .get_matches();

    let currency = matches.value_of("currency").unwrap();
//    let mut compressed = matches.is_present("compressed");
    let json = matches.is_present("json");
    let count = value_t!(matches.value_of("count"), usize).unwrap_or_else(|_e| 1);
    let bitcoin_address_type = if matches.is_present("segwit") {
//        compressed = true;
        BitcoinFormat::P2SH_P2WPKH
    } else {
        BitcoinFormat::P2PKH
    };
    let zcash_address_type = if matches.is_present("shielded") {
        ZcashFormat::Shielded
    } else {
        ZcashFormat::Transparent
    };
    let testnet = match matches.value_of("network") {
        Some("mainnet") => false,
        Some("testnet") => true,
        _ => false,
    };

    match currency {
        "bitcoin" => print_bitcoin_wallet(count, testnet, &bitcoin_address_type, json),
        "ethereum" => print_ethereum_wallet(count, json),
        "monero" => print_monero_wallet(count, testnet, json),
        "zcash" => print_zcash_wallet(count, testnet, &zcash_address_type, json),
        _ => panic!("Unsupported currency"),
    };
}

fn print_bitcoin_wallet(count: usize, testnet: bool, format: &BitcoinFormat, json: bool) {
    use bitcoin::Network;

    let network = match testnet {
        true => Network::Testnet,
        false => Network::Mainnet,
    };

    let private_key = BitcoinPrivateKey::new(network);
    let address = BitcoinAddress::from_private_key(&private_key, Some(format.clone()));

    #[derive(Serialize, Debug)]
    pub struct Wallet {
        private_key: String,
        address: String,
        network: String,
        compressed: bool,
    };

    let wallet = Wallet {
        private_key: private_key.wif.clone(),
        address: address.address,
        network: private_key.network.to_string(),
        compressed: private_key.compressed,
    };

    for _ in 0..count {
        if json {
            println!("{}", serde_json::to_string_pretty(&wallet).unwrap())
        } else {
            println!(
                "
        Private Key:    {}
        Address:        {}
        Network:        {}
        Compressed:     {}
        ",
                wallet.private_key, wallet.address, wallet.network, wallet.compressed
            )
        }
    }
}

fn print_ethereum_wallet(count: usize, json: bool) {
    use ethereum::Network;

    let network = Network::Mainnet;
    let format = EthereumFormat::Standard;
    let private_key = EthereumPrivateKey::new(network);
    let address = EthereumAddress::from_private_key(&private_key, Some(format));

    #[derive(Serialize, Debug)]
    pub struct Wallet {
        private_key: String,
        address: String,
        network: String,
    };

    let wallet = Wallet {
        private_key: private_key.wif.clone(),
        address: address.address,
        network: network.to_string(),
    };

    for _ in 0..count {
        if json {
            println!("{}", serde_json::to_string_pretty(&wallet).unwrap())
        } else {
            println!(
                "
        Private Key:    {}
        Address:        {}
        ",
                wallet.private_key, wallet.address
            )
        }
    }
}

fn print_monero_wallet(count: usize, testnet: bool, json: bool) {
    let wallets = MoneroWalletBuilder::build_many_from_options(testnet, count);
    if json {
        println!("{}", serde_json::to_string_pretty(&wallets).unwrap())
    } else {
        wallets.iter().for_each(|wallet| println!("{}", wallet));
    }
}

fn print_zcash_wallet(
    count: usize,
    testnet: bool,
    format: &ZcashFormat,
    json: bool) {
    use zcash::Network;

    let network = match testnet {
        true => Network::Testnet,
        false => Network::Mainnet
    };

    let private_key = ZcashPrivateKey::new(network);
    let address = ZcashAddress::from_private_key(&private_key, Some(format.clone()));

    #[derive(Serialize, Debug)]
    pub struct Wallet {
        private_key: String,
        address: String,
        network: String,
        compressed: bool
    };

    let wallet = Wallet {
        private_key: private_key.wif.clone(),
        address: address.address,
        network: private_key.network.to_string(),
        compressed: private_key.compressed
    };

    for _ in 0..count {
        if json {
            println!("{}", serde_json::to_string_pretty(&wallet).unwrap())
        } else {
            println!(
                "
        Private Key:    {}
        Address:        {}
        Network:        {}
        Compressed:     {}
        ",
                wallet.private_key,
                wallet.address,
                wallet.network,
                wallet.compressed
            )
        }
    }
}
