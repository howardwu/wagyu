#[macro_use(value_t)]
extern crate clap;
extern crate bitcoin;
extern crate serde_json;
extern crate zcash;

use bitcoin::builder::{WalletBuilder as BitcoinWalletBuilder};
use zcash::builder::{WalletBuilder as ZcashWalletBuilder};
use bitcoin::address::Type as AddressType;
use clap::{App, Arg};

fn main() {
    let network_vals = ["mainnet", "testnet"];
    let matches = App::new("wagen")
       .version("v0.1.0")
       .about("Generate a wallet for any cryptocurrency

Supported Currencies: Bitcoin, Zcash (t-address)")
       .author("Argus Observer <ali@argus.observer>")
       .arg(Arg::with_name("currency")
            .required(true)
            .help("Name of the currency to generate a wallet for (e.g. bitcoin, zcash)"))
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
    let mut compressed = matches.is_present("compressed");
    let json = matches.is_present("json");
    let count = value_t!(matches.value_of("count"), usize).unwrap_or_else(|_e| 1);
    let address_type = if matches.is_present("segwit") {
        compressed = true;
        AddressType::P2WPKH_P2SH
    } else {
        AddressType::P2PKH
    };
    let testnet = match matches.value_of("network") {
        Some("mainnet") => false,
        Some("testnet") => true,
        _ => false,
    };

    match currency {
        "bitcoin" => print_bitcoin_wallet(count, testnet, &address_type, compressed, json),
        "zcash" => print_zcash_wallet(count, testnet, compressed, json),
        _ => panic!("Unsupported currency"),
    };
}

fn print_bitcoin_wallet(count: usize, testnet: bool, address_type: &AddressType, compressed: bool, json: bool) {
    let wallets = BitcoinWalletBuilder::build_many_from_options(compressed, testnet, address_type, count);
    if json {
        println!("{}", serde_json::to_string_pretty(&wallets).unwrap())
    } else {
        wallets.iter().for_each(|wallet| println!("{}", wallet));
    }
}

fn print_zcash_wallet(count: usize, testnet: bool, compressed: bool, json: bool) {
    let wallets = ZcashWalletBuilder::build_many_from_options(compressed, testnet, count);
    if json {
        println!("{}", serde_json::to_string_pretty(&wallets).unwrap())
    } else {
        wallets.iter().for_each(|wallet| println!("{}", wallet));
    }
}
