#[macro_use(value_t)]
extern crate clap;
#[macro_use]
extern crate lazy_static;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_derive;

extern crate arrayvec;
extern crate base58;
extern crate digest;
extern crate either;
extern crate safemem;
extern crate serde_json;
extern crate tiny_keccak;

// mod bitcoin;
// mod ethereum;
mod monero;
// mod zcash;

// use bitcoin::address::Type as AddressType;
// use bitcoin::builder::WalletBuilder as BitcoinWalletBuilder;
use clap::{App, Arg};
// use ethereum::builder::WalletBuilder as EthereumWalletBuilder;
use monero::builder::WalletBuilder as MoneroWalletBuilder;
// use zcash::builder::WalletBuilder as ZcashWalletBuilder;

fn main() {
    let network_vals = ["mainnet", "testnet"];
    let matches = App::new("wagu")
       .version("v0.5.0")
       .about("Generate a wallet for any cryptocurrency

Supported Currencies: Bitcoin, Ethereum, Monero, Zcash (t-address)")
       .author("Argus Observer <team@argus.observer>")
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
    let mut compressed = matches.is_present("compressed");
    let json = matches.is_present("json");
    let count = value_t!(matches.value_of("count"), usize).unwrap_or_else(|_e| 1);
    // let address_type = if matches.is_present("segwit") {
    //     compressed = true;
    //     AddressType::P2WPKH_P2SH
    // } else {
    //     AddressType::P2PKH
    // };
    let testnet = match matches.value_of("network") {
        Some("mainnet") => false,
        Some("testnet") => true,
        _ => false,
    };

    match currency {
        // "bitcoin" => print_bitcoin_wallet(count, testnet, &address_type, compressed, json),
        "monero" => print_monero_wallet(count, testnet, json),
        // "zcash" => print_zcash_wallet(count, testnet, compressed, json),
        // "ethereum" => print_ethereum_wallet(count, json),
        _ => panic!("Unsupported currency"),
    };
}

// fn print_bitcoin_wallet(
//     count: usize,
//     testnet: bool,
//     address_type: &AddressType,
//     compressed: bool,
//     json: bool,
// ) {
//     let wallets =
//         BitcoinWalletBuilder::build_many_from_options(compressed, testnet, address_type, count);
//     if json {
//         println!("{}", serde_json::to_string_pretty(&wallets).unwrap())
//     } else {
//         wallets.iter().for_each(|wallet| println!("{}", wallet));
//     }
// }

// fn print_zcash_wallet(count: usize, testnet: bool, compressed: bool, json: bool) {
//     let wallets = ZcashWalletBuilder::build_many_from_options(compressed, testnet, count);
//     if json {
//         println!("{}", serde_json::to_string_pretty(&wallets).unwrap())
//     } else {
//         wallets.iter().for_each(|wallet| println!("{}", wallet));
//     }
// }

// fn print_ethereum_wallet(count: usize, json: bool) {
//     let wallets = EthereumWalletBuilder::build_many_from_options(count);
//     if json {
//         println!("{}", serde_json::to_string_pretty(&wallets).unwrap())
//     } else {
//         wallets.iter().for_each(|wallet| println!("{}", wallet));
//     }
// }

fn print_monero_wallet(count: usize, testnet: bool, json: bool) {
    let wallets = MoneroWalletBuilder::build_many_from_options(testnet, count);
    if json {
        println!("{}", serde_json::to_string_pretty(&wallets).unwrap())
    } else {
        wallets.iter().for_each(|wallet| println!("{}", wallet));
    }
}
