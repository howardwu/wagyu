#[macro_use(value_t)]
extern crate clap;
extern crate bitcoin;

use bitcoin::builder::WalletBuilder;
use clap::{App, Arg};

fn main() {
    let matches = App::new("wagen")
       .version("v0.1.0")
       .about("Generate a wallet for any cryptocurrency

Supported Currencies: Bitcoin")
       .author("Argus Observer <ali@argus.observer>")
       .arg(Arg::with_name("currency")
            .required(true)
            .help("Name of the currency to generate a wallet for (e.g. bitcoin)"))
        .arg(Arg::with_name("network")
            .short("N")
            .long("network")
            .takes_value(true)
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
       .get_matches();

    let currency = matches.value_of("currency").unwrap();
    let compressed = matches.is_present("compressed");
    let count = value_t!(matches.value_of("count"), u32).unwrap_or_else(|_e| 1);
    let testnet = match matches.value_of("network") {
        Some("mainnet") => false,
        Some("Mainnet") => false,
        Some("livenet") => false,
        Some("testnet") => true,
        Some("Testnet") => true,
        _ => false,
    };

    match currency {
        "bitcoin" => print_bitcoin_wallet(count, testnet, compressed),
        _ => panic!("Unsupported currency"),
    };
}

fn print_bitcoin_wallet(count: u32, testnet: bool, compressed: bool) {
    for _ in 0..count {
        let wallet = WalletBuilder::build_from_options(compressed, testnet);
        println!("{}", wallet);
    }
}
