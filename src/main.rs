extern crate arrayvec;
extern crate base58;
#[macro_use(value_t)]
extern crate clap;
extern crate digest;
extern crate either;
#[macro_use]
extern crate lazy_static;
extern crate openssl;
extern crate safemem;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tiny_keccak;

use clap::{App, Arg};

use bitcoin::wallet::BitcoinWallet;
use builder::WalletBuilder;
use clap::ArgMatches;
use ethereum::wallet::EthereumWallet;
use monero::wallet::MoneroWallet;
use traits::Config;
use traits::Network;
use traits::Wallet;
use zcash::wallet::ZcashWallet;

mod bitcoin;
mod builder;
mod ethereum;
mod monero;
mod traits;
mod zcash;

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
    let json = matches.is_present("json");
    let count = value_t!(matches.value_of("count"), usize).unwrap_or_else(|_e| 1);
    let config: Config = build_config(&matches);

    match currency {
        "bitcoin" => {
            print_wallet::<BitcoinWallet>(count, config, json);
        }
        "monero" => {
            print_wallet::<MoneroWallet>(count, config, json);
        }
        "zcash" => {
            print_wallet::<ZcashWallet>(count, config, json);
        }
        "ethereum" => {
            print_wallet::<EthereumWallet>(count, config, json);
        }
        _ => panic!("Unsupported currency"),
    };
}

fn build_config(matches: &ArgMatches) -> Config {
    let mut config: Config = Default::default();
    config.compressed = matches.is_present("compressed");

    if matches.is_present("segwit") {
        config.p2wpkh_p2sh = true;
        config.compressed = true;
    } else {
        config.p2pkh = true;
    }

    match matches.value_of("network") {
        Some("testnet") => {
            config.network = Network::Testnet;
        }
        _ => {
            config.network = Network::Mainnet;
        }
    };

    config
}

fn print_wallet<T: Wallet>(count: usize, config: Config, json: bool) {
    let wallets = WalletBuilder::build_many_from_options::<T>(config, count);
    if json {
        println!("{}", serde_json::to_string_pretty(&wallets).unwrap())
    } else {
        wallets.iter().for_each(|wallet| println!("{}", wallet));
    }
}
