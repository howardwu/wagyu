//! # Wagu CLI
//!
//! A command-line tool to generate cryptocurrency wallets.

use bitcoin::address::Format as BitcoinFormat;
use bitcoin::{BitcoinAddress, BitcoinPrivateKey, Mainnet as BitcoinMainnet, Testnet as BitcoinTestnet};
use ethereum::{EthereumAddress, EthereumPrivateKey};
use monero::address::Format as MoneroFormat;
use monero::{MoneroAddress, MoneroPrivateKey, Mainnet as MoneroMainnet, Testnet as MoneroTestnet};
use wagu_model::{Address, PrivateKey};
use zcash::address::Format as ZcashFormat;
use zcash::{ZcashAddress, ZcashPrivateKey, Mainnet as ZcashMainnet, Testnet as ZcashTestnet};

use clap::{App, Arg, SubCommand, AppSettings};
use serde::Serialize;
use std::marker::PhantomData;

fn main() {
    let network_vals = ["mainnet", "testnet"];
    let matches = App::new("wagu")
        .version("v0.6.0")
        .about("Generate a wallet for Bitcoin, Ethereum, Monero, and Zcash")
        .author("Argus <team@argus.dev>")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("bitcoin")
            .about("Generate a Bitcoin wallet")
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
            .arg(Arg::with_name("bech32")
                .long("bech32")
                .conflicts_with("segwit")
                .help("Enabling this flag generates a wallet with a Bech32 (SegWit enabled) address"))
        )
        .subcommand(SubCommand::with_name("ethereum")
            .about("Generate an Ethereum wallet")
            .arg(Arg::with_name("count")
                .short("n")
                .long("count")
                .takes_value(true)
                .help("Number of wallets to generate"))
            .arg(Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Enabling this flag prints the wallet in JSON format"))
        )
        .subcommand(SubCommand::with_name("monero")
            .about("Generate a Monero wallet")
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
            .arg(Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Enabling this flag prints the wallet in JSON format"))
        )
        .subcommand(SubCommand::with_name("zcash")
            .about("Generate a Zcash wallet")
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
            .arg(Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Enabling this flag prints the wallet in JSON format"))
            .arg(Arg::with_name("shielded")
                .long("shielded")
                .help("Enabling this flag generates a wallet with a shielded address"))
        )
        .get_matches();

    match matches.subcommand() {
        ("bitcoin", Some(bitcoin_matches)) => {
            let json = bitcoin_matches.is_present("json");
            let count = clap::value_t!(bitcoin_matches.value_of("count"), usize).unwrap_or_else(|_e| 1);
            let bitcoin_address_type = if bitcoin_matches.is_present("segwit") {
                BitcoinFormat::P2SH_P2WPKH
            } else if bitcoin_matches.is_present("bech32") {
                BitcoinFormat::Bech32
            } else {
                BitcoinFormat::P2PKH
            };

            let testnet = match bitcoin_matches.value_of("network") {
                Some("mainnet") => false,
                Some("testnet") => true,
                _ => false,
            };

            print_bitcoin_wallet(count, testnet, &bitcoin_address_type, json);
        },
        ("ethereum", Some(ethereum_matches)) => {
            let json = ethereum_matches.is_present("json");
            let count = clap::value_t!(ethereum_matches.value_of("count"), usize).unwrap_or_else(|_e| 1);

            print_ethereum_wallet(count, json);
        },
        ("monero", Some(monero_matches)) => {
            let json = monero_matches.is_present("json");
            let count = clap::value_t!(monero_matches.value_of("count"), usize).unwrap_or_else(|_e| 1);

            let testnet = match monero_matches.value_of("network") {
                Some("mainnet") => false,
                Some("testnet") => true,
                _ => false,
            };

            print_monero_wallet(count, testnet, json);
        },
        ("zcash", Some(zcash_matches)) => {
            let json = zcash_matches.is_present("json");
            let count = clap::value_t!(zcash_matches.value_of("count"), usize).unwrap_or_else(|_e| 1);

            let zcash_address_type = if zcash_matches.is_present("shielded") {
                ZcashFormat::Sprout
            } else {
                ZcashFormat::P2PKH
            };
            let testnet = match zcash_matches.value_of("network") {
                Some("mainnet") => false,
                Some("testnet") => true,
                _ => false,
            };

            print_zcash_wallet(count, testnet, &zcash_address_type, json);
        },
        ("", None)   => println!("No subcommand was used"),
        _            => unreachable!(),
    }
}

fn print_bitcoin_wallet(count: usize, testnet: bool, format: &BitcoinFormat, json: bool) {
    #[derive(Serialize, Debug)]
    pub struct Wallet {
        private_key: String,
        address: String,
        network: String,
        compressed: bool,
    };

    let wallet = if testnet {
        let private_key = BitcoinPrivateKey::<BitcoinTestnet>::new().unwrap();
        let address = BitcoinAddress::from_private_key(&private_key, &format).unwrap();

        Wallet {
            private_key: private_key.to_string(),
            address: address.to_string(),
            network: "testnet".into(),
            compressed: private_key.compressed,
        }
    } else {
        let private_key = BitcoinPrivateKey::<BitcoinMainnet>::new().unwrap();
        let address = BitcoinAddress::from_private_key(&private_key, &format).unwrap();

        Wallet {
            private_key: private_key.to_string(),
            address: address.to_string(),
            network: "mainnet".into(),
            compressed: private_key.compressed,
        }
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
    #[derive(Serialize, Debug)]
    pub struct Wallet {
        private_key: String,
        address: String,
    };

    let private_key = EthereumPrivateKey::new().unwrap();
    let address = EthereumAddress::from_private_key(&private_key, &PhantomData).unwrap();

    let wallet = Wallet {
        private_key: private_key.to_string(),
        address: address.address,
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
    #[derive(Serialize, Debug)]
    pub struct Wallet {
        private_key: String,
        address: String,
        network: String,
    };

    // TODO (howardwu): Add support for all Monero formats.
    let wallet = if testnet {
        let private_key = MoneroPrivateKey::<MoneroTestnet>::new().unwrap();
        let address = MoneroAddress::from_private_key(&private_key, &MoneroFormat::Standard).unwrap();

        Wallet {
            private_key: private_key.to_string(),
            address: address.to_string(),
            network: "testnet".into(),
        }
    } else {
        let private_key = MoneroPrivateKey::<MoneroMainnet>::new().unwrap();
        let address = MoneroAddress::from_private_key(&private_key, &MoneroFormat::Standard).unwrap();

        Wallet {
            private_key: private_key.to_string(),
            address: address.to_string(),
            network: "mainnet".into(),
        }
    };

    for _ in 0..count {
        if json {
            println!("{}", serde_json::to_string_pretty(&wallet).unwrap())
        } else {
            println!(
                "
        Private ( Spend, View ) Key:    {}
        Address:              {}
        ",
                wallet.private_key, wallet.address
            )
        }
    }
}

fn print_zcash_wallet(count: usize, testnet: bool, format: &ZcashFormat, json: bool) {
    #[derive(Serialize, Debug)]
    pub struct Wallet {
        private_key: String,
        address: String,
        network: String
    };

    let wallet = if testnet {
        let private_key = ZcashPrivateKey::<ZcashTestnet>::new().unwrap();
        let address = ZcashAddress::from_private_key(&private_key, &format).unwrap();

        Wallet {
            private_key: private_key.to_string(),
            address: address.to_string(),
            network: "testnet".into(),
        }
    } else {
        let private_key = ZcashPrivateKey::<ZcashMainnet>::new().unwrap();
        let address = ZcashAddress::from_private_key(&private_key, &format).unwrap();

        Wallet {
            private_key: private_key.to_string(),
            address: address.to_string(),
            network: "mainnet".into(),
        }
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
        ",
                wallet.private_key,
                wallet.address,
                wallet.network
            )
        }
    }
}
