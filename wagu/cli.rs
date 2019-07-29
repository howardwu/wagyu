//! # Wagu CLI
//!
//! A command-line tool to generate cryptocurrency wallets.

use bitcoin::address::Format as BitcoinFormat;
use bitcoin::{BitcoinAddress, BitcoinMnemonic, BitcoinPrivateKey, Mainnet as BitcoinMainnet, Testnet as BitcoinTestnet, BitcoinNetwork, English};
use ethereum::{EthereumAddress, EthereumPrivateKey};
use monero::address::Format as MoneroFormat;
use monero::{Mainnet as MoneroMainnet, MoneroAddress, MoneroPrivateKey, Testnet as MoneroTestnet};
use wagu_model::{Address, Mnemonic, PrivateKey, MnemonicExtended};
use zcash::address::Format as ZcashFormat;
use zcash::{Mainnet as ZcashMainnet, Testnet as ZcashTestnet, ZcashAddress, ZcashPrivateKey};

use clap::{App, Arg, SubCommand, AppSettings};
use serde::Serialize;
use std::marker::PhantomData;
use std::str::FromStr;

struct WalletMnemonic {
    pub new: bool,
    pub word_count: u8,
    pub mnemonic: String,
    pub password: String,
}

fn main() {
    let network_vals = ["mainnet", "testnet"];
    let matches = App::new("wagu")
        .version("v0.6.0")
        .about("Generate a wallet for Bitcoin, Ethereum, Monero, and Zcash")
        .author("Argus <team@argus.dev>")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("bitcoin")
            .about("Generate a Bitcoin wallet (run with -h for additional options)")
            .arg(Arg::with_name("bech32")
                .long("bech32")
                .conflicts_with("segwit")
                .help("Generate a wallet with a Bech32 (SegWit enabled) address"))
            .arg(Arg::with_name("network")
                .short("N")
                .long("network")
                .takes_value(true)
                .possible_values(&network_vals)
                .help("Network of wallet(s) to generate"))
            .arg(Arg::with_name("count")
                .short("n")
                .long("count")
                .takes_value(true)
                .help("Number of wallets to generate"))
            .arg(Arg::with_name("compressed")
                .short("c")
                .long("compressed")
                .help("Generate a wallet with a compressed public key"))
            .arg(Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Print the generated wallet(s) in JSON format"))
            .arg(Arg::with_name("mnemonic")
                .short("m")
                .takes_value(true)
//                .number_of_values(2)
                .min_values(0)
//                .value_names(&["mnemonic", "password"])
                .conflicts_with("bech32")
                .conflicts_with("segwit")
                .help("Generate a wallet by importing a Mnemonic (in quotes)")
            )
            .arg(Arg::with_name("segwit")
                .long("segwit")
                .help("Generate a wallet with a SegWit address"))
            .arg(Arg::with_name("private key")
                .short("p")
                .takes_value(true)
                .conflicts_with("bech32")
                .conflicts_with("mnemonic")
                .conflicts_with("segwit")
                .help("Generate a wallet by importing a private key")
            )
        )
        .subcommand(SubCommand::with_name("ethereum")
            .about("Generate an Ethereum wallet (run with -h for additional options)")
            .arg(Arg::with_name("count")
                .short("n")
                .long("count")
                .takes_value(true)
                .help("Number of wallets to generate"))
            .arg(Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Print the generated wallet(s) in JSON format"))
        )
        .subcommand(SubCommand::with_name("monero")
            .about("Generate a Monero wallet (run with -h for additional options)")
            .arg(Arg::with_name("count")
                .short("n")
                .long("count")
                .takes_value(true)
                .help("Number of wallets to generate"))
            .arg(Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Print the generated wallet(s) in JSON format"))
            .arg(Arg::with_name("network")
                .short("N")
                .long("network")
                .takes_value(true)
                .possible_values(&network_vals)
                .help("Network of wallet(s) to generate"))
            .arg(Arg::with_name("integrated")
                .short("i")
                .long("integrated")
                .takes_value(true)
                .value_name("Payment ID")
                .help("Generate a wallet with an integrated address - Requires a paymentID"))
            .arg(Arg::with_name("subaddress")
                .short("s")
                .long("subaddress")
                .takes_value(true)
                .value_names(&["Major index", "Minor index"])
                .conflicts_with("integrated")
                .number_of_values(2)
                .help("Generate a wallet with a subaddress - Requires a major (account) and minor index"))
        )
        .subcommand(SubCommand::with_name("zcash")
            .about("Generate a Zcash wallet (run with -h for additional options)")
            .arg(Arg::with_name("network")
                .short("N")
                .long("network")
                .takes_value(true)
                .possible_values(&network_vals)
                .help("Network of wallet(s) to generate"))
            .arg(Arg::with_name("count")
                .short("n")
                .long("count")
                .takes_value(true)
                .help("Number of wallets to generate"))
            .arg(Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Print the generated wallet(s) in JSON format"))
            .arg(Arg::with_name("shielded")
                .long("shielded")
                .help("Generate a wallet with a shielded address"))
        )
        .get_matches();

    match matches.subcommand() {
        ("bitcoin", Some(bitcoin_matches)) => {
            let count = clap::value_t!(bitcoin_matches.value_of("count"), usize).unwrap_or_else(|_e| 1);
            let json = bitcoin_matches.is_present("json");
            let bitcoin_address_type = if bitcoin_matches.is_present("segwit") {
                BitcoinFormat::P2SH_P2WPKH
            } else if bitcoin_matches.is_present("bech32") {
                BitcoinFormat::Bech32
            } else {
                BitcoinFormat::P2PKH
            };

            let network = match bitcoin_matches.value_of("network") {
                Some("testnet") => "testnet",
                _ => "mainnet",
            };

            let private_key: Option<&str> = if bitcoin_matches.is_present("private key") {
                bitcoin_matches.value_of("private key")
            } else { None };

            let wallet_mnemonic = if bitcoin_matches.is_present("mnemonic") {
                let mut mnemonic_values = bitcoin_matches.values_of("mnemonic").unwrap();
                match mnemonic_values.next() {
                    None => {
                        Some(WalletMnemonic { new: true, word_count: 15, mnemonic: "".into(), password: "".into() })
                    }
                    Some(val) => {
                        let num = val.parse();
                        if num.is_err() {
                            Some(WalletMnemonic { new: false, word_count: 0, mnemonic: val.into(), password: mnemonic_values.next().unwrap().into() })
                        } else {
                            Some(WalletMnemonic { new: true, word_count: num.clone().unwrap(), mnemonic: val.into(), password: "".into() })
                        }
                    }
                }
            } else { None };

            if network == "testnet" {
                type N = BitcoinTestnet;
                print_bitcoin_wallet::<N>(private_key, wallet_mnemonic, count, network, &bitcoin_address_type, json);
            } else {
                type N = BitcoinMainnet;
                print_bitcoin_wallet::<N>(private_key, wallet_mnemonic, count, network, &bitcoin_address_type, json);
            }
        },
        ("ethereum", Some(ethereum_matches)) => {
            let count = clap::value_t!(ethereum_matches.value_of("count"), usize).unwrap_or_else(|_e| 1);
            let json = ethereum_matches.is_present("json");

            print_ethereum_wallet(count, json);
        },
        ("monero", Some(monero_matches)) => {
            let count = clap::value_t!(monero_matches.value_of("count"), usize).unwrap_or_else(|_e| 1);
            let json = monero_matches.is_present("json");

            let monero_address_type = if monero_matches.is_present("subaddress") {
                let indexes: Vec<u32> = monero_matches.values_of("subaddress").unwrap().into_iter().map(|index| index.to_owned().parse().unwrap()).collect();
                MoneroFormat::Subaddress(indexes[0], indexes[1])
            } else if monero_matches.is_present("integrated") {
                let mut payment_id = [0u8; 8];
                payment_id.copy_from_slice(&hex::decode(monero_matches.value_of("integrated").unwrap()).unwrap());
                MoneroFormat::Integrated(payment_id)
            } else {
                MoneroFormat::Standard
            };

            let testnet = match monero_matches.value_of("network") {
                Some("mainnet") => false,
                Some("testnet") => true,
                _ => false,
            };

            print_monero_wallet(count, testnet, &monero_address_type, json);
        },
        ("zcash", Some(zcash_matches)) => {
            let count = clap::value_t!(zcash_matches.value_of("count"), usize).unwrap_or_else(|_e| 1);
            let json = zcash_matches.is_present("json");

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

fn print_bitcoin_wallet<N: BitcoinNetwork>(private_key: Option<&str>, wallet_mnemonic: Option<WalletMnemonic>, count: usize, network: &str, format: &BitcoinFormat, json: bool) {
    #[derive(Serialize, Debug)]
    pub struct Wallet {
        private_key: String,
        address: String,
        network: String,
        compressed: bool,
    };

    #[derive(Serialize, Debug)]
    pub struct ExtendedWallet {
        private_key: String,
        address: String,
        network: String,
        compressed: bool,
        test: Option<u32>,
    };

    for _ in 0..count {
        let wallet = match (private_key, &wallet_mnemonic ) {
            (None, None) => {
                let private_key = BitcoinPrivateKey::<N>::new().unwrap();
                let address = BitcoinAddress::from_private_key(&private_key, &format).unwrap();

                Wallet {
                    private_key: private_key.to_string(),
                    address: address.to_string(),
                    network: network.into(),
                    compressed: private_key.is_compressed(),
                }
            },
            (Some(wif), None) => {
                let private_key = BitcoinPrivateKey::<N>::from_str(wif).unwrap();
                let address = BitcoinAddress::from_private_key(&private_key, &format).unwrap();

                Wallet {
                    private_key: private_key.to_string(),
                    address: address.to_string(),
                    network: network.into(),
                    compressed: private_key.is_compressed(),
                }
            },
            (None, Some(wallet_mnemonic)) => {
                type W = English;
                if wallet_mnemonic.new {
                    let mnemonic = BitcoinMnemonic::<N, W>::new(wallet_mnemonic.word_count).unwrap();
                    let extended_private_key = mnemonic.to_extended_private_key(Some(&wallet_mnemonic.password)).unwrap();
                    println!("extended private key string = {:?}\n", extended_private_key.to_string());
                    println!("extended private key = {:?}", extended_private_key);
                    let private_key = mnemonic.to_private_key(Some(&wallet_mnemonic.password)).unwrap();
                    let address = BitcoinAddress::from_private_key(&private_key, &format).unwrap();

                    Wallet {
                        private_key: private_key.to_string(),
                        address: address.to_string(),
                        network: network.into(),
                        compressed: private_key.is_compressed(),
                    }
                }
                else {
                    let mnemonic = BitcoinMnemonic::<N, W>::from_phrase(&wallet_mnemonic.mnemonic).unwrap();
                    let extended_private_key = mnemonic.to_extended_private_key(Some(&wallet_mnemonic.password)).unwrap();
                    println!("extended private key string = {:?}", extended_private_key.to_string());
                    println!("extended private key = {:?}", extended_private_key);
                    let private_key = mnemonic.to_private_key(Some(&wallet_mnemonic.password)).unwrap();
                    let address = BitcoinAddress::from_private_key(&private_key, &format).unwrap();

                    Wallet {
                        private_key: private_key.to_string(),
                        address: address.to_string(),
                        network: network.into(),
                        compressed: private_key.is_compressed(),
                    }
                }
            },
            _ => unreachable!(),
        };

        // TODO clean format for different wallet outputs. Add child index, xprivkey, depth

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

    for _ in 0..count {
        let private_key = EthereumPrivateKey::new().unwrap();
        let address = EthereumAddress::from_private_key(&private_key, &PhantomData).unwrap();

        let wallet = Wallet {
            private_key: private_key.to_string(),
            address: address.to_string(),
        };

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

fn print_monero_wallet(count: usize, testnet: bool, format: &MoneroFormat, json: bool) {
    #[derive(Serialize, Debug)]
    pub struct Wallet {
        private_key: String,
        address: String,
        network: String,
    };

    for _ in 0..count {
        let wallet = if testnet {
            let private_key = MoneroPrivateKey::<MoneroTestnet>::new().unwrap();
            let address = MoneroAddress::from_private_key(&private_key, format).unwrap();

            Wallet {
                private_key: private_key.to_string(),
                address: address.to_string(),
                network: "testnet".into(),
            }
        } else {
            let private_key = MoneroPrivateKey::<MoneroMainnet>::new().unwrap();
            let address = MoneroAddress::from_private_key(&private_key, format).unwrap();

            Wallet {
                private_key: private_key.to_string(),
                address: address.to_string(),
                network: "mainnet".into(),
            }
        };

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

    for _ in 0..count {
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
