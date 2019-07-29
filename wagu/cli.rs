//! # Wagu CLI
//!
//! A command-line tool to generate cryptocurrency wallets.

use bitcoin::address::Format as BitcoinFormat;
use bitcoin::{BitcoinAddress, BitcoinMnemonic, BitcoinPrivateKey, Mainnet as BitcoinMainnet, Testnet as BitcoinTestnet, BitcoinNetwork, English};
use ethereum::{EthereumAddress, EthereumPrivateKey};
use monero::address::Format as MoneroFormat;
use monero::{Mainnet as MoneroMainnet, MoneroAddress, MoneroPrivateKey, Testnet as MoneroTestnet};
use wagu_model::{Address, PrivateKey, MnemonicExtended, ExtendedPrivateKey};
use zcash::address::Format as ZcashFormat;
use zcash::{Mainnet as ZcashMainnet, Testnet as ZcashTestnet, ZcashAddress, ZcashPrivateKey};

use clap::{App, Arg, SubCommand, AppSettings};
use serde::Serialize;
use std::marker::PhantomData;
use std::str::FromStr;

#[derive(Serialize, Clone, Debug)]
pub struct BitcoinWallet {
    pub private_key: Option<String>,
    pub wallet_mnemonic: Option<WalletMnemonic>,
    pub count: usize,
    pub network: String,
    pub format: BitcoinFormat,
    pub json: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct WalletMnemonic {
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
            .arg(Arg::with_name("compressed")
                .short("c")
                .long("compressed")
                .help("Generate a wallet with a compressed public key"))
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
            .arg(Arg::with_name("segwit")
                .long("segwit")
                .help("Generate a wallet with a SegWit address"))
            .subcommand(SubCommand::with_name("mnemonic")
                .about("Generate a wallet using mnemonics")
                .arg(Arg::with_name("word count")
                    .long("word_count")
                    .takes_value(true)
                    .number_of_values(1)
                    .value_name("word count")
                    .conflicts_with("import")
                    .help("Generate a wallet with a new mnemonic with the specified word count"))
                .arg(Arg::with_name("password")
                    .long("password")
                    .short("p")
                    .takes_value(true)
                    .number_of_values(1)
                    .value_name("password")
                    .help("Specify a password used for extended private key derivation"))
                .arg(Arg::with_name("import")
                    .long("import")
                    .takes_value(true)
                    .number_of_values(1)
                    .value_name("mnemonic")
                    .conflicts_with("new")
                    .help("Generate a wallet by importing a Mnemonic (in quotes)"))
            )
            .subcommand(SubCommand::with_name("private_key")
                .about("Generate a wallet by importing a private key")
                .arg(Arg::with_name("import")
                    .long("import")
                    .takes_value(true)
                    .number_of_values(1)
                    .value_name("private key")
                    .help("Generate a wallet by importing a private key"))
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

            let bitcoin_wallet = match bitcoin_matches.subcommand() {
                ("", None) => {
                    BitcoinWallet {
                        private_key: None,
                        wallet_mnemonic: None,
                        count,
                        network: network.into(),
                        format: bitcoin_address_type,
                        json
                    }
                },
                ("private_key", Some(private_key_matches)) => {
                    let private_key: Option<String> = private_key_matches.value_of("import").map(|s| s.to_string());

                    BitcoinWallet {
                        private_key,
                        wallet_mnemonic: None,
                        count,
                        network: network.into(),
                        format: bitcoin_address_type,
                        json
                    }
                },
                ("mnemonic", Some(mnemonic_matches)) => {
                    let password: String = mnemonic_matches.value_of("password").unwrap_or("").into();
                    let wallet_mnemonic = if mnemonic_matches.is_present("import") {
                        let mnemonic_values: &str = mnemonic_matches.value_of("import").unwrap();
                        let words: Vec<_> = mnemonic_values.split(' ').collect();
                        Some(WalletMnemonic { new: false, word_count: words.len() as u8, mnemonic: mnemonic_values.into(), password })
                    } else if mnemonic_matches.is_present("word count") {
                        let word_count: u8 = mnemonic_matches.value_of("word count").unwrap().parse().unwrap();
                        Some(WalletMnemonic { new: true, word_count, mnemonic: "".into(), password })
                    } else {
                        Some(WalletMnemonic { new: true, word_count: 12, mnemonic: "".into(), password })
                    };

                    BitcoinWallet {
                        private_key: None,
                        wallet_mnemonic,
                        count,
                        network: network.into(),
                        format: bitcoin_address_type,
                        json
                    }
                }
                _ => unreachable!(),
            };

            if network == "testnet" {
                type N = BitcoinTestnet;
                print_bitcoin_wallet::<N>(bitcoin_wallet);
            } else {
                type N = BitcoinMainnet;
                print_bitcoin_wallet::<N>(bitcoin_wallet);
            };
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
                ZcashFormat::Sapling(None)
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

fn print_bitcoin_wallet<N: BitcoinNetwork>(bitcoin_wallet: BitcoinWallet) {
    #[derive(Serialize, Debug)]
    pub struct Wallet {
        private_key: String,
        address: String,
        network: String,
        format: BitcoinFormat,
        compressed: bool,
    };

    #[derive(Serialize, Debug)]
    pub struct ExtendedWallet {
        phrase: String,
        extended_private_key: String,
        private_key: String,
        address: String,
        network: String,
        format: BitcoinFormat,
        compressed: bool,
    };

    for _ in 0..bitcoin_wallet.count {
        match bitcoin_wallet.wallet_mnemonic.clone() {
            None => {
                let private_key = match bitcoin_wallet.private_key.clone() {
                    None => { BitcoinPrivateKey::<N>::new().unwrap() },
                    Some(wif) => { BitcoinPrivateKey::<N>::from_str(&wif).unwrap() },
                };

                let address = BitcoinAddress::from_private_key(&private_key, &bitcoin_wallet.format).unwrap();
                let wallet = Wallet {
                    private_key: private_key.to_string(),
                    address: address.to_string(),
                    network: bitcoin_wallet.network.clone(),
                    format: address.format(),
                    compressed: private_key.is_compressed(),
                };

                if bitcoin_wallet.json {
                    println!("{}", serde_json::to_string_pretty(&wallet).unwrap())
                } else {
                    println!(
                            "
                Private Key:    {}
                Address:        {}
                Network:        {}
                Format:         {}
                Compressed:     {}
                ",
                        wallet.private_key, wallet.address, wallet.network, wallet.format, wallet.compressed
                    )
                }
            },
            Some(wallet_mnemonic) => {
                type W = English;
                let mnemonic = if wallet_mnemonic.new { BitcoinMnemonic::<N, W>::new(wallet_mnemonic.word_count).unwrap()
                } else { BitcoinMnemonic::<N, W>::from_phrase(&wallet_mnemonic.mnemonic).unwrap() };

                let extended_private_key = mnemonic.to_extended_private_key(Some(&wallet_mnemonic.password)).unwrap();
                let private_key = extended_private_key.to_private_key();
                let address = BitcoinAddress::from_private_key(&private_key, &bitcoin_wallet.format).unwrap();

                let mnemonic_wallet = ExtendedWallet {
                    phrase:  mnemonic.to_string(),
                    extended_private_key: extended_private_key.to_string(),
                    private_key: private_key.to_string(),
                    address: address.to_string(),
                    network: bitcoin_wallet.network.clone(),
                    format: address.format(),
                    compressed: private_key.is_compressed(),
                };

                if bitcoin_wallet.json {
                    println!("{}", serde_json::to_string_pretty(&mnemonic_wallet).unwrap())
                } else {
                    println!(
                        "
            Mnemonic:               {}
            Extended private Key:   {}
            Private Key:            {}
            Address:                {}
            Network:                {}
            Format:                 {}
            Compressed:             {}
            ",
                        mnemonic_wallet.phrase, mnemonic_wallet.extended_private_key, mnemonic_wallet.private_key, mnemonic_wallet.address, mnemonic_wallet.network, mnemonic_wallet.format, mnemonic_wallet.compressed
                    )
                }
            }
        };
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
            let private_key = match format {
                ZcashFormat::P2PKH => ZcashPrivateKey::<ZcashMainnet>::new_p2pkh().unwrap(),
                _ => ZcashPrivateKey::<ZcashMainnet>::new_sapling().unwrap(),
            };
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
