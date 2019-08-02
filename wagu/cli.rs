//! # Wagu CLI
//!
//! A command-line tool to generate cryptocurrency wallets.

use bitcoin::address::Format as BitcoinFormat;
use bitcoin::{BitcoinAddress, BitcoinMnemonic, BitcoinPrivateKey, Mainnet as BitcoinMainnet, Testnet as BitcoinTestnet, BitcoinNetwork, English, BitcoinDerivationPath, BitcoinExtendedPrivateKey};
use ethereum::{EthereumAddress, EthereumPrivateKey};
use monero::address::Format as MoneroFormat;
use monero::{Mainnet as MoneroMainnet, MoneroAddress, MoneroPrivateKey, Testnet as MoneroTestnet};
use wagu_model::{Address, PrivateKey, MnemonicExtended, ExtendedPrivateKey};
use zcash::address::Format as ZcashFormat;
use zcash::{Mainnet as ZcashMainnet, Testnet as ZcashTestnet, ZcashAddress, ZcashPrivateKey};

use clap::{App, Arg, SubCommand, AppSettings};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::marker::PhantomData;
use std::str::FromStr;
use rand::Rng;

#[derive(Serialize, Clone, Debug)]
pub struct BitcoinWallet {
    pub private_key: Option<String>,
    pub wallet_mnemonic: Option<WalletMnemonic>,
    pub extended_private_key: Option<WalletExtendedPrivateKey>,
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
    pub path: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct WalletExtendedPrivateKey {
    pub key: Option<String>,
    pub path: Option<String>,
}

fn main() {
    let network_vals = ["mainnet", "testnet"];

    // Generic wallet arguments
    let arg_count = Arg::from_usage("[count] -n --count=[count] 'Number of wallets to generate'");
    let arg_json = Arg::from_usage("[json] -j --json 'Print the generated wallet(s) in JSON format'");
    let arg_network = Arg::from_usage("[network] -N --network=[network] 'Network of wallet(s) to generate'")
        .possible_values(&network_vals);

    // Wallet import arguments
    let arg_path = Arg::from_usage("[path] --path=[path] 'Specify a derivation path'");
    let arg_import = Arg::from_usage("[import] --import")
        .conflicts_with("word_count");
    let arg_password = Arg::from_usage("[password] --password=[password] 'Specify a password used for extended private key derivation'");
    let arg_word_count = Arg::from_usage("[word count] --word_count=[word count] 'Generate a wallet with a new mnemonic with the specified word count'")
        .conflicts_with("import");

    // Bitcoin specific arguments
    let arg_compressed = Arg::from_usage("compressed -c --compressed 'Generate a wallet with a compressed public key'");
    let arg_bech32 = Arg::from_usage("[bech32] --bech32 'Generate a wallet with a Bech32 (SegWit enabled) address'")
        .conflicts_with("segwit");
    let arg_segwit = Arg::from_usage("[segwit] --segwit 'Generate a wallet with a Segwit address'")
        .conflicts_with("bech32");

    // Monero specific arguments
    let arg_integrated = Arg::from_usage("[integrated] -i --integrated=[PaymentID] 'Generate a wallet with an integrated address - Requires a paymentID'")
        .conflicts_with("subaddress");
    let arg_subaddress = Arg::from_usage("[subaddress] -s --subaddress=[Major Index][MinorIndex] 'Generate a wallet with a subaddress - Requires a major (account) and minor index'")
        .conflicts_with("integrated");

    // Zcash specific arguments
    let arg_shielded =  Arg::from_usage("[shielded] --shielded 'Generate a wallet with a shielded address'");

    // Subcommands
    let mnemonic_subcommand = SubCommand::with_name("mnemonic")
        .about("Generate a wallet using mnemonics")
        .arg(&arg_import.clone().number_of_values(1).value_name("mnemonic")
            .help("Generate a wallet by importing a Mnemonic (in quotes)"))
        .arg(&arg_path)
        .arg(&arg_password)
        .arg(&arg_word_count);

    let private_key_subcommand = SubCommand::with_name("private_key")
        .about("Generate a wallet by importing a private key")
        .arg(&arg_import.clone().number_of_values(1).value_name("private key")
            .help("Generate a wallet by importing a private key"));

    let extended_private_key_subcommand = SubCommand::with_name("extended_private_key")
        .about("Generate a wallet from an extended key")
        .arg(&arg_import.clone().number_of_values(1).value_name("extended private key")
            .help("Generate a wallet by importing an extended private key"))
        .arg(&arg_path);

    // Final CLI app
    let matches = App::new("wagyu")
        .version("v0.6.0")
        .about("Generate a wallet for Bitcoin, Ethereum, Monero, and Zcash")
        .author("Argus <team@argus.dev>")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("bitcoin")
            .about("Generate a Bitcoin wallet (run with -h for additional options)")
            .arg(&arg_bech32)
            .arg(&arg_compressed)
            .arg(&arg_count)
            .arg(&arg_json)
            .arg(&arg_network)
            .arg(&arg_segwit)
            .subcommand(mnemonic_subcommand)
            .subcommand(private_key_subcommand)
            .subcommand(extended_private_key_subcommand)
        )
        .subcommand(SubCommand::with_name("ethereum")
            .about("Generate an Ethereum wallet (run with -h for additional options)")
            .arg(&arg_count)
            .arg(&arg_json)
        )
        .subcommand(SubCommand::with_name("monero")
            .about("Generate a Monero wallet (run with -h for additional options)")
            .arg(&arg_count)
            .arg(&arg_json)
            .arg(&arg_network)
            .arg(&arg_integrated)
            .arg(&arg_subaddress)
        )
        .subcommand(SubCommand::with_name("zcash")
            .about("Generate a Zcash wallet (run with -h for additional options)")
            .arg(&arg_network)
            .arg(&arg_count)
            .arg(&arg_json)
            .arg(&arg_shielded)
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
                        extended_private_key: None,
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
                        extended_private_key: None,
                        count,
                        network: network.into(),
                        format: bitcoin_address_type,
                        json
                    }
                },
                ("mnemonic", Some(mnemonic_matches)) => {
                    let password: String = mnemonic_matches.value_of("password").unwrap_or("").into();
                    let path = mnemonic_matches.value_of("path").map(|s| s.to_string());
                    let wallet_mnemonic = if mnemonic_matches.is_present("import") {
                        let mnemonic_values: &str = mnemonic_matches.value_of("import").unwrap();
                        let words: Vec<_> = mnemonic_values.split(' ').collect();
                        Some(WalletMnemonic { new: false, word_count: words.len() as u8, mnemonic: mnemonic_values.into(), password, path })
                    } else if mnemonic_matches.is_present("word count") {
                        let word_count: u8 = mnemonic_matches.value_of("word count").unwrap().parse().unwrap();
                        Some(WalletMnemonic { new: true, word_count, mnemonic: "".into(), password, path })
                    } else {
                        Some(WalletMnemonic { new: true, word_count: 12, mnemonic: "".into(), password, path })
                    };

                    BitcoinWallet {
                        private_key: None,
                        wallet_mnemonic,
                        extended_private_key: None,
                        count,
                        network: network.into(),
                        format: bitcoin_address_type,
                        json
                    }
                },
                ("extended_private_key", Some(xpriv_matches)) => {
                    let path = xpriv_matches.value_of("path").map(|s| s.to_string());
                    let key = xpriv_matches.value_of("import").map(|s| s.to_string());
                    let extended_private_key = Some( WalletExtendedPrivateKey { key, path });

                    BitcoinWallet {
                        private_key: None,
                        wallet_mnemonic: None,
                        extended_private_key,
                        count,
                        network: network.into(),
                        format: bitcoin_address_type,
                        json
                    }
                },
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
        match (bitcoin_wallet.wallet_mnemonic.clone(), bitcoin_wallet.extended_private_key.clone()) {
            (None, None) => {
                let private_key = match bitcoin_wallet.private_key.clone() {
                    None => {
                        let rng = &mut StdRng::from_entropy();
                        BitcoinPrivateKey::<N>::new(rng).unwrap()
                    },
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
            (Some(wallet_mnemonic), None) => {
                type W = English;
                let rng = &mut StdRng::from_entropy();
                let mnemonic = if wallet_mnemonic.new { BitcoinMnemonic::<N, W>::new(wallet_mnemonic.word_count, rng).unwrap()
                } else { BitcoinMnemonic::<N, W>::from_phrase(&wallet_mnemonic.mnemonic).unwrap() };

                let master_xpriv_key = mnemonic.to_extended_private_key(Some(&wallet_mnemonic.password)).unwrap();
                let extended_private_key = match wallet_mnemonic.path {
                    Some(path) => { master_xpriv_key.derive(&BitcoinDerivationPath::from_str(&path).unwrap()).unwrap() },
                    None => { master_xpriv_key },
                };
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
            Extended Private Key:   {}
            Private Key:            {}
            Address:                {}
            Network:                {}
            Format:                 {}
            Compressed:             {}
            ",
                        mnemonic_wallet.phrase, mnemonic_wallet.extended_private_key, mnemonic_wallet.private_key, mnemonic_wallet.address, mnemonic_wallet.network, mnemonic_wallet.format, mnemonic_wallet.compressed
                    )
                }
            },
            (None, Some(wallet_extended)) => {
                let extended_private_key = match (wallet_extended.key, wallet_extended.path)  {
                    (None, None) => {
                        let rng = &mut StdRng::from_entropy();
                        let seed: [u8; 32] = rng.gen();
                        BitcoinExtendedPrivateKey::<N>::new_master(&seed, &bitcoin_wallet.format).unwrap()
                    },
                    (Some(key), None) => {
                        BitcoinExtendedPrivateKey::<N>::from_str(&key).unwrap()
                    },
                    (None, Some(path)) => {
                        let rng = &mut StdRng::from_entropy();
                        let seed: [u8; 32] = rng.gen();
                        BitcoinExtendedPrivateKey::<N>::new(
                            &seed,
                            &bitcoin_wallet.format,
                            &BitcoinDerivationPath::from_str(&path).unwrap())
                            .unwrap()
                    },
                    (Some(key), Some(path)) => {
                        BitcoinExtendedPrivateKey::from_str(&key)
                            .unwrap()
                            .derive(&BitcoinDerivationPath::from_str(&path).unwrap()).unwrap()
                    },
                };
                let private_key = extended_private_key.to_private_key();
                let address = BitcoinAddress::from_private_key(&private_key, &bitcoin_wallet.format).unwrap();

                let extended_wallet = ExtendedWallet {
                    phrase:  "".into(),
                    extended_private_key: extended_private_key.to_string(),
                    private_key: private_key.to_string(),
                    address: address.to_string(),
                    network: bitcoin_wallet.network.clone(),
                    format: address.format(),
                    compressed: private_key.is_compressed(),
                };

                if bitcoin_wallet.json {
                    println!("{}", serde_json::to_string_pretty(&extended_wallet).unwrap())
                } else {
                    println!(
                            "
                Extended Private Key:   {}
                Private Key:            {}
                Address:                {}
                Network:                {}
                Format:                 {}
                Compressed:             {}
                ",
                        extended_wallet.extended_private_key, extended_wallet.private_key, extended_wallet.address, extended_wallet.network, extended_wallet.format, extended_wallet.compressed
                    )
                }
            },
            _ => unreachable!(),
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
        let rng = &mut StdRng::from_entropy();
        let private_key = EthereumPrivateKey::new(rng).unwrap();
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
        private_spend_key: String,
        private_view_key: String,
        address: String,
        network: String,
    };

    for _ in 0..count {
        let wallet = if testnet {
            let rng = &mut StdRng::from_entropy();
            let private_key = MoneroPrivateKey::<MoneroTestnet>::new(rng).unwrap();
            let address = MoneroAddress::from_private_key(&private_key, format).unwrap();

            Wallet {
                private_spend_key: hex::encode(private_key.to_private_spend_key()),
                private_view_key: hex::encode(private_key.to_private_view_key()),
                address: address.to_string(),
                network: "testnet".into(),
            }
        } else {
            let rng = &mut StdRng::from_entropy();
            let private_key = MoneroPrivateKey::<MoneroMainnet>::new(rng).unwrap();
            let address = MoneroAddress::from_private_key(&private_key, format).unwrap();

            Wallet {
                private_spend_key: hex::encode(private_key.to_private_spend_key()),
                private_view_key: hex::encode(private_key.to_private_view_key()),
                address: address.to_string(),
                network: "mainnet".into(),
            }
        };

        if json {
            println!("{}", serde_json::to_string_pretty(&wallet).unwrap())
        } else {
            println!(
                "
        Private Spend Key:    {}
        Private View Key:     {}
        Address:              {}
        Network:              {}
        ",
                wallet.private_spend_key, wallet.private_view_key, wallet.address, wallet.network
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
            let rng = &mut StdRng::from_entropy();
            let private_key = ZcashPrivateKey::<ZcashTestnet>::new(rng).unwrap();
            let address = ZcashAddress::from_private_key(&private_key, &format).unwrap();

            Wallet {
                private_key: private_key.to_string(),
                address: address.to_string(),
                network: "testnet".into(),
            }
        } else {
            let rng = &mut StdRng::from_entropy();
            let private_key = match format {
                ZcashFormat::P2PKH => ZcashPrivateKey::<ZcashMainnet>::new_p2pkh(rng).unwrap(),
                _ => ZcashPrivateKey::<ZcashMainnet>::new_sapling(rng).unwrap(),
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
