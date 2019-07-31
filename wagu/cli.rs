//! # Wagu CLI
//!
//! A command-line tool to generate cryptocurrency wallets.

use bitcoin::address::Format as BitcoinFormat;
use bitcoin::{BitcoinAddress, BitcoinMnemonic, BitcoinPrivateKey, Mainnet as BitcoinMainnet, BitcoinNetwork, BitcoinDerivationPath, BitcoinExtendedPrivateKey,  English as BitcoinEnglish, Testnet as BitcoinTestnet};
use ethereum::{English as EthereumEnglish, EthereumAddress, EthereumMnemonic, EthereumDerivationPath, EthereumExtendedPrivateKey, EthereumPrivateKey};
use monero::address::Format as MoneroFormat;
use monero::{English as MoneroEnglish, Mainnet as MoneroMainnet, MoneroAddress, MoneroMnemonic, MoneroNetwork, MoneroPrivateKey, Testnet as MoneroTestnet};
use wagu_model::{Address, Mnemonic, MnemonicExtended, ExtendedPrivateKey, PrivateKey};
use zcash::address::Format as ZcashFormat;
use zcash::{Mainnet as ZcashMainnet, Testnet as ZcashTestnet, ZcashAddress, ZcashNetwork, ZcashExtendedPrivateKey, ZcashDerivationPath, ZcashPrivateKey};

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
    pub mnemonic_values: Option<MnemonicValues>,
    pub extended_private_key_values: Option<ExtendedPrivateKeyValues>,
    pub count: usize,
    pub network: String,
    pub format: BitcoinFormat,
    pub json: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct EthereumWallet {
    pub private_key: Option<String>,
    pub mnemonic_values: Option<MnemonicValues>,
    pub extended_private_key_values: Option<ExtendedPrivateKeyValues>,
    pub count: usize,
    pub json: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct MoneroWallet {
    pub private_key: Option<String>,
    pub mnemonic_values: Option<MnemonicValues>,
    pub count: usize,
    pub network: String,
    pub format: MoneroFormat,
    pub json: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct ZcashWallet {
    pub private_key: Option<String>,
    pub extended_private_key_values: Option<ExtendedPrivateKeyValues>,
    pub count: usize,
    pub network: String,
    pub format: ZcashFormat,
    pub json: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct MnemonicValues {
    pub word_count: Option<u8>,
    pub mnemonic: String,
    pub password: String,
    pub path: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ExtendedPrivateKeyValues {
    pub key: Option<String>,
    pub path: Option<String>,
}

fn main() {
    // Generic wallet arguments
    let arg_count = Arg::from_usage("[count] -n --count=[count] 'Number of wallets to generate'");
    let arg_json = Arg::from_usage("[json] -j --json 'Print the generated wallet(s) in JSON format'");
    let arg_network = Arg::from_usage("[network] -N --network=[network] 'Network of wallet(s) to generate'")
        .possible_values(&["mainnet", "testnet"]);

    // Wallet import arguments
    let arg_path = Arg::from_usage("[path] --path=[path] 'Specify a derivation path'");
    let arg_import = Arg::from_usage("[import] --import")
        .conflicts_with("word_count");
    let arg_password = Arg::from_usage("[password] --password=[password] 'Specify a password used for extended private key derivation'");
    let arg_word_count = Arg::from_usage("[word count] --word_count=[word count] 'Generate a wallet with a new mnemonic with the specified word count'")
        .conflicts_with("import");

    // Bitcoin specific arguments
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
        .arg(&arg_password);

    let monero_mnemonic_subcommand = SubCommand::with_name("mnemonic")
        .about("Generate a wallet using mnemonics")
        .arg(&arg_import.clone().number_of_values(1).value_name("mnemonic")
            .help("Generate a wallet by importing a Mnemonic (in quotes)"));

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
    let matches = App::new("wagu")
        .version("v0.6.0")
        .about("Generate a wallet for Bitcoin, Ethereum, Monero, and Zcash")
        .author("Argus <team@argus.dev>")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("bitcoin")
            .about("Generate a Bitcoin wallet (run with -h for additional options)")
            .arg(&arg_bech32)
            .arg(&arg_count)
            .arg(&arg_json)
            .arg(&arg_network)
            .arg(&arg_segwit)
            .subcommand(extended_private_key_subcommand.to_owned())
            .subcommand(mnemonic_subcommand
                .to_owned()
                .arg(&arg_word_count))
            .subcommand(private_key_subcommand.to_owned())
        )
        .subcommand(SubCommand::with_name("ethereum")
            .about("Generate an Ethereum wallet (run with -h for additional options)")
            .arg(&arg_count)
            .arg(&arg_json)
            .subcommand(extended_private_key_subcommand.to_owned())
            .subcommand(mnemonic_subcommand
                .to_owned()
                .arg(&arg_word_count))
            .subcommand(private_key_subcommand.to_owned())
        )
        .subcommand(SubCommand::with_name("monero")
            .about("Generate a Monero wallet (run with -h for additional options)")
            .arg(&arg_count)
            .arg(&arg_json)
            .arg(&arg_network)
            .arg(&arg_integrated)
            .arg(&arg_subaddress)
            .subcommand(monero_mnemonic_subcommand.to_owned())
            .subcommand(private_key_subcommand.to_owned())
        )
        .subcommand(SubCommand::with_name("zcash")
            .about("Generate a Zcash wallet (run with -h for additional options)")
            .arg(&arg_network)
            .arg(&arg_count)
            .arg(&arg_json)
            .arg(&arg_shielded)
            .subcommand(extended_private_key_subcommand.to_owned())
            .subcommand(private_key_subcommand.to_owned())
        )
        .get_matches();

    match matches.subcommand() {
        ("bitcoin", Some(bitcoin_matches)) => {
            let bitcoin_address_type = if bitcoin_matches.is_present("segwit") {
                BitcoinFormat::P2SH_P2WPKH
            } else if bitcoin_matches.is_present("bech32") {
                BitcoinFormat::Bech32
            } else { BitcoinFormat::P2PKH };

            let network = match bitcoin_matches.value_of("network") {
                Some("testnet") => "testnet",
                _ => "mainnet",
            };

            let mut bitcoin_wallet = BitcoinWallet {
                private_key: None,
                mnemonic_values: None,
                extended_private_key_values: None,
                count: clap::value_t!(bitcoin_matches.value_of("count"), usize).unwrap_or_else(|_e| 1),
                network: network.to_owned(),
                format: bitcoin_address_type,
                json: bitcoin_matches.is_present("json"),
            };

            match bitcoin_matches.subcommand() {
                ("", None) => {},
                ("private_key", Some(private_key_matches)) => {
                    bitcoin_wallet.private_key = private_key_matches.value_of("import").map(|s| s.to_string());
                },
                ("mnemonic", Some(mnemonic_matches)) => {
                    let password: String = mnemonic_matches.value_of("password").unwrap_or("").to_owned();
                    let path = mnemonic_matches.value_of("path").map(|s| s.to_string());
                    bitcoin_wallet.mnemonic_values = match (mnemonic_matches.value_of("import"), mnemonic_matches.value_of("word count")) {
                        (Some(phrase), _) => Some(MnemonicValues { word_count: None, mnemonic: phrase.to_owned(), password, path }),
                        (None, Some(word_count)) => { Some(MnemonicValues { word_count: Some(word_count.parse().unwrap()), mnemonic: "".to_owned(), password, path }) },
                        (None, None) => Some(MnemonicValues { word_count: Some(12), mnemonic: "".to_owned(), password, path }),
                    };
                },
                ("extended_private_key", Some(xpriv_matches)) => {
                    let path = xpriv_matches.value_of("path").map(|s| s.to_string());
                    let key = xpriv_matches.value_of("import").map(|s| s.to_string());
                    bitcoin_wallet.extended_private_key_values = Some( ExtendedPrivateKeyValues { key, path });
                },
                _ => unreachable!(),
            };

            match network {
                "testnet" => {
                    type N = BitcoinTestnet;
                    print_bitcoin_wallet::<N>(bitcoin_wallet);
                },
                _ => {
                    type N = BitcoinMainnet;
                    print_bitcoin_wallet::<N>(bitcoin_wallet);
                }
            };
        },
        ("ethereum", Some(ethereum_matches)) => {
            let mut ethereum_wallet = EthereumWallet {
                private_key: None,
                mnemonic_values: None,
                extended_private_key_values: None,
                count: clap::value_t!(ethereum_matches.value_of("count"), usize).unwrap_or_else(|_e| 1),
                json: ethereum_matches.is_present("json"),
            };

            match ethereum_matches.subcommand() {
                ("", None) => {},
                ("private_key", Some(private_key_matches)) => {
                    ethereum_wallet.private_key = private_key_matches.value_of("import").map(|s| s.to_string());
                },
                ("mnemonic", Some(mnemonic_matches)) => {
                    let password: String = mnemonic_matches.value_of("password").unwrap_or("").to_owned();
                    let path = mnemonic_matches.value_of("path").map(|s| s.to_string());
                    ethereum_wallet.mnemonic_values = match (mnemonic_matches.value_of("import"), mnemonic_matches.value_of("word count")) {
                        (Some(phrase), _) => Some(MnemonicValues { word_count: None, mnemonic: phrase.to_owned(), password, path }),
                        (None, Some(word_count)) => { Some(MnemonicValues { word_count: Some(word_count.parse().unwrap()), mnemonic: "".to_owned(), password, path }) },
                        (None, None) => Some(MnemonicValues { word_count: Some(12), mnemonic: "".to_owned(), password, path }),
                    };
                },
                ("extended_private_key", Some(xpriv_matches)) => {
                    let path = xpriv_matches.value_of("path").map(|s| s.to_string());
                    let key = xpriv_matches.value_of("import").map(|s| s.to_string());
                    ethereum_wallet.extended_private_key_values = Some( ExtendedPrivateKeyValues { key, path });
                },
                _ => unreachable!(),
            };

            print_ethereum_wallet(ethereum_wallet);
        },
        ("monero", Some(monero_matches)) => {
            let monero_address_type = match (monero_matches.values_of("subaddress"), monero_matches.value_of("integrated")) {
                (Some(indexes), None) => {
                    let indexes: Vec<u32> = indexes.into_iter().map(|index| index.to_owned().parse().unwrap()).collect();
                    MoneroFormat::Subaddress(indexes[0], indexes[1])
                },
                (None, Some(payment_id_string)) => {
                    let mut payment_id = [0u8; 8];
                    payment_id.copy_from_slice(&hex::decode(payment_id_string).unwrap());
                    MoneroFormat::Integrated(payment_id)
                },
                (None, None) => { MoneroFormat::Standard },
                _ => unreachable!(),
            };

            let network = match monero_matches.value_of("network") {
                Some("testnet") => "testnet",
                _ => "mainnet",
            };

            let mut monero_wallet = MoneroWallet {
                private_key: None,
                mnemonic_values: None,
                count: clap::value_t!(monero_matches.value_of("count"), usize).unwrap_or_else(|_e| 1),
                network: network.to_owned(),
                format: monero_address_type,
                json: monero_matches.is_present("json"),
            };

            match monero_matches.subcommand() {
                ("", None) => {},
                ("private_key", Some(private_key_matches)) => {
                    monero_wallet.private_key = private_key_matches.value_of("import").map(|s| s.to_string());
                },
                ("mnemonic", Some(mnemonic_matches)) => {
                    let password: String = mnemonic_matches.value_of("password").unwrap_or("").to_owned();
                    let path = mnemonic_matches.value_of("path").map(|s| s.to_string());
                    monero_wallet.mnemonic_values = match mnemonic_matches.value_of("import") {
                        Some(phrase) => Some(MnemonicValues { word_count: None, mnemonic: phrase.to_owned(), password, path }),
                        None => Some(MnemonicValues { word_count: Some(25), mnemonic: "".to_owned(), password, path }),
                    };
                },
                _ => unreachable!(),
            };

            match network {
                "testnet" => {
                    type N = MoneroTestnet;
                    print_monero_wallet::<N>(monero_wallet);
                },
                _ => {
                    type N = MoneroMainnet;
                    print_monero_wallet::<N>(monero_wallet);
                }
            };
        },
        ("zcash", Some(zcash_matches)) => {
            let zcash_address_type = if zcash_matches.is_present("shielded") {
                ZcashFormat::Sapling(None)
            } else {
                ZcashFormat::P2PKH
            };

            let network = match zcash_matches.value_of("network") {
                Some("testnet") => "testnet",
                _ => "mainnet",
            };

            let mut zcash_wallet = ZcashWallet {
                private_key: None,
                extended_private_key_values: None,
                count: clap::value_t!(zcash_matches.value_of("count"), usize).unwrap_or_else(|_e| 1),
                network: network.to_owned(),
                format: zcash_address_type,
                json: zcash_matches.is_present("json"),
            };

            match zcash_matches.subcommand() {
                ("", None) => {},
                ("private_key", Some(private_key_matches)) => {
                    zcash_wallet.private_key = private_key_matches.value_of("import").map(|s| s.to_string());
                },
                ("extended_private_key", Some(xpriv_matches)) => {
                    let path = xpriv_matches.value_of("path").map(|s| s.to_string());
                    let key = xpriv_matches.value_of("import").map(|s| s.to_string());
                    zcash_wallet.extended_private_key_values = Some( ExtendedPrivateKeyValues { key, path });
                },
                _ => unreachable!(),
            };

            match network {
                "testnet" => {
                    type N = ZcashTestnet;
                    print_zcash_wallet::<N>(zcash_wallet);
                },
                _ => {
                    type N = ZcashMainnet;
                    print_zcash_wallet::<N>(zcash_wallet);
                }
            };

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
        format: String,
        compressed: bool,
    };

    #[derive(Serialize, Debug)]
    pub struct ExtendedWallet {
        phrase: String,
        extended_private_key: String,
        private_key: String,
        address: String,
        network: String,
        format: String,
        compressed: bool,
    };

    for _ in 0..bitcoin_wallet.count {
        match (bitcoin_wallet.mnemonic_values.clone(), bitcoin_wallet.extended_private_key_values.clone()) {
            (None, None) => {
                let private_key = match bitcoin_wallet.private_key.clone() {
                    None => {
                        let rng = &mut StdRng::from_entropy();
                        BitcoinPrivateKey::<N>::new(rng).unwrap()
                    },
                    Some(key) => { BitcoinPrivateKey::<N>::from_str(&key).unwrap() },
                };

                let address = BitcoinAddress::from_private_key(&private_key, &bitcoin_wallet.format).unwrap();
                let wallet = Wallet {
                    private_key: private_key.to_string(),
                    address: address.to_string(),
                    network: bitcoin_wallet.network.clone(),
                    format: address.format().to_string(),
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
            (Some(mnemonic_values), None) => {
                type W = BitcoinEnglish;
                let rng = &mut StdRng::from_entropy();
                let mnemonic = match mnemonic_values.word_count {
                    Some(word_count) => BitcoinMnemonic::<N, W>::new(word_count, rng).unwrap(),
                    None => BitcoinMnemonic::<N, W>::from_phrase(&mnemonic_values.mnemonic).unwrap()
                };

                let master_xpriv_key = mnemonic.to_extended_private_key(Some(&mnemonic_values.password)).unwrap();
                let extended_private_key = match mnemonic_values.path {
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
                    format: address.format().to_string(),
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
                        BitcoinExtendedPrivateKey::<N>::from_str(&key)
                            .unwrap()
                            .derive(&BitcoinDerivationPath::from_str(&path).unwrap()).unwrap()
                    },
                };
                let private_key = extended_private_key.to_private_key();
                let address = BitcoinAddress::from_private_key(&private_key, &bitcoin_wallet.format).unwrap();

                let extended_wallet = ExtendedWallet {
                    phrase:  "".to_owned(),
                    extended_private_key: extended_private_key.to_string(),
                    private_key: private_key.to_string(),
                    address: address.to_string(),
                    network: bitcoin_wallet.network.clone(),
                    format: address.format().to_string(),
                    compressed: private_key.is_compressed(),
                };

                if bitcoin_wallet.json {
                    println!("{}", serde_json::to_string_pretty(&extended_wallet).unwrap())
                } else {
                    println!(
                            "
                    Extended private Key:   {}
                    Private Key:            {}
                    Address:                {}
                    Network:                {}
                    Format:                 {}
                    Compressed:             {}
                    ",
                        extended_wallet.extended_private_key, extended_wallet.private_key, extended_wallet.address, extended_wallet.network, extended_wallet.format, extended_wallet.compressed
                    )
                };
            },
            _ => unreachable!(),
        };
    }
}

fn print_ethereum_wallet(ethereum_wallet: EthereumWallet) {
    #[derive(Serialize, Debug)]
    pub struct Wallet {
        private_key: String,
        address: String,
    };

    #[derive(Serialize, Debug)]
    pub struct ExtendedWallet {
        phrase: String,
        extended_private_key: String,
        private_key: String,
        address: String,
    };


    for _ in 0..ethereum_wallet.count {
        match (ethereum_wallet.mnemonic_values.clone(), ethereum_wallet.extended_private_key_values.clone()) {
            (None, None) => {
                let private_key = match ethereum_wallet.private_key.clone() {
                    None => {
                        let rng = &mut StdRng::from_entropy();
                        EthereumPrivateKey::new(rng).unwrap()
                    },
                    Some(key) => { EthereumPrivateKey::from_str(&key).unwrap() },
                };
                let address = EthereumAddress::from_private_key(&private_key, &PhantomData).unwrap();

                let wallet = Wallet {
                    private_key: private_key.to_string(),
                    address: address.to_string(),
                };

                if ethereum_wallet.json {
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
            },
            (Some(mnemonic_values), None) => {
                type W = EthereumEnglish;
                let rng = &mut StdRng::from_entropy();
                let mnemonic = match mnemonic_values.word_count {
                    Some(word_count) => EthereumMnemonic::<W>::new(word_count, rng).unwrap(),
                    None => EthereumMnemonic::<W>::from_phrase(&mnemonic_values.mnemonic).unwrap()
                };

                let master_xpriv_key = mnemonic.to_extended_private_key(Some(&mnemonic_values.password)).unwrap();
                let extended_private_key = match mnemonic_values.path {
                    Some(path) => { master_xpriv_key.derive(&EthereumDerivationPath::from_str(&path).unwrap()).unwrap() },
                    None => { master_xpriv_key },
                };
                let private_key = extended_private_key.to_private_key();
                let address = EthereumAddress::from_private_key(&private_key, &PhantomData).unwrap();

                let mnemonic_wallet = ExtendedWallet {
                    phrase:  mnemonic.to_string(),
                    extended_private_key: extended_private_key.to_string(),
                    private_key: private_key.to_string(),
                    address: address.to_string(),
                };

                if ethereum_wallet.json {
                    println!("{}", serde_json::to_string_pretty(&mnemonic_wallet).unwrap())
                } else {
                    println!(
                            "
                    Mnemonic:               {}
                    Extended private Key:   {}
                    Private Key:            {}
                    Address:                {}
                    ",
                        mnemonic_wallet.phrase, mnemonic_wallet.extended_private_key, mnemonic_wallet.private_key, mnemonic_wallet.address
                    )
                };
            },
            (None, Some(wallet_extended)) => {
                let extended_private_key = match (wallet_extended.key, wallet_extended.path)  {
                    (None, None) => {
                        let rng = &mut StdRng::from_entropy();
                        let seed: [u8; 32] = rng.gen();
                        EthereumExtendedPrivateKey::new_master(&seed, &PhantomData).unwrap()
                    },
                    (Some(key), None) => {
                        EthereumExtendedPrivateKey::from_str(&key).unwrap()
                    },
                    (None, Some(path)) => {
                        let rng = &mut StdRng::from_entropy();
                        let seed: [u8; 32] = rng.gen();
                        EthereumExtendedPrivateKey::new(
                            &seed,
                            &PhantomData,
                            &EthereumDerivationPath::from_str(&path).unwrap())
                            .unwrap()
                    },
                    (Some(key), Some(path)) => {
                        EthereumExtendedPrivateKey::from_str(&key)
                            .unwrap()
                            .derive(&EthereumDerivationPath::from_str(&path).unwrap()).unwrap()
                    },
                };
                let private_key = extended_private_key.to_private_key();
                let address = EthereumAddress::from_private_key(&private_key, &PhantomData).unwrap();

                let extended_wallet = ExtendedWallet {
                    phrase:  "".to_owned(),
                    extended_private_key: extended_private_key.to_string(),
                    private_key: private_key.to_string(),
                    address: address.to_string(),
                };

                if ethereum_wallet.json {
                    println!("{}", serde_json::to_string_pretty(&extended_wallet).unwrap())
                } else {
                    println!(
                            "
                    Extended private Key:   {}
                    Private Key:            {}
                    Address:                {}
                    ",
                        extended_wallet.extended_private_key, extended_wallet.private_key, extended_wallet.address
                    )
                };
            },
            _ => unreachable!(),
        };
    }
}

fn print_monero_wallet<N: MoneroNetwork>(monero_wallet: MoneroWallet) {
    #[derive(Serialize, Debug)]
    pub struct Wallet {
        private_key: String,
        address: String,
        network: String,
        format: String,
    };

    #[derive(Serialize, Debug)]
    pub struct MnemonicWallet {
        phrase: String,
        private_key: String,
        address: String,
        network: String,
        format: String,
    };

    for _ in 0..monero_wallet.count {

        match monero_wallet.mnemonic_values.clone() {
            None => {
                let private_key = match monero_wallet.private_key.clone() {
                    None => {
                        let rng = &mut StdRng::from_entropy();
                        MoneroPrivateKey::<N>::new(rng).unwrap()
                    },
                    Some(key) => { MoneroPrivateKey::<N>::from_str(&key).unwrap() },
                };
                let address = MoneroAddress::from_private_key(&private_key, &monero_wallet.format).unwrap();

                let wallet = Wallet {
                    private_key: private_key.to_string(),
                    address: address.to_string(),
                    network: monero_wallet.network.to_owned(),
                    format: monero_wallet.format.to_string(),
                };

                if monero_wallet.json {
                    println!("{}", serde_json::to_string_pretty(&wallet).unwrap())
                } else {
                    println!(
                            "
                    Private ( Spend, View ) Key:    {}
                    Address:                        {}
                    Network:                        {}
                    Format:                         {}
                    ",
                        wallet.private_key, wallet.address, wallet.network, wallet.format
                    )
                }

            },
            Some(mnemonic_values) => {
                type W = MoneroEnglish;
                let rng = &mut StdRng::from_entropy();

                let mnemonic = match mnemonic_values.word_count {
                    Some(_) => MoneroMnemonic::<N, W>::new(rng).unwrap(),
                    None => MoneroMnemonic::<N, W>::from_phrase(&mnemonic_values.mnemonic).unwrap()
                };

                let private_key = mnemonic.to_private_key(None).unwrap();
                let address = MoneroAddress::from_private_key(&private_key, &monero_wallet.format).unwrap();

                let mnemonic_wallet = MnemonicWallet {
                    phrase:  mnemonic.to_string(),
                    private_key: private_key.to_string(),
                    address: address.to_string(),
                    network: monero_wallet.network.to_owned(),
                    format: monero_wallet.format.to_string(),
                };

                if monero_wallet.json {
                    println!("{}", serde_json::to_string_pretty(&mnemonic_wallet).unwrap())
                } else {
                    println!(
                            "
                    Mnemonic:                       {}
                    Private ( Spend, View ) Key:    {}
                    Address:                        {}
                    Network:                        {}
                    Format:                         {}
                    ",
                        mnemonic_wallet.phrase, mnemonic_wallet.private_key, mnemonic_wallet.address, mnemonic_wallet.network, mnemonic_wallet.format
                    )
                };
            }
        }
    }
}

fn print_zcash_wallet<N: ZcashNetwork>(zcash_wallet: ZcashWallet) {
    #[derive(Serialize, Debug)]
    pub struct Wallet {
        private_key: String,
        address: String,
        diversifier: String,
        format: String,
        network: String,
    };

    #[derive(Serialize, Debug)]
    pub struct ExtendedWallet {
        phrase: String,
        extended_private_key: String,
        private_key: String,
        address: String,
        diversifier: String,
        format: String,
        network: String,
    };

    for _ in 0..zcash_wallet.count {
        match zcash_wallet.extended_private_key_values.clone() {
            None => {
                let private_key = match zcash_wallet.private_key.clone() {
                    None => {
                        let rng = &mut StdRng::from_entropy();
                        match zcash_wallet.format {
                            ZcashFormat::P2PKH => ZcashPrivateKey::<N>::new_p2pkh(rng).unwrap(),
                            _ => ZcashPrivateKey::<N>::new_sapling(rng).unwrap(),
                        }
                    },
                    Some(key) => { ZcashPrivateKey::<N>::from_str(&key).unwrap() },
                };

                let address = ZcashAddress::from_private_key(&private_key, &zcash_wallet.format).unwrap();
                let address_format = address.format().to_string();
                let address_format: Vec<String> = address_format.split(" ").map(|s| s.to_owned()).collect();
                let wallet = Wallet {
                    private_key: private_key.to_string(),
                    address: address.to_string(),
                    diversifier: address_format.get(1).unwrap_or(&"".to_owned()).to_owned(),
                    format: address_format[0].to_owned(),
                    network: zcash_wallet.network.clone(),
                };

                if zcash_wallet.json {
                    println!("{}", serde_json::to_string_pretty(&wallet).unwrap())
                } else {
                    println!(
                            "
                    Private Key:    {}
                    Address:        {}
                    Diversifier:    {}
                    Format:         {}
                    Network:        {}
                    ",
                        wallet.private_key, wallet.address, wallet.diversifier, wallet.format, wallet.network
                    )
                }
            },
            Some(wallet_extended) => {
                let extended_private_key = match (wallet_extended.key, wallet_extended.path)  {
                    (None, None) => {
                        let rng = &mut StdRng::from_entropy();
                        let seed: [u8; 32] = rng.gen();
                        ZcashExtendedPrivateKey::<N>::new_master(&seed, &zcash_wallet.format).unwrap()
                    },
                    (Some(key), None) => {
                        ZcashExtendedPrivateKey::<N>::from_str(&key).unwrap()
                    },
                    (None, Some(path)) => {
                        let rng = &mut StdRng::from_entropy();
                        let seed: [u8; 32] = rng.gen();
                        ZcashExtendedPrivateKey::<N>::new(
                            &seed,
                            &zcash_wallet.format,
                            &ZcashDerivationPath::from_str(&path).unwrap())
                            .unwrap()
                    },
                    (Some(key), Some(path)) => {
                        ZcashExtendedPrivateKey::<N>::from_str(&key)
                            .unwrap()
                            .derive(&ZcashDerivationPath::from_str(&path).unwrap()).unwrap()
                    },
                };

                let private_key = extended_private_key.to_private_key();
                let address = ZcashAddress::from_private_key(&private_key, &zcash_wallet.format).unwrap();
                let address_format = address.format().to_string();
                let address_format: Vec<String> = address_format.split(" ").map(|s| s.to_owned()).collect();

                let extended_wallet = ExtendedWallet {
                    phrase:  "".to_owned(),
                    extended_private_key: extended_private_key.to_string(),
                    private_key: private_key.to_string(),
                    address: address.to_string(),
                    diversifier: address_format.get(1).unwrap_or(&"".to_owned()).to_owned(),
                    format: address_format[0].to_owned(),
                    network: zcash_wallet.network.clone(),
                };

                if zcash_wallet.json {
                    println!("{}", serde_json::to_string_pretty(&extended_wallet).unwrap())
                } else {
                    println!(
                            "
                    Extended private Key:   {}
                    Private Key:            {}
                    Address:                {}
                    Diversifier:            {}
                    Format:                 {}
                    Network:                {}
                    ",
                        extended_wallet.extended_private_key, extended_wallet.private_key, extended_wallet.address, extended_wallet.diversifier, extended_wallet.format, extended_wallet.network,
                    )
                };
            },
        };
    }
}
